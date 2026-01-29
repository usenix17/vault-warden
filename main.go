package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nxadm/tail"
	"gopkg.in/yaml.v3"
)

// --- Shared Configuration & Structs ---

type VaultConfig struct {
	Address    string   `yaml:"address"`
	UnsealKeys []string `yaml:"unseal_keys"`
	WebhookURL string   `yaml:"webhook_url"`
	AuditLog   string   `yaml:"audit_log"`
}

type VaultStatus struct {
	Sealed      bool   `json:"sealed"`
	Initialized bool   `json:"initialized"`
	Progress    int    `json:"progress"`
	Threshold   int    `json:"t"`
}

type AuditEntry struct {
	Request struct {
		Path string `json:"path"`
	} `json:"request"`
	Auth struct {
		DisplayName string `json:"display_name"`
	} `json:"auth"`
	Error string `json:"error"`
}

type DiscordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp"`
}

type DiscordPayload struct {
	Embeds []DiscordEmbed `json:"embeds"`
}

// --- Helper Functions ---

func readConfig(path string) (*VaultConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	var cfg VaultConfig
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	// Validate required fields
	if cfg.Address == "" {
		return nil, fmt.Errorf("address is required")
	}
	if len(cfg.UnsealKeys) == 0 {
		return nil, fmt.Errorf("unseal_keys is required")
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("webhook_url is required")
	}

	return &cfg, nil
}

func sendDiscord(url, title, desc string, color int) error {
	payload := DiscordPayload{
		Embeds: []DiscordEmbed{{
			Title:       title,
			Description: desc,
			Color:       color,
			Timestamp:   time.Now().Format(time.RFC3339),
		}},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		// Log but don't fail - Discord being down shouldn't break monitoring
		fmt.Printf("⚠️  Discord webhook failed: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("⚠️  Discord returned %d: %s\n", resp.StatusCode, body)
		return fmt.Errorf("discord returned status %d", resp.StatusCode)
	}

	return nil
}

// --- Command: Unlock ---

func runUnlock(cfg *VaultConfig) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// Check current seal status
	// Note: Vault returns 503 when sealed, 200 when unsealed
	// We need to handle both as valid responses
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/sys/health", cfg.Address), nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read health response: %w", err)
	}

	var status VaultStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("parse health response: %w", err)
	}

	if !status.Sealed {
		fmt.Println("✓ Vault is already unsealed. Skipping.")
		return nil
	}

	fmt.Printf("🔒 Vault is sealed. Attempting to unseal with %d keys...\n", len(cfg.UnsealKeys))

	// Send unseal keys
	for i, key := range cfg.UnsealKeys {
		reqBody, err := json.Marshal(map[string]string{"key": key})
		if err != nil {
			return fmt.Errorf("marshal unseal key %d: %w", i+1, err)
		}

		req, err := http.NewRequest("PUT", cfg.Address+"/v1/sys/unseal", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("create unseal request %d: %w", i+1, err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("unseal request %d failed: %w", i+1, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("read unseal response %d: %w", i+1, err)
		}

		var unsealStatus VaultStatus
		if err := json.Unmarshal(body, &unsealStatus); err != nil {
			return fmt.Errorf("parse unseal response %d: %w", i+1, err)
		}

		if !unsealStatus.Sealed {
			fmt.Println("✓ Vault successfully unsealed")
			// Send notification
			sendDiscord(cfg.WebhookURL, "🔓 Vault Unsealed", 
				"Vault has been successfully unsealed.", 0x2ecc71)
			return nil
		}

		fmt.Printf("  Progress: %d/%d keys\n", unsealStatus.Progress, unsealStatus.Threshold)
	}

	return fmt.Errorf("vault still sealed after providing all %d keys", len(cfg.UnsealKeys))
}

// --- Command: Audit ---

func processAuditLine(line string, webhookURL string) {
	var entry AuditEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return
	}

	// Alert on privileged access
	if strings.Contains(entry.Request.Path, "sign/root") || 
	   strings.Contains(entry.Request.Path, "database/creds/admin") {
		desc := fmt.Sprintf("**User:** %s\n**Resource:** `%s`", 
			entry.Auth.DisplayName, entry.Request.Path)
		sendDiscord(webhookURL, "🚨 SECURITY ALERT: Privileged Access", desc, 0xe74c3c)
		fmt.Printf("🚨 Privileged access: %s -> %s\n", entry.Auth.DisplayName, entry.Request.Path)
	}

	// Alert on unseal events
	if strings.Contains(entry.Request.Path, "sys/unseal") && entry.Error == "" {
		sendDiscord(webhookURL, "🔓 Vault Unsealed", 
			"Vault has been successfully unsealed.", 0x2ecc71)
		fmt.Println("🔓 Vault unseal detected")
	}
}

func runAudit(cfg *VaultConfig) error {
	fmt.Println("🛡️  Vault Warden Active. Monitoring logs...")
	sendDiscord(cfg.WebhookURL, "🛡️ Vault Warden Active", 
		"Monitoring audit logs for Starnix cluster...", 0x3498db)

	// Verify audit log exists
	if _, err := os.Stat(cfg.AuditLog); err != nil {
		return fmt.Errorf("audit log not accessible: %w", err)
	}

	// Use tail library for proper log rotation handling
	t, err := tail.TailFile(cfg.AuditLog, tail.Config{
		Follow:   true,
		ReOpen:   true, // Handles log rotation
		Poll:     true, // Use polling (more reliable than inotify)
		Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}, // Start at end of file
		Logger:   tail.DiscardingLogger, // Suppress tail's own logs
	})
	if err != nil {
		return fmt.Errorf("tail audit log: %w", err)
	}
	defer t.Stop()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case line := <-t.Lines:
			if line.Err != nil {
				fmt.Printf("⚠️  Error reading line: %v\n", line.Err)
				continue
			}
			processAuditLine(line.Text, cfg.WebhookURL)

		case <-sigChan:
			fmt.Println("\n🛑 Shutting down gracefully...")
			sendDiscord(cfg.WebhookURL, "🛑 Vault Warden Stopped", 
				"Audit monitoring has been stopped.", 0x95a5a6)
			return nil
		}
	}
}

// --- Main Entrypoint ---

func main() {
	configPath := flag.String("config", "/etc/vault-warden.yaml", "Path to config file")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: vault-warden [-config path] [unlock | audit]")
		fmt.Println("\nCommands:")
		fmt.Println("  unlock  - Unseal Vault if sealed")
		fmt.Println("  audit   - Monitor audit logs for privileged access")
		os.Exit(1)
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		fmt.Printf("❌ Config error: %v\n", err)
		os.Exit(1)
	}

	var cmdErr error
	switch flag.Arg(0) {
	case "unlock":
		cmdErr = runUnlock(cfg)
	case "audit":
		cmdErr = runAudit(cfg)
	default:
		fmt.Printf("❌ Unknown command: %s\n", flag.Arg(0))
		os.Exit(1)
	}

	if cmdErr != nil {
		fmt.Printf("❌ Error: %v\n", cmdErr)
		os.Exit(1)
	}
}
