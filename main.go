package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
		return nil, err
	}
	defer file.Close()
	var cfg VaultConfig
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func sendDiscord(url, title, desc string, color int) {
	payload := DiscordPayload{
		Embeds: []DiscordEmbed{{
			Title:       title,
			Description: desc,
			Color:       color,
			Timestamp:   time.Now().Format(time.RFC3339),
		}},
	}
	data, _ := json.Marshal(payload)
	http.Post(url, "application/json", bytes.NewBuffer(data))
}

// --- Command: Unlock ---

func runUnlock(cfg *VaultConfig) {
	client := &http.Client{Timeout: 10 * time.Second}
	
	resp, err := client.Get(fmt.Sprintf("%s/v1/sys/health", cfg.Address))
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var status VaultStatus
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &status)

	if !status.Sealed {
		fmt.Println("Vault is already unsealed. Skipping.")
		return
	}

	fmt.Println("Vault is sealed. Sending keys...")
	for _, key := range cfg.UnsealKeys {
		reqBody, _ := json.Marshal(map[string]string{"key": key})
		req, _ := http.NewRequest("PUT", cfg.Address+"/v1/sys/unseal", bytes.NewReader(reqBody))
		client.Do(req)
	}
}

// --- Command: Audit ---

func runAudit(cfg *VaultConfig) {
	fmt.Println("🛡️ Vault Warden Active. Monitoring logs...")
	sendDiscord(cfg.WebhookURL, "🛡️ Vault Warden Active", "Monitoring audit logs for Starnix cluster...", 0x3498db)

	file, err := os.Open(cfg.AuditLog)
	if err != nil {
		fmt.Printf("Error opening audit log: %v\n", err)
		return
	}
	defer file.Close()
	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if strings.Contains(entry.Request.Path, "sign/root") || strings.Contains(entry.Request.Path, "database/creds/admin") {
			desc := fmt.Sprintf("**User:** %s\n**Resource:** `%s`", entry.Auth.DisplayName, entry.Request.Path)
			sendDiscord(cfg.WebhookURL, "🚨 SECURITY ALERT: Privileged Access", desc, 0xe74c3c)
		}

		if strings.Contains(entry.Request.Path, "sys/unseal") && entry.Error == "" {
			sendDiscord(cfg.WebhookURL, "🔓 Vault Unsealed", "Vault has been successfully unsealed.", 0x2ecc71)
		}
	}
}

// --- Main Entrypoint ---

func main() {
	configPath := flag.String("config", "/etc/vault-warden.yaml", "Path to config file")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: vault-warden [-config path] [unlock | audit]")
		os.Exit(1)
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		fmt.Printf("Config error: %v\n", err)
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "unlock":
		runUnlock(cfg)
	case "audit":
		runAudit(cfg)
	default:
		fmt.Printf("Unknown command: %s\n", flag.Arg(0))
		os.Exit(1)
	}
}
