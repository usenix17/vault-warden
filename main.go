package main

import (
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "os"
        "strings"
        "time"
)

const (
        WebhookURL = "https://discord.com/api/webhooks/SOMEWEBHOOK"
        AuditLog   = "/var/log/vault_audit.log"
)

type DiscordEmbed struct {
        Title       string `json:"title"`
        Description string `json:"description"`
        Color       int    `json:"color"`
        Timestamp   string `json:"timestamp"`
}

type DiscordPayload struct {
        Embeds []DiscordEmbed `json:"embeds"`
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

func sendDiscordEmbed(title, desc string, color int) {
        payload := DiscordPayload{
                Embeds: []DiscordEmbed{{
                        Title:       title,
                        Description: desc,
                        Color:       color,
                        Timestamp:   time.Now().Format(time.RFC3339),
                }},
        }
        data, _ := json.Marshal(payload)
        http.Post(WebhookURL, "application/json", bytes.NewBuffer(data))
}

func main() {
        // 1. Send "Warden Started" notification
        sendDiscordEmbed("🛡 Vault Warden Active", "Monitoring audit logs for Starnix cluster...", 0x3498db) // Blue

        file, err := os.Open(AuditLog)
        if err != nil {
                fmt.Printf("Error opening audit log: %v\n", err)
                return
        }
        defer file.Close()

        // Start at the end of the file
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

                // LOGIC: Filter for Root SSH or DB Admin
                if strings.Contains(entry.Request.Path, "sign/root") || strings.Contains(entry.Request.Path, "database/creds/admin") {
                        title := "🚨 SECURITY ALERT: Privileged Access"
                        desc := fmt.Sprintf("**User:** %s\n**Resource:** `%s`", entry.Auth.DisplayName, entry.Request.Path)
                        sendDiscordEmbed(title, desc, 0xe74c3c) // Red
                }

                // LOGIC: Filter for Unseal operations (if your unsealer uses a specific token or path)
                if strings.Contains(entry.Request.Path, "sys/unseal") && entry.Error == "" {
                        sendDiscordEmbed("🔓 Vault Unsealed", "Vault has been successfully unsealed.", 0x2ecc71) // Green
                }
        }
}
