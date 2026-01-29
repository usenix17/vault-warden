# Vault Warden

A unified security utility for HashiCorp Vault management, featuring automated unsealing and real-time Discord audit notifications.

## Features

- Multi-call Binary: One tool, two modes (unlock and audit).
- Auto-Unseal: Periodically checks Vault health and applies unseal keys via the /sys/unseal API.
- Warden Audit: Tails the Vault audit log and sends rich Discord embeds for privileged access (Root SSH, DB Admin).
- YAML Configuration: Centralized management for keys, webhooks, and endpoints.

---

## Installation

### 1. Build the Binary

# Initialize module if starting fresh

```bash
go mod init vault-warden
go mod tidy
go build -o vault-warden main.go
```

# Move to system path

```bash
sudo mv vault-warden /usr/local/bin/
```

### 2. Configure
Create `/etc/vault-warden.yaml` and restrict permissions:

```bash
sudo touch /etc/vault-warden.yaml
sudo chmod 600 /etc/vault-warden.yaml
```

**Config Content:**

```yaml
address: "http://127.0.0.1:8200"
unseal_keys:
  - "YOUR_KEY_1"
  - "YOUR_KEY_2"
  - "YOUR_KEY_3"
webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
audit_log: "/var/log/vault_audit.log"
```

---

## Systemd Deployment

We use three units to manage the lifecycle of the tool:

| Unit | Type | Command | Purpose |
| :--- | :--- | :--- | :--- |
| vault-warden.service | Simple | audit | Continuous Discord monitoring |
| vault-unlocker.service | Oneshot | unlock | Runs a single unseal check |
| vault-unlocker.timer | Timer | N/A | Triggers the unlocker every 2m |

### Deployment
1. Copy the .service and .timer files to /etc/systemd/system/.
2. Enable the stack:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-warden.service
sudo systemctl enable --now vault-unlocker.timer
```

---

## Operations

**Watch Warden Logs:**
`journalctl -fu vault-warden`

**Check Last Unseal Attempt:**
`systemctl status vault-unlocker`

**Verify Active Timers:**
`systemctl list-timers | grep vault`

---

## Security Posture
- Identity Enforcement: Audit logs capture Authentik OIDC display names for full accountability.
- Real-time Alerting: Immediate Discord notification for sign/root (SSH) and database/creds (DB) requests.
- Network Isolation: Vault remains bound to 127.0.0.1, with external access strictly managed via Cloudflare Tunnels.
