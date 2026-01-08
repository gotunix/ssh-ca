# SSH Certificate Authority (CA) Management Tool

This script provides a complete SSH CA solution for:

- Generating SSH CA key pairs
- Signing user public keys with certificates
- Tracking all signed certificates
- Managing Key Revocation Lists (KRL)
- Revoking certificates
- Distributing KRL to remote servers

## Directory Structure

By default, the SSH CA uses `~/.sshca/` as the CA directory:

```
~/.sshca/
├── ca                      # CA private key
├── ca.pub                  # CA public key
├── certificates.json       # Certificate database
├── ca_config.json          # CA configuration
├── revoked_keys.krl        # Key Revocation List
├── inventory/              # Inventory files (optional)
│   └── servers.yaml
└── reports/                # Custom report templates (optional)
    └── sshca_report_template.html
```

## Usage

### Initialize a new CA (unencrypted)

```bash
# Creates ~/.sshca/ directory
ssh-ca init --name "MyCompany-CA"
```

### Initialize an encrypted CA (recommended for production)

```bash
# Creates ~/.sshca/ directory
ssh-ca init --name "Production-CA" --prompt-passphrase
```

### Sign a user's public key (1 year validity)

```bash
ssh-ca sign --public-key user.pub --identity user@example.com --principals user,admin --validity 1y
```

### Sign with custom duration (1 day, 1 week, 6 months, etc.)

```bash
ssh-ca sign --public-key user.pub --identity user@example.com --principals user --validity 1d
ssh-ca sign --public-key user.pub --identity user@example.com --principals user --validity 1w
ssh-ca sign --public-key user.pub --identity user@example.com --principals user --validity 6M
```

### Sign same key with multiple CAs (use --ca-dir to specify different CAs)

```bash
ssh-ca --ca-dir /path/to/prod-ca sign user.pub --identity user@prod --principals user --output user-cert-prod.pub
ssh-ca --ca-dir /path/to/staging-ca sign user.pub --identity user@staging --principals user --output user-cert-staging.pub
ssh-ca --ca-dir /path/to/dev-ca sign user.pub --identity user@dev --principals user,admin --output user-cert-dev.pub
```

### Sign a key on a remote server

```bash
ssh-ca sign-remote --server web1.example.com --remote-key /home/alice/.ssh/id_ed25519.pub \
                   --identity alice@example.com --principals alice,webadmin --validity 1y
```

### List all signed certificates

```bash
ssh-ca list
```

### Revoke a certificate

```bash
ssh-ca revoke --serial 1 --reason "User left company"
```

### Update the KRL

```bash
ssh-ca update-krl
```

### Push KRL to remote servers

```bash
# Using inventory file from ~/.sshca/inventory/
ssh-ca push-krl --inventory servers.yaml

# Or with full path
ssh-ca push-krl --inventory /path/to/ssh-inventory.yaml
```

### Push KRL to specific group or servers

```bash
ssh-ca push-krl --inventory servers.yaml --limit webservers
ssh-ca push-krl --inventory servers.yaml --limit "prod*"
```

### Push CA public key to remote servers

```bash
ssh-ca push-ca --inventory servers.yaml
```

### Push CA to specific group or servers

```bash
ssh-ca push-ca --inventory servers.yaml --limit webservers
ssh-ca push-ca --inventory servers.yaml --limit "prod*"
```

### Remove CA public key from remote servers

```bash
ssh-ca remove-ca --inventory servers.yaml
```

### Remove CA from specific servers

```bash
ssh-ca remove-ca --inventory servers.yaml --limit webservers
```

### List CA deployment status on remote servers

```bash
ssh-ca list-ca-deployments --inventory servers.yaml
```

### Check CA deployment on specific servers

```bash
ssh-ca list-ca-deployments --inventory servers.yaml --limit webservers
```

### Show CA information

```bash
ssh-ca info
```

## Duration formats

- `1s`, `1m`, `1h`, `1d`, `1w`, `1M` (months), `1y` (years)
- Or ssh-keygen format: `+52w`, `-1d:+52w`, `always`

## Environment Variables

- `SSHCA_DIR`: Default CA directory (default: `~/.sshca`). Example: `export SSHCA_DIR=/etc/ssh-ca`

## Inventory Files

Inventory files can be placed in `~/.sshca/inventory/` and referenced by filename only:

```bash
# Create inventory file
mkdir -p ~/.sshca/inventory
cat > ~/.sshca/inventory/production.yaml << EOF
servers:
  - web1.example.com
  - web2.example.com
ssh_user: deploy
ca_path: /etc/ssh/ca.pub
krl_path: /etc/ssh/revoked_keys.krl
EOF

# Use it by filename
ssh-ca push-ca --inventory production.yaml
```

## Custom Report Templates

Place custom Jinja2 templates in `~/.sshca/reports/sshca_report_template.html` to customize report output.
