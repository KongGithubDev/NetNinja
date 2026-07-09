#!/bin/bash
set -e

echo "========================================"
echo "   NetNinja Xray REALITY Server Setup   "
echo "========================================"

UUID="${1:-b831381d-6324-4d53-ad4f-8cda48b30811}"

# ── 1. Install Xray-core ────────────────────────────────────────────
if ! command -v xray &>/dev/null; then
    echo "[1/3] Installing Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
else
    echo "[1/3] Xray-core already installed"
fi

# ── 2. Generate REALITY key pair ────────────────────────────────────
echo "[2/3] Generating REALITY key pair..."
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')

echo "  Private Key: $PRIVATE_KEY"
echo "  Public Key : $PUBLIC_KEY"

# ── 3. Write server config ──────────────────────────────────────────
echo "[3/3] Writing server config..."
cat > /usr/local/etc/xray/config.json <<EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.microsoft.com:443",
                    "serverNames": [
                        "www.microsoft.com",
                        "www.bing.com"
                    ],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": [
                        "6ba85179e30d4fc2"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "block"
            }
        ]
    }
}
EOF

# ── 4. Firewall ─────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow 443/tcp
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --reload
fi

# ── 5. Restart Xray ────────────────────────────────────────────────
systemctl restart xray || true

echo ""
echo "========================================"
echo "   SERVER READY"
echo "========================================"
echo "  UUID      : $UUID"
echo "  Port      : 443"
echo "  Public Key: $PUBLIC_KEY"
echo "  ShortId   : 6ba85179e30d4fc2"
echo "  Dest      : www.microsoft.com:443"
echo ""
echo "Share Public Key with your clients!"
echo "========================================"
