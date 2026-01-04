#!/usr/bin/env bash
# Quick installer for PUPMAS
set -e

echo "[+] Installing PUPMAS..."

# Check dependencies
for cmd in python3 git; do
  if ! command -v $cmd &>/dev/null; then
    echo "[!] $cmd not found. Installing..."
    apt-get update -qq
    apt-get install -y $cmd
  fi
done

# Install to /opt/pupmas
INSTALL_DIR="/opt/pupmas"
if [ -d "$INSTALL_DIR" ]; then
  echo "[+] Updating existing installation..."
  cd "$INSTALL_DIR"
  git pull -q
else
  echo "[+] Cloning repository..."
  git clone -q https://github.com/dagdelenemre/pupmas.git "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# Setup venv and install deps
if [ ! -d venv ]; then
  python3 -m venv venv
fi
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Configure directories
mkdir -p data/logs data/reports data/timelines
chmod 755 data data/logs data/reports data/timelines

# Initialize config if needed
if [ -f config/config.yaml.example ] && [ ! -f config/config.yaml ]; then
  cp config/config.yaml.example config/config.yaml
  echo "[+] Created default config"
fi

# Create launcher
cat > /usr/local/bin/pupmas <<'EOF'
#!/usr/bin/env bash
APP_DIR="/opt/pupmas"
source "$APP_DIR/venv/bin/activate"
exec python3 "$APP_DIR/pupmas.py" "$@"
EOF
chmod +x /usr/local/bin/pupmas

echo "[✓] Done! Run: pupmas --help"
