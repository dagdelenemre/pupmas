#!/usr/bin/env bash
# Quick updater for PUPMAS
set -e

INSTALL_DIR="/opt/pupmas"

if [ ! -d "$INSTALL_DIR" ]; then
  echo "[!] PUPMAS not installed. Install with:"
  echo "    curl -sSL https://raw.githubusercontent.com/dagdelenemre/pupmas/main/install.sh | sudo bash"
  exit 1
fi

echo "[+] Updating PUPMAS..."
cd "$INSTALL_DIR"
git pull -q origin main

if [ -d venv ]; then
  source venv/bin/activate
  pip install -q --upgrade pip
  pip install -q -r requirements.txt
fi

echo "[✓] Update complete! Version: $(git describe --tags 2>/dev/null || git rev-parse --short HEAD)"
