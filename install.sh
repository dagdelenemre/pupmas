#!/usr/bin/env bash
set -euo pipefail

# Simple installer for PUPMAS
# - Clones/updates the repo
# - Creates a virtualenv
# - Installs dependencies
# - Installs launcher to /usr/local/bin/pupmas

REPO_URL="https://github.com/dagdelenemre/pupmas.git"
INSTALL_DIR="${INSTALL_DIR:-/opt/pupmas}"
LAUNCHER="/usr/local/bin/pupmas"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[!] python3 bulunamadı. Lütfen python3 kurun." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "[!] git bulunamadı. Lütfen git kurun (sudo apt install git)." >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Lütfen sudo ile çalıştırın: sudo ./install.sh" >&2
  exit 1
fi

echo "[+] Kurulum dizini: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "[+] Repo mevcut, güncelleniyor..."
  git -C "$INSTALL_DIR" pull --ff-only
else
  echo "[+] Repo klonlanıyor..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

if [ ! -d venv ]; then
  echo "[+] Virtualenv oluşturuluyor..."
  "$PYTHON_BIN" -m venv venv
fi

source venv/bin/activate

echo "[+] Bağımlılıklar yükleniyor..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Launcher yazılıyor: $LAUNCHER"
cat > "$LAUNCHER" <<'EOF'
#!/usr/bin/env bash
APP_DIR="/opt/pupmas"
VENV="$APP_DIR/venv"
if [ -d "$VENV" ]; then
  source "$VENV/bin/activate"
fi
exec "$VENV/bin/python" "$APP_DIR/pupmas.py" "$@"
EOF

chmod +x "$LAUNCHER"

echo "[+] Kurulum tamamlandı. Çalıştırmak için: pupmas --help"
