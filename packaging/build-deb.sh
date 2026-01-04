#!/usr/bin/env bash
set -euo pipefail

# Build a Debian package for PUPMAS
# Usage:
#   chmod +x packaging/build-deb.sh
#   VERSION=1.0.0 ./packaging/build-deb.sh
# Output:
#   pupmas_<VERSION>_all.deb (install with: sudo apt install ./pupmas_<VERSION>_all.deb)

VERSION=${VERSION:-1.0.0}
PKGNAME="pupmas"
WORKDIR=$(mktemp -d)
PKGROOT="$WORKDIR/$PKGNAME"
APP_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DST="$PKGROOT/opt/pupmas"

mkdir -p "$PKGROOT/DEBIAN" "$APP_DST" "$PKGROOT/usr/local/bin"

cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: pupmas
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Maintainer: dagdelenemre
Depends: python3, python3-venv, python3-pip, git
Description: PUPMAS cybersecurity automation tool with automated scanning pipeline
EOF

cat > "$PKGROOT/DEBIAN/postinst" <<'EOF'
#!/usr/bin/env bash
set -e
APP_DIR="/opt/pupmas"
cd "$APP_DIR"
if [ ! -d venv ]; then
  python3 -m venv venv
fi
source "$APP_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r requirements.txt
chmod +x /usr/local/bin/pupmas || true
exit 0
EOF
chmod 755 "$PKGROOT/DEBIAN/postinst"

rsync -a \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude '__pycache__' \
  --exclude 'data/logs' \
  "$APP_SRC"/ "$APP_DST"/

cat > "$PKGROOT/usr/local/bin/pupmas" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/pupmas"
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(cd "$(dirname "$SCRIPT_PATH")" && pwd)
if [ -d "$APP_DIR/venv" ]; then
  source "$APP_DIR/venv/bin/activate"
fi
exec python3 "$APP_DIR/pupmas.py" "$@"
EOF
chmod 755 "$PKGROOT/usr/local/bin/pupmas"

OUT="${PKGNAME}_${VERSION}_all.deb"
dpkg-deb --build "$PKGROOT" "$OUT"
echo "Built $OUT"
echo "Install with: sudo apt install ./$OUT"
