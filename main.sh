#!/bin/bash
# JP OFFICIAL AUTO INSTALLER

set -e

REPO="VPNULTIMATE/JP_V1"
BRANCH="main"
ZIP_NAME="JP_V1.zip"
FOLDER_NAME="JP_V1"

clear
echo "====================================="
echo "      JP OFFICIAL AUTO INSTALL       "
echo "====================================="
echo ""
sleep 1

cd /root

echo "[1/4] Update dependencies..."
apt update -y >/dev/null 2>&1 || yum update -y >/dev/null 2>&1 || true
apt install -y wget curl unzip >/dev/null 2>&1 || yum install -y wget curl unzip >/dev/null 2>&1 || true

echo "[2/4] Hapus file lama..."
rm -rf "$FOLDER_NAME" "$ZIP_NAME"

echo "[3/4] Download paket panel JP OFFICIAL..."
DOWNLOAD_URL="https://github.com/${REPO}/raw/${BRANCH}/${ZIP_NAME}"
wget --no-check-certificate -O "$ZIP_NAME" "$DOWNLOAD_URL"

if [[ ! -f "$ZIP_NAME" ]]; then
    echo "Gagal download file:"
    echo "$DOWNLOAD_URL"
    exit 1
fi

echo "[4/4] Extract dan install..."
unzip "$ZIP_NAME" >/dev/null 2>&1
cd "$FOLDER_NAME"

chmod +x main.sh
./main.sh

echo ""
echo "====================================="
echo "   INSTALLER JP OFFICIAL SELESAI"
echo "====================================="
