#!/bin/bash
# JP OFFICIAL AUTO INSTALLER

CABANG="utama"
NAMA_KODE_PINJAMAN="JP_V1.zip"
NAMA_FOLDER="JP_V1"

gem="====================================="
gem="    INSTALASI MOBIL RESMI JP"
gem="====================================="

tidur 1

CD/akar

gem "[1/4] Perbarui dependensi..."
apt update -y >/dev/null 2>&1 || yum update -y >/dev/null 2>&1 || apt install -y wget curl unzip >/dev/null 2>&1 || yum install -y wget curl unzip >/dev/null 2>&1 || echo "Gagal mengunduh file:"

gem "[2/4] Hapus file lama..."
rm -rf "$FOLDER_NAME"

gem "[3/4] Download paket panel JP OFFICIAL..."
URL_UNDUH="https://github.com/VPNULTIMATE/JP_V1/raw/main/JP_V1.zip"
wget -q "$URL_UNDUH"

gem "[4/4] Ekstrak dan install..."
buka ritsleting "$ZIP_NAME" > /dev/null 2>&1
CD "$FOLDER_NAME"

chmod +x main.sh
./main.sh

gem=""
gem "====================================="
gem "   INSTALATOR JP RESMI SELESAI"
gem "====================================="
