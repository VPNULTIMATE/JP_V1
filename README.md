# 🧠 JP_V1 — AutoScript VPN / XRAY Installer

![Version](https://img.shields.io/badge/version-1.0-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-success)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/build-passing-brightgreen)

> 🔧 **JP_V1** dibuat oleh **VPNULTIMATE** — installer otomatis untuk VPS (Debian/Ubuntu)  
> yang mengatur layanan **VPN, XRAY, dan Tunneling** secara lengkap dan cepat.  
> Dirancang untuk efisiensi ⚡, kestabilan 🛡️, dan kemudahan penggunaan 💻.

---

## ⚙️ Fitur Utama

✅  Multi-Port & Multi-Protocol  
✅  Auto Setup Domain & SSL  
✅  Support Debian 10+ & Ubuntu 20+  
✅  Auto Install XRAY Core  
✅  Menu Interaktif (ketik `menu`)  
✅  Full Logging & Monitoring  
✅  Auto Reboot & Cleanup System  

---

## 🧩 Protokol yang Didukung

| Jenis              | Protokol                                |
|--------------------|------------------------------------------|
| **SSH / OpenVPN**  | UDP, Dropbear, WebSocket                 |
| **XRAY Core**      | VMESS, VLESS, TROJAN, GRPC, TLS, WS      |
| **Keamanan**       | Fail2Ban, UFW Firewall                   |
| **Manajemen**      | Backup / Restore otomatis                |

---

## 🚀 Cara Install

Jalankan perintah berikut di VPS kamu (sebagai root):

```bash
sudo apt update && sudo apt install -y curl
bash <(curl -sSL https://raw.githubusercontent.com/VPNULTIMATE/JP_V1/main/main.sh)

Atau jika ingin menyimpan file terlebih dahulu:

wget -O main.sh https://raw.githubusercontent.com/VPNULTIMATE/JP_V1/main/main.sh
chmod +x main.sh
sudo ./main.sh


---

🧠 Menu Utama

Setelah instalasi selesai dan VPS reboot, ketik perintah:

menu

📋 Daftar Menu:

1) SSH / OpenVPN
2) Xray / Vmess / Vless / Trojan
3) Backup / Restore
4) Fail2ban / Firewall
5) System Info
0) Exit


---

🗂 Struktur Folder

JP_V1/
├── files/              # File konfigurasi tambahan (config, SSL, menu)
├── main.sh             # Script utama installer
├── menu.zip            # File pendukung untuk sistem menu
├── LICENSE             # Lisensi MIT
└── README.md           # Dokumentasi proyek


---

🧾 Lisensi

Proyek ini dirilis di bawah MIT License —
Kamu bebas menggunakan, memodifikasi, dan mendistribusikan ulang script ini selama mencantumkan kredit ke VPNULTIMATE.

📄  Lihat detail lisensi: LICENSE


---

📬 Kontak & Dukungan

📢  Telegram: @JPOFFICIALSTORE
🌐  GitHub Repo: VPNULTIMATE / JP_V1
💬  Dikelola oleh tim developer VPNULTIMATE


---

🧡  Dibuat dengan semangat open source
“Simple Setup, Powerful Performance”
