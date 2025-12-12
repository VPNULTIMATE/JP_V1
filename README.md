# JP_V1 — AutoScript VPN/Xray Installer

🚀 **JP_V1** adalah _autoscript_ berbasis **bash shell** untuk VPS (Debian/Ubuntu) yang membantu instalasi dan konfigurasi lengkap layanan VPN dan tunneling secara otomatis.  
Mendukung berbagai protokol populer seperti:
- SSH / OpenVPN / UDP / Dropbear
- Xray (VMESS, VLESS, TROJAN, GRPC, TLS, WS)
- Fail2Ban / Firewall / Backup & Restore otomatis

---

## 🧰 **Fitur Unggulan**

✅ Multi-Port & Multi-Protocol  
✅ Auto Setup Domain & SSL  
✅ Support Debian 10+ & Ubuntu 20+  
✅ Auto Install Xray Core  
✅ Menu interaktif (ketik `menu`)  
✅ Full Logging & Monitoring  
✅ Auto reboot & cleanup system  

---

## ⚙️ **Cara Install**

Jalankan perintah di bawah ini di VPS kamu:

```bash
sudo apt update && sudo apt install -y curl
bash <(curl -sSL https://raw.githubusercontent.com/VPNULTIMATE/JP_V1/main/main.sh)
