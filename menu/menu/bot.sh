#!/bin/bash
MYIP=$(wget -qO- ipinfo.io/ip);

IZIN=$(curl -sS https://raw.githubusercontent.com/RaikazuWebId/izinsc/main/ip | awk '{print $4}' | grep $MYIP)
if [ $MYIP = $IZIN ]; then
echo "IZIN DI TERIMA!!"
else
clear
figlet "Akses Di Tolak, Emang Enak Di Tolak?" | lolcat
exit 0
fi
clear

# WARNA ATAU COLOR 
BR='\e[94;1m'
green='\033[0;32m'
r="\e[91;1m"
RED="\e[91;1m"
Blu_Cy="\e[5;36m"
# // color format 38
runn='\e[38;5;14m' 
acc='\e[38;5;146m'
LO='\e[38;5;162m'
UK='\e[38;5;99m'  # UNGU KOLOT
BK='\e[38;5;196m' # BEREM KOLOT 
R1='\e[38;5;155m' # HEJO SEMU BODAS
R2='\e[38;5;49m'  # HEJO LIME / APEL
BC='\e[38;5;195m' # BODAS CERAH PISAN
HU='\e[38;5;115m' # HEJO SEMU ABU
UB='\e[38;5;147m' # UNGU KABODASAN
KT='\e[38;5;187m' # KONENG TARIGU
Suffix='\e[0m'

#install
cp /media/cybervpn/var.txt /tmp
cp /root/cybervpn/var.txt /tmp
rm -rf cybervpn
apt update && apt upgrade -y
apt install python3 python3-pip -y
apt install sqlite3 -y
cd /media/
rm -rf cybervpn
wget https://raw.githubusercontent.com/RaikazuWebId/vpnscript/mytich/bot/cybervpn.zip
unzip cybervpn.zip
cd cybervpn
rm var.txt
rm database.db
rm log-install.txt
pip3 install -r requirements.txt
pip install pillow
pip install speedtest-cli
pip3 install aiohttp
pip3 install paramiko
#isi data
azi=$(cat /root/nsdomain)
domain=$(cat /etc/xray/domain)
clear
echo "INSTALL BOT CREATE SSH via TELEGRAM"
read -e -p "[*] Input Your Id Telegram :" admin
read -e -p "[*] Input Your bot Telegram :" token
read -e -p "[*] Input username Telegram :" user

cat > /media/cybervpn/var.txt << END
ADMIN="$admin"
BOT_TOKEN="$token"
DOMAIN="$domain"
DNS="$azi"
PUB="7fbd1f8aa0abfe15a7903e837f78aba39cf61d36f183bd604daa2fe4ef3b7b59"
OWN="$user"
SALDO="999999"
END


clear
echo "Done"
echo "Your Data Bot"
echo -e "==============================="
echo "API KEY TOKEN : $token"
echo "ID            : $admin"
echo "DOMAIN        : $domain"
echo -e "==============================="
echo "Setting done"


rm -f /usr/bin/nenen

echo -e '#!/bin/bash\ncd /media/\npython3 -m cybervpn' > /usr/bin/nenen


chmod 777 /usr/bin/nenen

cat > /etc/systemd/system/cybervpn.service << END
[Unit]
Description=Simple CyberVPN - @CyberVPN
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/nenen
Restart=always

[Install]
WantedBy=multi-user.target

END
systemctl daemon-reload
systemctl start cybervpn
systemctl enable cybervpn

clear
echo "Cek Asset Bot"
rm -f /usr/bin/panelbot
rm -f /usr/bin/addnoobz
rm -f /usr/bin/add-vless
rm -f /usr/bin/addtr
rm -f /usr/bin/addws
rm -f /usr/bin/addssh
rm -f /usr/bin/cek-ssh
rm -f /usr/bin/cek-ssh
rm -f /usr/bin/cek-tr
rm -f /usr/bin/cek-vless
rm -f /usr/bin/cek-ws
rm -f /usr/bin/del-vless
rm -f /usr/bin/cek-noobz
rm -f /usr/bin/deltr
rm -f /usr/bin/delws
rm -f /usr/bin/delss
rm -f /usr/bin/renew-ss
rm -f /usr/bin/renewtr
rm -f /usr/bin/renewvless
rm -f /usr/bin/renewws
rm -f /usr/bin/cek-mws
rm -f /usr/bin/cek-mvs
rm -f /usr/bin/cek-mss
rm -f /usr/bin/cek-mts

echo "Downloading Assets"

cd /usr/bin/

wget https://raw.githubusercontent.com/RaikazuWebId/vpnscript/mytich/bot/raikazuvpn.zip
unzip raikazuvpn.zip

echo "Downloading Assets Done Maseeh"



cp /tmp/var.txt /media/cybervpn

function RaikazuGanteng() {
rm /media/cybervpn.zip
rm /usr/bin/raikazuvpn.zip
echo -e "       ${BR}┌──────────────────────────────────────┐${Suffix}"
echo -e "       ${BC}     --[ INSTALATION SUCCESSFULL ]--           ${Suffix}"
echo -e "       ${BC}       --[ ENTER TO BACK MENU ]--              ${Suffix} " 
echo -e "       ${BR}└──────────────────────────────────────┘${Suffix}"
echo ""
}
function Open_Menu() {
echo -e ""
read -n 1 -s -r -p "--"
menu
}
RaikazuGanteng
Open_Menu