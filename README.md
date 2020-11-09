# INSTALLATION
apt update && apt upgrade -y && wget https://raw.githubusercontent.com/janda09/sshsedang/main/sshsedang.sh && chmod +x sshsedang.sh && ./sshsedang.sh

# FITUR

<br>OpenSSH : 22, 143, 2507
<br>Dropbear : 111, 222, 333
<br>SSL : 444 (openvpn SSL) 446
<br>OpenVPN : 443 (TCP) 445 (UDP)
<br>Squid3 : 80, 3128, 8080 (limit to IP SSH)
<br>Config OpenVPN: http://myip:81/sshsedang.zip
<br>badvpn : badvpn-udpgw port 7200
<br>nginx : 81

# NOTE
<br>Setelah selesai install ssh, Harap restart stunnel4 & squid !!!
