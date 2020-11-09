#!/bin/bash
#
# Original script by fornesia, rzengineer and fawzya 
# Mod by Janda Baper Group
# 
# ==================================================

# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# company name details
country=ID
state=JATIM
locality=KEDIRI
organization=sshsedang.site
organizationalunit=sshsedang site
commonname=sshsedang.site
email=sshsedang@gmail.com

# configure rc.local
cat <<EOF >/etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

exit 0
EOF
chmod +x /etc/rc.local
systemctl daemon-reload
systemctl start rc-local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local


# install wget and curl
apt-get -y install wget curl

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# set repo
echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list.d/webmin.list
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -

# update
apt-get update

# install webserver
apt-get -y install nginx

# install essential package
apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip unrar ssh

 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# Mod By Janda Baper Group
Port 22
Port 143
Port 2507
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/janda09/install/master/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by Ipang Nett Nott</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/janda09/install/master/vps.conf"

# install openvpn
apt-get -y install openvpn easy-rsa chrony  pam pam-devel pam_radius

cd /usr/share/easy-rsa/3
cat > /usr/share/easy-rsa/3/vars  << HERE
export KEY_COUNTRY="ID"
export KEY_PROVINCE="JATIM"
export KEY_CITY="KEDIRI"
export KEY_ORG="sshsedang.site"
export KEY_EMAIL="sshsedang@gmail.com"
export KEY_CN="sshsedang.site"
export KEY_OU="sshsedang.site"
export KEY_NAME="sshsedang.site"
export KEY_ALTNAMES="vpn-server"
HERE

. ./vars
./easyrsa init-pki
./easyrsa gen-dh
#./easyrsa build-ca
#./easyrsa gen-req vpn-server nopass
#./easyrsa sign-req server vpn-server
#openvpn --genkey --secret pki/ta.key
#cp -r pki/* /etc/openvpn/
 
cp -r /usr/share/easy-rsa/3/pki/dh.pem /etc/openvpn/dh.pem
cat > /etc/openvpn/ca.crt << HERE
-----BEGIN CERTIFICATE-----
MIIDMDCCAhigAwIBAgIUY+kFJtsaNkfBOLnOlTDrQAL4XuQwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEAwwCY2EwHhcNMjAwNjAzMDkxMjMzWhcNMzAwNjAxMDkxMjMz
WjANMQswCQYDVQQDDAJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMP7wIowX0FdjabvIm+jeBU3gdMiSnFcTY0lTlvVjagafAIxCHZmssRq3sttiHh+
j8ZcCg5myBhLwCICAJ2MthrpDtzvM4C3/JiTkzGjssnL2e5FV5VaPvuKWT/ZmVb5
Aq1Fdhsj88y+HQVxfeGFWo+yXebTc0/aUgE296LwgFp3tpAI3Vf1AnCfhPN1JBNG
RZic0dSmjj2psmMf+kaucISyYhrQUNFTsSXf5fy1Ak1gDLQMIpAnsT+webfByftZ
YYUy92G7+MfAFhf1UCMF0WsTu1ms8e8PLxMRBSeqwM75xCYQatIGyeiqYlTPlJ8n
4E3ziY1dqAEevMOA7dzr97MCAwEAAaOBhzCBhDAdBgNVHQ4EFgQUPjSqfGmn67bd
L5/7twL7J7KE2yowSAYDVR0jBEEwP4AUPjSqfGmn67bdL5/7twL7J7KE2yqhEaQP
MA0xCzAJBgNVBAMMAmNhghRj6QUm2xo2R8E4uc6VMOtAAvhe5DAMBgNVHRMEBTAD
AQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAtr1DGoOIAM4B9qnG
807AwG+LxCleJ4wBqcPrJglQEPiSpjTfKMP5XVkpQlYyVh85xfPOQQrTs7xpb2JS
hm7ILgy/qtuP0jt2KRRK5o86/cQ6CIymxTZBAJYgD6ocb5BU4B5/YAI85vaE1evI
fmHwlgppYUWBVOul8qcKRi9gp9uTXjw8558mIQIndeIfGGA36hWz+fNsw1BIudfL
YaiiO7QeUhZwmpdA7MXv9nfC73Al5vfk3/pN23OIderUQun1WKi5a/M6lRUa4vOJ
wnJa3QF5dBbAL2xjs9wKLBYZ8BfGHngycbOSCpj4+JRCgHakXLJsmSba3m5lfg86
zMrxdQ==
-----END CERTIFICATE-----
HERE

cat > /etc/openvpn/vpn-server.crt << HERE
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIQZ8r1uyJQdBllVc1T9II71TANBgkqhkiG9w0BAQsFADAN
MQswCQYDVQQDDAJjYTAeFw0yMDA2MDMwOTE3NTNaFw0yMjA5MDYwOTE3NTNaMA4x
DDAKBgNVBAMMA2NsMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANfU
P4kuoiAgkahHepfYA+Pc3NktwTKbxU7uDDwC4ZnhhgqK9sp+SDAdutbrZ4CGsnkC
6ZomGnrzkYsvnmaRBGjPwWCGY/jwJas6e/7AHx2Zj+vT0FykRojJNK80qR8ZFCpI
ki+1MQ7DfehLl+JJYQkpGUAWnBrEYhTOzJRpwmUhydhPymsrIUgXkiGGG82j+5h8
nkOdm9RkykNHxxXBtX9mv8bOKQLbSw7MWQzbyP/vAoJV6LJjq2EHXXhe2+wj4gqH
RLRpTKAKQ67bjgxBmI2NhpQ3HgrEskf3bqQx60kUDh9HoCLx6p89A+pnqiiBYpyn
8+1lGxb/+jWHH+zq31ECAwEAAaOBqTCBpjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRo
8dlXTx/gK7w1zh95+6WpAzwYSDBIBgNVHSMEQTA/gBQ+NKp8aafrtt0vn/u3Avsn
soTbKqERpA8wDTELMAkGA1UEAwwCY2GCFGPpBSbbGjZHwTi5zpUw60AC+F7kMBMG
A1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDAOBgNVHREEBzAFggNjbDEw
DQYJKoZIhvcNAQELBQADggEBAArYgpv4M4L/GXJCx03qatmRlzxulT4y4Lz0lfHS
CTD155f4ASGCPMw5TokriOgRGqnY5EmXpM6ck3qCvE0zrnSYDZCFMERoxRnEb78H
IZ0NkO6YevVGh+Uh3GbgRWylw0RZ/g1+9er5tQCnzjD0iE1YKCsaTVFTYVpUk2nT
1e2rBhTNIVSalw8xZPqHhJaGwLoBTxEV7Iua7/zTZzhyOrJLtnkMipFYptsJFx49
GpZnpnxxiS18MV7YlFLkzqVX0Bt94AnZodinlRPgQRkG6tu1+8exNPLolgFbgc3s
XuEiDHCIIwj//xt7e2fNy/gJHCzg2oBII6SpkYmvfJhffg0=
-----END CERTIFICATE-----
HERE

cat > /etc/openvpn/vpn-server.key << HERE
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDX1D+JLqIgIJGo
R3qX2APj3NzZLcEym8VO7gw8AuGZ4YYKivbKfkgwHbrW62eAhrJ5AumaJhp685GL
L55mkQRoz8FghmP48CWrOnv+wB8dmY/r09BcpEaIyTSvNKkfGRQqSJIvtTEOw33o
S5fiSWEJKRlAFpwaxGIUzsyUacJlIcnYT8prKyFIF5IhhhvNo/uYfJ5DnZvUZMpD
R8cVwbV/Zr/GzikC20sOzFkM28j/7wKCVeiyY6thB114XtvsI+IKh0S0aUygCkOu
244MQZiNjYaUNx4KxLJH926kMetJFA4fR6Ai8eqfPQPqZ6oogWKcp/PtZRsW//o1
hx/s6t9RAgMBAAECggEBAMDPMS9pRJa04crWiFNsPBVs8rLl6ClA9WRMzwsxe79P
tMJoYI6HgA/UD1z+kclFC92FV5FJJvDd9RDFqplwReMoblW/2UHDr7MnHSx5D5MO
437HC+YnL4f1T6aRweAxNE2N5WLPWJMa27kRBw+1hAV9/Lu/NxfGhuSV1jdjv7E9
eMxHmwbdIukK0W251tsvFhrXHnGVwmhLTzxQKcBgS08CBa1iV5FgmvJ23AqF02kr
pJRUMTE4e6R0AZRaUsrStNdDGVkKBlalxKN9rlCkaPttSU+Al/Hh6z8Npog3j/tv
kFAolXt5eRquALosAYfMNtpUbviDl0gUwEog90uinAECgYEA9TJ+TqEzet1WgwM2
bwfCBwY0zPSA+hb7EVRxw+pulqUrIIIkMaPuOTxHPRVO3iZ00IWEqsPa0+JDB51J
mYMPZDw3UH4kH1xiGfzn+2rkKFXCmlUGsc+go3NBFq1PwxYPAiGROkuENUSWArMN
M9790P7AiNJaeCLMmBUgS6+/j0ECgYEA4VaFLl3NgiQ524qvEGNwbe+2WsU1lOXA
RBzwP1eMa3wL7ptA6VcrGyPUFqgzyHszTvkuLaWF5TC35lGvRfb3oBLiDA8urIrE
bQJtS/xk4LGjGmZrjiWX7zjJk2+jztHk5YOH1yW0y33fcaSBssPMRdeo6VC3cfg4
DTQNArL3XBECgYAN0/srlAvDMhhe6x92w4k9vCveIyvi7sjaAVkpI195P3dfLfe8
lPIqaCvcVgdMn/6Wg/EncEQ3DtuY4lX0Ql/r1zmHYJXI7vzZWln649xaKfv/mCv4
ey0kCqvxC3UkG2pdRGdcUkXyexu6qz5jXoAR+UwCa1qOy+ed7BMWMaMsAQKBgHBP
RyHM7timZY/el1J7vVWN3D1xfTsxJ5rLMZLgd8Q6l1fdWYTzRTDJsrN4MhcCEJiT
6Ugm741DsuTAYbNlXBYUU0Xfa0vj/fK2+vKcYUr8PmayFXlLk2ZPz2gEhIhYZNVf
sRyyVmH14qApdds7a1yEGFPxPv020fkCsFlgCZmBAoGBALiAkKutcAm7Vu5StiR9
HbQiYJIQawrdgzkFh2OC3uaF1FsN1nR51EcM4jxfWkh/RaOdB4+IqsIbHb/SaP+u
ygTSoxdp6ExukMpTIJiETtxm6Fz6uUl+OlPWBhUIDkIiOWOnl0aaMF1VI9d9EzHv
Lj0U1EWqlmePlpDY5H1/CoSP
-----END PRIVATE KEY-----
HERE

cd /etc/openvpn
mkdir /var/log/openvpn/
cat >  /etc/openvpn/sshsedang-UDP.ovpn << HERE
plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
##############################################
#              SSH SEDANG GROUP              #
#                SSH SEDANG ™                #
##############################################
port 445
proto udp
dev tun21
ca /etc/openvpn/ca.crt
cert /etc/openvpn/vpn-server.crt
key /etc/openvpn/vpn-server.key
dh /etc/openvpn/dh.pem
server 10.0.0.0 255.255.0.0
push "redirect-gateway def1"
push "remote-gateway 10.0.0.1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
max-clients 1032
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
log-append  /var/log/openvpn/openvpn1.log
verb 6
mute 20
explicit-exit-notify 1
daemon
mode server
verify-client-cert none
HERE
 
cat > /etc/openvpn/sshsedang-TCP.ovpn << HERE
plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
##############################################
#              SSH SEDANG GROUP              #
#                SSH SEDANG ™                #
##############################################
port 443
proto tcp
dev tun12
ca /etc/openvpn/ca.crt
cert /etc/openvpn/vpn-server.crt
key /etc/openvpn/vpn-server.key
dh /etc/openvpn/dh.pem
server 10.4.0.0 255.255.0.0
#ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "remote-gateway 10.4.0.1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"
duplicate-cn
keepalive 10 120
max-clients 1032
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
verb 3
mute 20
daemon
mode server
verify-client-cert none
HERE
wget  -O /etc/openvpn/sshsedang-SSL.ovpn "https://raw.githubusercontent.com/janda09/sshsedang/main/sshsedang-SSL.conf"
echo '<ca>' >> /etc/openvpn/sshsedang-SSL.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/sshsedang-SSL.ovpn
echo '</ca>' >> /etc/openvpn/sshsedang-SSL.ovpn

ln -sf /usr/sbin/openvpn /etc/init.d/openvpn.udp
ln -sf /usr/sbin/openvpn /etc/init.d/openvpn.tcp
 
cat > /etc/systemd/system/openvpn-tcp.service << HERE
[Unit]
Description=OpenVPN TCP
After=network.target
 
[Service]
Type=forking
ExecStart=/etc/init.d/openvpn.tcp /etc/openvpn/sshsedang-TCP.ovpn
 
[Install]
WantedBy=multi-user.target
HERE

cat > /etc/systemd/system/openvpn-udp.service << HERE
[Unit]
Description=OpenVPN UDP
After=network.target
 
[Service]
Type=forking
ExecStart=/etc/init.d/openvpn.udp /etc/openvpn/sshsedang-UDP.ovpn
 
[Install]
WantedBy=multi-user.target
HERE

cat > /etc/pam.d/openvpn << HERE
auth	    required    	pam_radius_auth.so
account  required    	pam_radius_auth.so
HERE

cat >/etc/pam_radius.conf << HERE
# server[:port] shared_secret  	timeout (s)
$RADSRV $RADPASS        	3
HERE
 
systemctl enable openvpn-udp && systemctl start openvpn-udp 
systemctl enable openvpn-tcp && systemctl start openvpn-tcp 

cat > /etc/sysctl.conf << HERE
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
HERE
sysctl -p /etc/sysctl.conf

cp sshsedang-TCP.ovpn /home/vps/public_html/
cp sshsedang-UDP.ovpn /home/vps/public_html/
cp sshsedang-SSL.ovpn /home/vps/public_html/

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/janda09/install/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/janda09/install/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200

# Install and Configure PPTP VPN
apt-get install pptpd -y
cat <<END> /etc/ppp/pptpd-options
ms-dns 8.8.8.8
ms-dns 8.8.4.4

END

cat <<END> /etc/pptpd.conf
localip $MYIP
remoteip $MYIP-225

END
pptpd restart 
cat <<'END'> /etc/sysctl.conf
net.ipv4.ip_forward=1

END
sysctl -p
iptables -P FORWARD ACCEPT
iptables --table nat -A POSTROUTING -o venet0 -j MASQUERADE

cat <<END> /etc/network/if-pre-up.d/iptablesload
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0

END
chmod +x /etc/network/if-pre-up.d/iptablesload
sysctl -p

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/Port 143/Port 143/g' /etc/ssh/sshd_config
sed -i 's/Port 2507/Port 2507/g' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=111/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 222 -p 333"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
apt-get -y install squid
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/janda09/sshsedang/main/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf;

# install webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf

# install stunnel
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 444
connect = 127.0.0.1:111
accept = 555
connect = 127.0.0.1:111
accept = 666
connect = 127.0.0.1:111

[openvpn]
accept = 446
connect = 127.0.0.1:443

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# configure stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
cd /etc/stunnel/
wget -O /etc/stunnel/ssl.conf "https://raw.githubusercontent.com/janda09/sshsedang/main/ssl.conf"
sed -i $MYIP2 /etc/stunnel/ssl.conf;
cp ssl.conf /home/vps/public_html/
cd

# colored text
apt-get -y install ruby
gem install lolcat

# install fail2ban
apt-get -y install fail2ban

# install ddos deflate
cd
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/janda09/install/master/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# banner /etc/bnr
cd
wget -O /etc/bnr "https://raw.githubusercontent.com/janda09/sshsedang/main/bnr"
wget -O /etc/banner "https://raw.githubusercontent.com/janda09/sshsedang/main/banner"
sed -i 's@#Banner@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/bnr"@g' /etc/default/dropbear

# xml parser
cd
apt-get install -y libxml-parser-perl

# compress configs
cd /home/vps/public_html
zip sshsedang.zip ssl.conf sshsedang-SSL.ovpn sshsedang-TCP.ovpn sshsedang-UDP.ovpn

# Installing Premium Script
cd
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.d/rc.local
echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire
echo "0 0 * * * root /usr/local/bin/user-expire-pptp" > /etc/cron.d/user-expire-pptp

cat > /root/ban.sh <<END3
#!/bin/bash
#/usr/local/bin/user-ban
END3

cat > /root/limit.sh <<END3
#!/bin/bash
#/usr/local/bin/user-limit
END3

cd /usr/local/bin
wget -O premi.zip "https://raw.githubusercontent.com/janda09/openvpn/master/premi.zip"
unzip premi.zip
rm -f premi.zip

cp /usr/local/bin/premium-script /usr/local/bin/menu
chmod +x /usr/local/bin/*
cd
#set auto kill multi login
cd /usr/bin
wget -O janda "https://raw.githubusercontent.com/janda09/install/master/set_multilogin_autokill_lib"
chmod +x janda
echo "* * * * * root /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 5; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 10; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 15; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 20; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 25; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 30; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 35; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 40; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 45; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 50; /usr/bin/janda 2" >> /etc/crontab
echo "* * * * * root sleep 55; /usr/bin/janda 2" >> /etc/crontab

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
service cron restart
service sshd restart
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/webmin restart
/etc/init.d/stunnel4 stop
/etc/init.d/stunnel4 start
/etc/init.d/squid start
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# grep ports 
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
nginxport="$(netstat -nlpt | grep -i nginx| grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

# install neofetch
curl "https://bintray.com/user/downloadSubjectPublicKey?username=bintray"| apt-key add -
apt-get update
apt-get install neofetch
apt-get install vnstat -y

# Creating Profile Info
echo 'clear' > /etc/profile.d/janda.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/janda.sh
echo 'neofetch ' >> /etc/profile.d/janda.sh
echo 'echo -e "" ' >> /etc/profile.d/janda.sh
echo 'echo -e "################################################" ' >> /etc/profile.d/janda.sh
echo 'echo -e "#                 SSH SEDANG ™                 #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "#               SSH SEDANG GROUP               #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "# Ketik menu untuk menampilkan daftar perintah #" ' >> /etc/profile.d/janda.sh
echo 'echo -e "################################################" ' >> /etc/profile.d/janda.sh
echo 'echo -e "" ' >> /etc/profile.d/janda.sh
chmod +x /etc/profile.d/janda.sh

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean

# info
clear
bash /etc/profile.d/janda.sh
echo "Autoscript Include:" | tee log-install.txt
echo "===========================================" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Service"  | tee -a log-install.txt
echo "-------"  | tee -a log-install.txt
echo "OpenSSH    : 22, 143, 2507"  | tee -a log-install.txt
echo "Dropbear   : 111, 222, 333"  | tee -a log-install.txt
echo "SSL        : 444, 555, 666"  | tee -a log-install.txt
echo "OpenVPNSSL : 446"  | tee -a log-install.txt
echo "OpenVPN    : TCP 443"  | tee -a log-install.txt
echo "OpenVPN    : UDP 445"  | tee -a log-install.txt
echo "Squid3     : 80, 3128, 8080 (limit to IP SSH)"  | tee -a log-install.txt
echo "Config VPN : http://$MYIP:81/sshsedang.zip"  | tee -a log-install.txt
echo "badvpn     : badvpn-udpgw port 7200"  | tee -a log-install.txt
echo "nginx      : 81"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Script"  | tee -a log-install.txt
echo "------"  | tee -a log-install.txt
echo "menu (Displays a list of available commands)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Other features"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "Webmin     : http://$MYIP:10000/"  | tee -a log-install.txt
echo "Timezone   : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "IPv6       : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Original Script by Fornesia, Rzengineer & Fawzya"  | tee -a log-install.txt
echo "Mod by SSH SEDANG ™"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
cd
rm -f /root/sshsedang.sh
