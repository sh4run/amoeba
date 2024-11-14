#!/bin/bash 
#
# Usage: 
#      sudo ./install-amoeba-server.sh <port-num>
#

if ! [ "$1" -eq "$1" ] 2>/dev/null
then
   echo "Usage:"
   echo "    sudo ./install-amoeba-server.sh <port-num>"
   exit
fi

if [ "$(id -u)" -ne 0 ]; then
   echo "Usage:"
   echo "    sudo ./install-amoeba-server.sh $1"
   exit
fi

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

CONF="/etc/amoeba/amoeba.json"
SYSTEMD="/etc/systemd/system/amoeba.service"

if [ -f ${CONF} ]; then
    echo "Found existing config ${CONF}"
    exit
fi

if [ -f ${SYSTEMD} ]; then
    echo "Found existing service ${SYSTEMD}"
    systemctl daemon-reload
    systemctl restart amoeba
    exit
fi

cp -f amoeba /usr/local/bin/

username=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
RNUM=$(date +%N)
RNUM=${RNUM#0}
SCRAMB=$(( $RNUM % 300 +20 ))
server_ip=`ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'`

rm -f amoeba-key*
ssh-keygen -b 1024 -m pem -t rsa -f amoeba-key -N "" -q
ssh-keygen -m pem -e -f amoeba-key >amoeba-key.pub.pem

mkdir /etc/amoeba/
cp amoeba-key /etc/amoeba
cp server.json amoeba.json
sed -i "s/userA/$username/g" amoeba.json
sed -i "s/password-user-a/$password/g" amoeba.json
sed -i "s/88/$SCRAMB/g" amoeba.json
sed -i "s/9191/$1/g" amoeba.json
sed -i "s/testkey/\/etc\/amoeba\/amoeba-key/g" amoeba.json
cp amoeba.json ${CONF}

cp client.json amoeba-client.json
sed -i "s/userA/$username/g" amoeba-client.json
sed -i "s/password-user-a/$password/g" amoeba-client.json
sed -i "s/88/$SCRAMB/g" amoeba-client.json
sed -i "s/9191/$1/g" amoeba-client.json
sed -i "s/testkey/\/etc\/amoeba\/amoeba-key/g" amoeba-client.json
sed -i "s/5566/$1/g" amoeba-client.json
sed -i "s/127.0.0.1/$server_ip/g" amoeba-client.json
tar czvf amoeba-client.tar.gz amoeba amoeba-key.pub.pem amoeba-client.json

echo "Generating new service..."
echo "[Unit]" >>${SYSTEMD}
echo "Description=amoeba service" >>${SYSTEMD}
echo "After=network.target" >>${SYSTEMD}
echo "" >>${SYSTEMD}
echo "[Service]" >>${SYSTEMD}
echo "Type=simple" >>${SYSTEMD}
echo "LimitNOFILE=32768" >>${SYSTEMD}
echo "ExecStart=/usr/local/bin/amoeba -c ${CONF}" >>${SYSTEMD}
echo "" >>${SYSTEMD}
echo "[Install]" >>${SYSTEMD}
echo "WantedBy=multi-user.target" >>${SYSTEMD}

systemctl daemon-reload
systemctl enable amoeba
systemctl start amoeba

rm -r amoeba-key*
rm amoeba.json
rm amoeba-client.json

