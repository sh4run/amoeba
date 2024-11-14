#!/bin/bash
#
# Usage: 
#      sudo ./install-amoeba-client.sh
#

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

tar xzvf amoeba-client.tar.gz

mkdir /etc/amoeba/
cp amoeba-key.pub.pem /etc/amoeba/
cp amoeba-client.json ${CONF}
cp amoeba /usr/local/bin/

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

rm amoeba-client.json
rm amoeba-key.pub.pem
rm amoeba

