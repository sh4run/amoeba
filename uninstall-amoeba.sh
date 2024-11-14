#!/bin/bash
#
# Usage: 
#    sudo bash ./uninstall-amoeba.sh
#

CONF_DIR="/etc/amoeba/"
SYSTEMD_DIR="/etc/systemd/system/"
BIN_DIR="/usr/local/bin/"

targets=($(ls ${CONF_DIR}*.json))
for target in "${targets[@]}";
do
    service=${target##*/}
    service=${service%.*}
    systemctl stop $service
    systemctl disable $service
    rm $SYSTEMD_DIR$service.service
done

rm -rf $CONF_DIR
if [ -f ${BIN_DIR}amoeba ]; then
    rm ${BIN_DIR}amoeba
fi
