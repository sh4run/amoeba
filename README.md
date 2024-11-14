# amoeba
A proxy derived from SSS(scrambled shadowsocks) with a brand new architecture and a enhanced protocol.

Features include:
1. Multiple threads.
2. Message driven.
3. Optimized for HTTPS traffic.
3. Easy configuration. No domain name, certificate or web server is needed.
4. Support of multiple users.

## Build

<details>
    <summary>Click for details</summary>

####
You might need to install gcc, make, git, libev-dev, and libmbedtls-dev before any following steps.

    sudo apt install gcc make git libev-dev libmbedtls-dev

A dynamically-linked binary requires libev-dev and libmbedtls-dev to be installed on your target machine(vps). 

To build a dynamically-linked binary:

    git clone --recurse-submodules https://github.com/sh4run/amoeba.git
    cd amoeba
    make

A statically-linked binary doesn't have such a requirement. To build a statically-linked binary:
    
    make clean
    make DYNAMIC=off

</details>

## Deploy

### Manual Steps

<details>
    <summary>Click for details</summary>

####  
Generate public/private key with:

    ssh-keygen -b 1024 -m pem -t rsa -f testkey -N "" -q
    ssh-keygen -m pem -e -f testkey >testkey.pub.pem

Server side:

    ./amoeba -c server.json

Client side:

    ./amoeba -c client.json

Please change the config files to suit your own needs.

</details>

### Scripts

<details>
    <summary>Click for details</summary>

####
After a successful build, you can install amoeba server as a service at your build machine. 

    sudo ./install-amoeba-server.sh <port-number>

If your amoeba server is not running on your build machine, please copy the following files to your target VPS before running the above script. It is better to have your target VPS and build machine run the same version of Linux to avoid a possible libc mismatch. 

    client.json
    server.json
    amoeba
    install-amoeba-server.sh

The install script generates a tarball after it installs amoeba server. Please copy the following files to your local machine:

    amoeba-client.tar.gz
    install-amoeba-client.sh

And install amoeba client with:

    sudo ./install-amoeba-client.sh 

To uninstall amoeba server or client:

    sudo ./uninstall-amoeba.sh

</details>
