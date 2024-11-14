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
You might need to install gcc, make, git, libev-dev, and libmbedtls-dev before the following steps.

A dynamically-linked binary requires libev-dev and libmbedtls-dev to be installed on your target machine(vps). 

To build a statically-linked binary:

    git clone --recurse-submodules https://github.com/sh4run/amoeba.git
    cd amoeba
    make

A statically-linked binary doesn't have such a requirement. To build a statically-linked binary:
    
    make clean
    make DYNAMIC=off

</details>

## Deploy
Generate public/private key with:

    ssh-keygen -b 1024 -m pem -t rsa -f testkey
    ssh-keygen -m pem -e -f testkey >testkey.pub.pem

Server side:

    ./amoeba -c server.json

Client side:

    ./amoeba -c client.json
