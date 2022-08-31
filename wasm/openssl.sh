#!/bin/bash

source "/data/cwinter/emsdk/emsdk_env.sh"

git clone git://git.openssl.org/openssl.git --depth 1 --branch OpenSSL_1_1_1-stable
cd openssl
emcmake ./Configure -no-asm -no-ssl3 -no-comp -no-engine -no-deprecated -shared -no-dso --openssldir=built linux-generic32 no-ssl2 no-hw 
# -no-apps
emmake make
