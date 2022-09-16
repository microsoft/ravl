#!/bin/bash

# Requires emscripten in the path
source "~/emsdk/emsdk_env.sh"

git clone git://git.openssl.org/openssl.git --depth 1 --branch OpenSSL_1_1_1-stable
cd openssl
emconfigure ./Configure -no-asm -no-ssl3 -no-comp -no-engine -no-deprecated -shared -no-dso --openssldir=built linux-generic32 no-ssl2 no-hw
sed -i "s/^CROSS_COMPILE=.*$/CROSS_COMPILE=/" Makefile
emmake make build_generated libssl.a libcrypto.a
