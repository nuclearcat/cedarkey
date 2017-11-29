#!/bin/bash
if [ -z "$1" ]; then
echo "Usage: ${0} command"
cat << EOF
    prepare - fetch associated submodules
    build - build firmware and userspace
    flash - install firmware to key over st-link
EOF
fi

if [ "$1" == "prepare" ]; then
git submodule update --init
fi

if [ "$1" == "build" ]; then
cd firmware/libopencm3
make
cd ../src
make cedarkey.bin
cd ../../userspace
cd userspace
make
fi

if [ "$1" == "flash" ]; then
cd firmware/src
make cedarkey.stlink-flash
fi
