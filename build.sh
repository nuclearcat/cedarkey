#!/bin/bash
if [ -z "$1" ]; then
echo "Usage: ${0} command"
cat << EOF
    prepare - fetch associated submodules
    build - build firmware and userspace
    flash - install firmware to key over st-link
    blank - erase all data from cedarkey
EOF
fi

if [ "$1" == "prepare" ]; then
git submodule update --init
#cd scrypt
#git checkout 1.2.1
fi

if [ "$1" == "build" ]; then
cd firmware/libopencm3
make
cd ../src
make cedarkey.bin
cd ../../libscrypt
make
cd ../userspace
make
fi

if [ "$1" == "flash" ]; then
cd firmware/src
make cedarkey.stlink-flash
fi

if [ "$1" == "blank" ]; then
st-flash erase
fi
