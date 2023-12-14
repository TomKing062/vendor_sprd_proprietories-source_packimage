#!/bin/bash

AVB_TOOL=../../../../../../../external/avb/avbtool

if [ $# -ne 1 ]; then
    echo "Usage: genkey.sh <partion_name>:boot/recovery/system/vendor/..."
    exit 1
fi

if [ ! -f "$AVB_TOOL" ]; then
    echo "avbtool not found! please check!"
    exit
fi

partition=$1
privatekey=rsa4096_"$partition".pem
publickey=rsa4096_"$partition"_pub.bin

openssl genrsa -out $privatekey 4096
$AVB_TOOL extract_public_key --key $privatekey --output $publickey
