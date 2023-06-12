#!/bin/bash

set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: umount.sh <image ID>"
    exit 1
fi
IID=${1}

if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

echo "----Running----"
WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
IMAGE_DIR=`get_fs_mount ${IID}`

DEVICE=`get_dev_of_image ${IMAGE}`
# get_dev_of_image ${IMAGE}
echo "WORK_DIR "${WORK_DIR}
echo "IMAGE "${IMAGE}
echo "IMAGE_DIR "${IMAGE_DIR}
echo "Device "${DEVICE}

echo "----Unmounting----"
umount "${IMAGE_DIR}"

echo "----Disconnecting Device File----"
for DEV in ${DEVICE}
do
    losetup -d "${DEV}" &>/dev/null
done
kpartx -d "${IMAGE}"
dmsetup remove $(basename "${DEVICE}") &>/dev/null
