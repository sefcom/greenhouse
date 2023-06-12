#!/greenhouse/busybox/sh

FS_PATH=${1}
LINK_PATH=${2}
TARGET_PATH=${3}

sudo chroot $1 /greenhouse/busybox ln -s $3 $2