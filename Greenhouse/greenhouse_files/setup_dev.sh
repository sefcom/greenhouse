#!/bin/sh

BUSYBOX=${1}
DEV=${2}

${BUSYBOX} echo "    - settng up dev nodes in " $DEV
${BUSYBOX} chmod -R 777 "$DEV"

# taken from FirmAE fixImage.sh
${BUSYBOX} mknod -m 660 $DEV/mem c 1 1 &> /dev/null
${BUSYBOX} mknod -m 640 $DEV/kmem c 1 2 &> /dev/null
#${BUSYBOX} mknod -m 666 $DEV/null c 1 3 &> /dev/null
${BUSYBOX} mknod -m 666 $DEV/zero c 1 5 &> /dev/null
#${BUSYBOX} mknod -m 444 $DEV/random c 1 8 &> /dev/null
#${BUSYBOX} mknod -m 444 $DEV/urandom c 1 9 &> /dev/null
${BUSYBOX} mknod -m 666 $DEV/armem c 1 13 &> /dev/null

${BUSYBOX} mknod -m 666 $DEV/tty c 5 0 &> /dev/null
${BUSYBOX} mknod -m 622 $DEV/console c 5 1 &> /dev/null
${BUSYBOX} mknod -m 666 $DEV/ptmx c 5 2 &> /dev/null

${BUSYBOX} mknod -m 622 $DEV/tty0 c 4 0 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/ttyS0 c 4 64 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/ttyS1 c 4 65 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/ttyS2 c 4 66 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/ttyS3 c 4 67 &> /dev/null

${BUSYBOX} mknod -m 644 $DEV/adsl0 c 100 0 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/ppp c 108 0 &> /dev/null
${BUSYBOX} mknod -m 666 $DEV/hidraw0 c 251 0 &> /dev/null

${BUSYBOX} mkdir -p $DEV/mtd &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/0 c 90 0 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/1 c 90 2 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/2 c 90 4 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/3 c 90 6 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/4 c 90 8 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/5 c 90 10 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/6 c 90 12 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/7 c 90 14 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/8 c 90 16 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/9 c 90 18 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/10 c 90 20 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/11 c 90 22 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/12 c 90 24 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/13 c 90 26 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/14 c 90 28 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/15 c 90 30 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd/16 c 90 32 &> /dev/null

${BUSYBOX} mknod -m 644 $DEV/mtd0 c 90 0 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr0 c 90 1 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd1 c 90 2 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr1 c 90 3 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd2 c 90 4 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr2 c 90 5 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd3 c 90 6 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr3 c 90 7 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd4 c 90 8 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr4 c 90 9 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd5 c 90 10 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr5 c 90 11 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd6 c 90 12 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr6 c 90 13 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd7 c 90 14 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr7 c 90 15 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd8 c 90 16 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr8 c 90 17 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd9 c 90 18 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr9 c 90 19 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtd10 c 90 20 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr10 c 90 21 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr11 c 90 22 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr12 c 90 23 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr13 c 90 24 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr14 c 90 25 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr15 c 90 26 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdr16 c 90 27 &> /dev/null

${BUSYBOX} mkdir -p $DEV/mtdblock &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/0 b 31 0 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/1 b 31 1 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/2 b 31 2 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/3 b 31 3 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/4 b 31 4 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/5 b 31 5 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/6 b 31 6 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/7 b 31 7 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/8 b 31 8 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/9 b 31 9 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/10 b 31 10 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/11 b 31 11 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/12 b 31 12 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/13 b 31 13 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/14 b 31 14 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/15 b 31 15 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock/16 b 31 16 &> /dev/null

${BUSYBOX} mknod -m 644 $DEV/mtdblock0 b 31 0 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock1 b 31 1 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock2 b 31 2 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock3 b 31 3 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock4 b 31 4 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock5 b 31 5 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock6 b 31 6 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock7 b 31 7 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock8 b 31 8 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock9 b 31 9 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock10 b 31 10 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock11 b 31 11 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock12 b 31 12 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock13 b 31 13 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock14 b 31 14 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock15 b 31 15 &> /dev/null
${BUSYBOX} mknod -m 644 $DEV/mtdblock16 b 31 16 &> /dev/null

${BUSYBOX} mkdir -p $DEV/tts &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/tts/0 c 4 64 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/tts/1 c 4 65 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/tts/2 c 4 66 &> /dev/null
${BUSYBOX} mknod -m 660 $DEV/tts/3 c 4 67 &> /dev/null
