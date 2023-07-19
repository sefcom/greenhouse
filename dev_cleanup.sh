#!/bin/bash

while true; do
	LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}'`
	for LDEV in $LOOPDEVS; do
		echo "losetup -d " $LDEV
		sudo losetup -d /dev/$LDEV
	done
	LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}'`
	for LDEV in $LOOPDEVS; do
		echo "dmsetup remove " ${LDEV}p1
		sudo dmsetup remove ${LDEV}p1
	done
	sleep 60
done
