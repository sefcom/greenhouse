#!/bin/bash

# minikube start --driver=docker --memory 8192 --cpus 4 # --memory 81920 --cpus 10

function cleanup()
{
	minikube delete --all
	LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | tr "/" " " | awk '{print $2}'`
	for LDEV in $LOOPDEVS; do
		echo "losetup -d " $LDEV
		sudo losetup -d /dev/$LDEV
	done
	LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | tr "/" " " | awk '{print $2}'`
	for LDEV in $LOOPDEVS; do
		echo "dmsetup remove " ${LDEV}p1
		sudo dmsetup remove ${LDEV}p1
	done
}

trap cleanup SIGINT

eval $(minikube docker-env) && make release

minikube mount k8:/shared &
minikube mount /dev:/host/dev --uid root --gid disk
