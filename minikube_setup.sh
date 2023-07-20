#!/bin/bash

# minikube start --driver=kvm2 --memory 8192 --cpus 2

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

mkdir -p k8/logs
mkdir -p k8/results
mkdir -p k8/patches
mkdir -p k8/done
mkdir -p k8/retries

# eval $(minikube docker-env) && make release

eval $(minikube docker-env) && docker pull capysix/greenhouse-ae:latest && docker tag capysix/greenhouse-ae:latest greenhouse:usenix-eval-jul2023

echo "getting sudo for dev_cleanup"
sudo echo "...done"

minikube mount k8:/shared &

./docker_cleanup.sh &
sudo ./dev_cleanup.sh
