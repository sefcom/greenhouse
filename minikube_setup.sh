#!/bin/bash

# minikube start --driver=docker --memory 8192 --cpus 4 # --memory 81920 --cpus 10

function cleanup()
{
	minikube delete --all
	while true; do
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
minikube mount /dev:/host/dev --uid root --gid disk &

./docker_cleanup.sh &
sudo ./dev_cleanup.sh
