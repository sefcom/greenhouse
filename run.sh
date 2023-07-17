#!/bin/bash

BRAND=${1}
IMG_PATH=${2}

/gh/test.sh
if [[ $? != 0 ]]; then
	echo "Greenhouse docker container not setup properly, exiting!"
	exit 1
fi

if [[ $BRAND == "" || $IMG_PATH == "" ]]; then
	echo "Usage: run_gh.sh <brand> <imgpath>"
	exit 1
fi

if [[ ! -e $IMG_PATH ]]; then
	echo "Missing image at path " $IMG_PATH
	exit 1
fi

echo "--------------------------------------------------------------------" 
echo "env check:"
LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | awk '{print $1}'`
for LDEV in $LOOPDEVS; do
	echo "Disconnecting stale loopdev" $LDEV
	losetup -d $LDEV
done
echo "--------------------------------------------------------------------" 

SHA256=`sha256sum /${IMG_PATH} | awk '{print $1}'`
echo "sha256sum: " ${SHA256}
echo "--------------------------------------------------------------------" 

source /root/venv/bin/activate
mkdir -p /gh/results

echo "Running Greenhouse"
echo ${BRAND} ${IMG_PATH}
echo "--------------------------------------------------------------------" 

cd /gh
# HTTP
timeout 86400 python3 /gh/gh.py --outpath /gh/results/${SHA256} --workspace /tmp/scratch --firmae /work/FirmAE --logpath=/patches/${SHA256}.log --cache_path=/cache --ip 172.21.0.2 --ports="80,81" --max_cycles=26 -rh --brand=${BRAND} --rehost_type="HTTP" --img_path=/${IMG_PATH} | tee -a /tmp/gh.log
RET_CODE=`echo $?`

echo "--------------------------------------------------------------------" 
echo "...cleaning up"
echo "--------------------------------------------------------------------" 

cd /work/$JOB_INDEX/FirmAE/
sudo timeout 600 /work/$JOB_INDEX/FirmAE/scripts/delete.sh 1

for i in `ls /work/$JOB_INDEX/FirmAE/scratch`; do
	echo "...deleting $i"
	sudo /work/$JOB_INDEX/FirmAE/scripts/delete.sh $i
done

LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}'`
for LDEV in $LOOPDEVS; do
	echo "Disconnecting " $LDEV
	losetup -d /dev/$LDEV
done

LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}'`
for LDEV in $LOOPDEVS; do
	echo "dmsetup removing " ${LDEV}p1
	dmsetup remove ${LDEV}p1
done

echo "--------------------------------------------------------------------" 
echo "GHREHOST COMPLETE: " $RET_CODE
echo "--------------------------------------------------------------------" 

