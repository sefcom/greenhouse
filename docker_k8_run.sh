#!/bin/bash

DIR_PATH=${1}
LIST_PATH=${2}
JOB_INDEX=${3}
SKIP_FLAG=${4}
RETRY_FLAG=${5}

CONF=`sed "${JOB_INDEX}!d" ${LIST_PATH}`
BRAND=`echo $CONF | awk '{print $1}'`
NAME=`echo $CONF | awk '{print $2}'`
IMG_PATH=${DIR_PATH}/`echo $CONF | awk '{print $3}'`
OUT_PATH=${DIR_PATH}/logs/${JOB_INDEX}
RETRY_PATH=${DIR_PATH}/retries/${JOB_INDEX}
LOCAL_OUT=/logs/${JOB_INDEX}
LOCAL_PATCH=/patches/${JOB_INDEX}
LABEL="${NAME//./_}"
PG_STATUS="/pg_status"
MAX_RETRIES=2

mkdir /${BRAND}

if [[ -f ${OUT_PATH} && SKIP_FLAG == "1" ]]; then
       echo "log already present, skip!"
       exit 0
fi

echo "RUNNING K8POD: " ${POD_NAME} " on > " ${NODE_NAME} > ${LOCAL_OUT} 2>&1
echo $DIR_PATH $LIST_PATH $JOB_INDEX >> ${LOCAL_OUT} 2>&1 
echo $IMG_PATH $BRAND $NAME >> ${LOCAL_OUT} 2>&1 

echo "env check:" >> ${LOCAL_OUT}
LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | awk '{print $1}'`
for LDEV in $LOOPDEVS; do
	echo "Disconnecting stale loopdev" $LDEV >> ${LOCAL_OUT}
	losetup -d $LDEV
done

echo "Network Devices:" >> ${LOCAL_OUT}
echo "--------------------------------------------------------------------" >> ${LOCAL_OUT}
ifconfig >> ${LOCAL_OUT}
echo "--------------------------------------------------------------------" >> ${LOCAL_OUT}

echo "setup FirmAE:" >> ${LOCAL_OUT}
mkdir /work/$JOB_INDEX
mv /work/FirmAE /work/$JOB_INDEX/FirmAE

sed -i "s/#huge_pages = try/huge_pages = off/" /usr/share/postgresql/12/postgresql.conf.sample
sudo pg_dropcluster 12 main
sudo pg_createcluster 12 main
sudo /etc/init.d/postgresql restart
sudo -u postgres bash -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" > /dev/null
sudo -u postgres createdb -O firmadyne firmware > /dev/null
sudo -u postgres psql -d firmware < /work/$JOB_INDEX/FirmAE/database/schema  > /dev/null

sudo service postgresql stop
sudo service postgresql start >>  ${LOCAL_OUT} 2>&1 
sleep 5
sudo service postgresql status > $PG_STATUS 2>&1 
sleep 1

PG_FAILED=`grep ": down" $PG_STATUS`
if [[ $PG_FAILED != "" ]]; then
	echo "pg_ctl failed on " $NODE_NAME
	echo "PG STATUS:"
	cat $PG_STATUS
	sleep 30s
	exit 1
fi

echo "PG STATUS:" $PG_STATUS
echo "PG STATUS:" >> ${LOCAL_OUT}
cat $PG_STATUS >> ${LOCAL_OUT}

echo "copying " ${IMG_PATH} "to" /${BRAND}/${NAME} >> ${LOCAL_OUT} 2>&1 
cp ${IMG_PATH} /${BRAND}/${NAME}
SHA256=`sha256sum /${BRAND}/${NAME} | awk '{print $1}'`
echo ${SHA256} >> ${LOCAL_OUT} 2>&1 

if [ -f "${DIR_PATH}/cache/${SHA256}.tar.gz" ]; then
	echo "Copying cache ${SHA256}.tar.gz"
	echo "Copying cache ${SHA256}.tar.gz" >> ${LOCAL_OUT} 2>&1 
	cp ${DIR_PATH}/cache/${SHA256}.tar.gz /cache/
	tar -xzf /cache/${SHA256}.tar.gz -C /cache/
	rm /cache/${SHA256}.tar.gz
	ls /cache >> ${LOCAL_OUT} 2>&1 
fi

source /root/venv/bin/activate

echo "Running Greenhouse"
echo ${BRAND}/${NAME}
echo ${SHA256}

cd /gh
# HTTP
timeout 72000 python3 /gh/gh.py --outpath /results/${JOB_INDEX} --workspace /tmp/scratch --firmae /work/$JOB_INDEX/FirmAE --logpath=${LOCAL_PATCH} --cache_path=/cache --ip 172.21.0.2 --ports="80,81" --max_cycles=26 -rh --brand=${BRAND} --rehost_type="HTTP" --img_path=/${BRAND}/${NAME} >> ${LOCAL_OUT} 2>&1 

# UPNP
#timeout 129600 python3 /gh/gh.py --outpath /results/${JOB_INDEX} --workspace /tmp/scratch --firmae /work/$JOB_INDEX/FirmAE --logpath=${LOCAL_PATCH} --cache_path=/cache --ip 172.21.0.2 --ports="80,81,1900" --max_cycles=26 -rh --brand=${BRAND} --rehost_type="UPNP" --img_path=/${BRAND}/${NAME} >> ${LOCAL_OUT} 2>&1 

# DNS
#timeout 129600 python3 /gh/gh.py --outpath /results/${JOB_INDEX} --workspace /tmp/scratch --firmae /work/$JOB_INDEX/FirmAE --logpath=${LOCAL_PATCH} --cache_path=/cache --ip 172.21.0.2 --ports="80,53" --max_cycles=26 -rh --brand=${BRAND} --rehost_type="DNS" --img_path=/${BRAND}/${NAME} >> ${LOCAL_OUT} 2>&1 

RET_CODE=`echo $?`
tail ${LOCAL_OUT}

cd /work/$JOB_INDEX/FirmAE/
sudo timeout 600 /work/$JOB_INDEX/FirmAE/scripts/delete.sh 1

for i in `ls /work/$JOB_INDEX/FirmAE/scratch`; do
	echo "...deleting $i"
	sudo /work/$JOB_INDEX/FirmAE/scripts/delete.sh $i
done

LOOPDEVS=`losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}'`
for LDEV in $LOOPDEVS; do
	echo "Disconnecting " $LDEV
	echo "    - Disconnecting /dev/"$LDEV  >> ${LOCAL_OUT} 2>&1 
	losetup -d /dev/$LDEV
	dmsetup remove ${LDEV}p1
done

timeout 600 ifconfig -a | sed 's/[ :\t].*//;/^$/d' | grep tap | xargs -L 1 -I{} ifconfig {} down

if [[ $RET_CODE == 124 ]]; then
	echo "! REHOST TIMEDOUT !" 
	echo "! REHOST TIMEDOUT !" >> ${LOCAL_OUT}
fi

cp ${LOCAL_PATCH} ${DIR_PATH}/patches/${JOB_INDEX}

if [ -d "/results/${JOB_INDEX}" ]; then
	cd /results/
	mv /results/${JOB_INDEX} /results/${SHA256}
	tar -czf ${JOB_INDEX}_${SHA256}.tar.gz ${SHA256}
	cp /results/${JOB_INDEX}_${SHA256}.tar.gz ${DIR_PATH}/results/
	cd /
fi

CACHEPATH=`ls /cache`
echo $CACHEPATH
HASCACHE=`ls /cache/$CACHEPATH/GH_SUCCESSFUL_CACHE`
if [[ $HASCACHE != "" ]]; then
	echo "Good rehost, creating cache: " ${SHA256}.tar.gz >> ${LOCAL_OUT}
	if [[ ! -f ${DIR_PATH}/cache/${SHA256}.tar.gz ]]; then
		cd /cache
		tar -czf ${SHA256}.tar.gz $CACHEPATH
		cp ${SHA256}.tar.gz ${DIR_PATH}/cache/
	else
		echo "    - cache already present, skip!" >> ${LOCAL_OUT}
	fi
else
	echo  "No cache created" >> ${LOCAL_OUT}
fi

# keep log	
echo "GHREHOST COMPLETE: " $RET_CODE >> ${LOCAL_OUT}
cp ${LOCAL_OUT} ${OUT_PATH}


sudo service postgresql stop
echo ${JOB_INDEX} > ${DIR_PATH}/done/${SHA256}
echo "GHREHOST COMPLETE: " $RET_CODE
echo "RETRY_FLAG: " $RETRY_FLAG

if [[ $RETRY_FLAG == "1" ]]; then
	if [[ $RET_CODE -ne 0 ]]; then
		if [[ ! -f $RETRY_PATH ]]; then
			echo 1 > $RETRY_PATH
		fi
		COUNT=`cat $RETRY_PATH`
		if [[ COUNT -lt $MAX_RETRIES ]]; then
			echo "Attempting a retry!"
			echo $(($COUNT+1)) > $RETRY_PATH
			exit 42
		fi
		echo "No retries left"
	fi
fi

echo "CONTAINER EXIT"
exit 0
