#!/bin/bash

INIT=/routersploit/routersploit_gh/Initializer.py
SPLOIT=/routersploit/routersploit_gh/rsf.py
EXPLOIT_FILE=/routersploit/exploits.list
TARGETPATH=${1}
OUTPATH=/routersploit/results

if [ ! -f "$EXPLOIT_FILE" ]; then
	echo "[ERROR] -- $EXPLOIT_FILE does not exist\n"
	exit 0
fi

echo "Using image : $TARGETPATH"
echo "    - OUTPATH: " $OUTPATH
echo "    - TARGETPATH: " $TARGETPATH

if [ ! -e "$TARGETPATH" ]; then
	echo "[ERROR] -- $TARGETPATH not found"
	exit 0
fi

TAG=`basename $TARGETPATH | tr "."  " " | awk '{print $1}'`
mkdir $OUTPATH
STDOUT_FILE=/routersploit/results/$TAG.stdout
touch $STDOUT_FILE

cd /

mkdir /firmware
cp -r $TARGETPATH /firmware

HASHNAME=`ls /firmware/`
FIRMWARE=`ls /firmware/$HASHNAME`
ROOT=/firmware/$HASHNAME/$FIRMWARE/debug

JSON_FILE=/firmware/$HASHNAME/$FIRMWARE/config.json
echo "using configs" $JSON_FILE

if [[ ! -f $JSON_FILE ]]; then
	echo "[ERROR] -- config.json does not exist" >> $STDOUT_FILE
	echo "[ERROR] -- config.json does not exist"
	# mv $STDOUT_FILE $OUTDIR
	exit 0
fi

# copy etc/passwd file
echo "Setting up GH_PATH_TRAVERSAL file"
GHPASSWD=/routersploit/GH_PATH_TRAVERSAL
FSPATH=/$ROOT/fs
cp $GHPASSWD $FSPATH/

 if [[ -L $FSPATH"/etc/passwd" ]]; then
 	if [[ ! -f $FSPATH"/etc/passwd" ]]; then
 		echo "    - overwriting broken symlink"
 		rm -f $FSPATH/etc/passwd
 		cp $GHPASSWD $FSPATH/etc/passwd
 	fi
 elif [[ ! -f $FSPATH"/etc/passwd" ]]; then
 	echo "    - missing" $FSPATH/etc/passwd
 	echo "    - copying passwd"
 	ETCPATH=$FSPATH/etc
 	if [[ -L $ETCPATH ]]; then
 		RELPATH=`readlink $ETCPATH`
 		ETCPATH=$FSPATH/$RELPATH
 	fi
 	if [[ ! -d $ETCPATH ]]; then
 		mkdir -p $ETCPATH
 	fi
 	if [[ -f $ETCPATH/passwd ]]; then
 		rm -f $ETCPATH/passwd
 	fi
 	cp $GHPASSWD $ETCPATH/passwd
 fi
 
# setup docker
docker load -i /ubuntu.tar

echo "Getting arguments"
HASH=$(cat $JSON_FILE | jq ".hash" | tr -d '"')
BRAND=$(cat $JSON_FILE | jq ".brand" | tr -d '"')
REHOSTED=$(cat $JSON_FILE | jq ".result" | tr -d '"')
JSON_IP=$(cat $JSON_FILE | jq ".targetip" | tr -d '"')
JSON_PORT=$(cat $JSON_FILE | jq ".targetport" | tr -d '"')
JSON_USERNAME=$(cat $JSON_FILE | jq ".loginuser" | tr -d '"')
JSON_PASSWORD=$(cat $JSON_FILE | jq ".loginpassword" | tr -d '"')

if [[ $REHOSTED != "SUCCESS" ]]; then
	echo "TARGET NOT A SUCCESSFUL REHOST, TRYING ANYWAY..." >> $STDOUT_FILE
	echo "TARGET NOT A SUCCESSFUL REHOST, TRYING ANYWAY..."
	# mv $STDOUT_FILE $OUTDIR/
	# exit 0
fi

echo "Build docker"
if [ ! -f /$ROOT/docker-compose.yml ]; then
	echo "[ERROR] -- docker-compose.yml does not exist" >> $STDOUT_FILE
	mv $STDOUT_FILE $OUTPATH/
	exit 0
fi

# remove apt-get from debug runs
sed -i '2d' /$ROOT/Dockerfile

cd /$ROOT/
docker-compose build


# default backups
if [[ $JSON_IP == "" ]]; then
JSON_IP=172.18.0.2
fi

if [[ $JSON_PORT == "" ]]; then
JSON_PORT=80
fi

echo "Target: " /firmware/$HASHNAME/$FIRMWARE  1>>$STDOUT_FILE 2>>$STDOUT_FILE 
echo "Target: " /firmware/$HASHNAME/$FIRMWARE
echo "Running image" 1>>$STDOUT_FILE
echo "    - specs: " $JSON_IP $JSON_PORT $JSON_USERNAME $JSON_PASSWORD 1>>$STDOUT_FILE
echo "Running image"
echo "    - specs: " $JSON_IP $JSON_PORT $JSON_USERNAME $JSON_PASSWORD

TOTAL_EXPLOITS=`cat $EXPLOIT_FILE | wc -l`
for (( i=1; i<=$TOTAL_EXPLOITS; i++)); do
	EXPLOIT=$(sed "${i}q;d" $EXPLOIT_FILE)
	echo "============================================="
	echo "Testing exploit" $EXPLOIT >>$STDOUT_FILE
	echo "Testing exploit" $EXPLOIT
	cd /$ROOT/
	echo "----------------------------------------------------" >> /docker_logs
	docker-compose up 2>&1 >> /docker_logs &

	CONTAINERNAME=`docker container list | grep "gh_rehosted" | awk '{print $1}'`
	echo "Created container" $CONTAINERNAME
	sleep 60s
	
	set +e
	
	curl --connect-timeout 60 $JSON_IP:$JSON_PORT > /curlresult
	echo "<------------>"
	head /curlresult
	echo "<------------>"
	
	echo "<------------>"  >>$STDOUT_FILE
	head /curlresult  >>$STDOUT_FILE
	echo "<------------>" >>$STDOUT_FILE

	echo "Running initializer on" $BRAND $JSON_IP $JSON_PORT
	echo "Running initializer on" $BRAND $JSON_IP >>$STDOUT_FILE
	cd /
	timeout 600 $INIT -m "FULL_RUN" -b $BRAND -t $JSON_IP -p $JSON_PORT -u "$JSON_USERNAME" -w "$JSON_PASSWORD"
	sleep 1s
	set -e
	echo "--------------------------------------------" >> $STDOUT_FILE

	echo "Running routersploit with ip " $JSON_IP " port " $JSON_PORT  " user " $JSON_USERNAME  " passwd " $JSON_PASSWORD
	echo "Running routersploit with ip " $JSON_IP " port " $JSON_PORT  " user " $JSON_USERNAME  " passwd " $JSON_PASSWORD >>$STDOUT_FILE
	export PATH=$PATH:/routersploit/
	for repeats in {1..1}; do
		$SPLOIT -a -f $EXPLOIT -t $JSON_IP -p $JSON_PORT -u "$JSON_USERNAME" -w "$JSON_PASSWORD" > /RSFOUT
		cat /RSFOUT >> $STDOUT_FILE
		echo "-------------------------------" >> $STDOUT_FILE
		sleep 1s
	done
	cat /RSFOUT
	sleep 5s
	echo "-------------------------------"

	echo "Listing firmware root"
	echo "Listing firmware root" >> $STDOUT_FILE
	docker container list >>$STDOUT_FILE
	CONTAINERNAME=`docker container list | grep "gh_rehosted" | awk '{print $1}'`
	if [[ $CONTAINERNAME != "" ]]; then
		set +e
		docker exec $CONTAINERNAME sync
		sleep 10s
		FWFILES=`docker exec $CONTAINERNAME ls /fs` 
		echo $FWFILES
		echo "-------------------------------" >> $STDOUT_FILE
		for FILENAME in $FWFILES; do
			#if [[ $FILENAME == "GHRCE*" ]]; then
			echo $FILENAME >> $STDOUT_FILE
			#fi
		done
		set -e
	fi
	#echo "-------------------------------" >> $STDOUT_FILE
	# cat /docker_logs >> $STDOUT_FILE
	echo "done"
	#echo "-------------------------------" >> $STDOUT_FILE

	cd /$ROOT/
	docker-compose down
	sleep 1s
done
echo "============================================="
echo "=============================================" >> $STDOUT_FILE

echo "Parsing results"
echo "============================================="
mkdir /$OUTPATH/logs

mv $STDOUT_FILE /$OUTPATH/logs

cd /routersploit/routersploit_gh/routersploit-log-parser

python3 parse-routersploit-logs.py -ld /$OUTPATH/logs
cp /$OUTPATH/logs/processed_data/vulnerable.csv /$OUTPATH/

echo "Summarized results at: " /$OUTPATH/vulnerable.csv

cd /
echo "Run Complete"

exit 0
