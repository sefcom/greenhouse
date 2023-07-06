#!/bin/bash

set -euo

CUR_DIR=$PWD
IMG_DIR=$PWD/tar_files
WORKDIR=$PWD/workdir
SPLOIT_DIR=$(realpath $PWD/../routersploit_ghpatched/routersploit_ghpatched)
WORK_LIST=$PWD/data.csv


run_one () {
	LINE=$1
	IFS=',' read ID BRAND FM_NAME IP_ADDR EXPLOIT <<< "$LINE"
	IMG_ID=$ID.tar.gz
	if [ ! -f $IMG_DIR/$IMG_ID ]; then
		echo "$IMG_DIR/$IMG_ID does not exist"
		exit 1
	fi

	rm -rf $WORKDIR/*

	cp $IMG_DIR/$IMG_ID $WORKDIR

	cd $WORKDIR

	echo "[*] Extracting $IMG_ID"
	tar -xf $IMG_ID 

	cd $ID/$FM_NAME

	echo "[*] Building docker"
	docker-compose build

	echo "[*] Running docker"
	docker-compose up 1>>$ID.out 2>>$ID.out &

	echo "Sleeping"

	sleep 30s

	cd $SPLOIT_DIR
	CONFIG_FILE=$WORKDIR/$ID/$FM_NAME/config.json
	echo "[*] Running Initializer"
	./Initializer.py -m FULL_RUN -b $BRAND -c $CONFIG_FILE

	PORT=$(cat $CONFIG_FILE |jq .port | tr -d '"')
	UNAME=$(cat $CONFIG_FILE | jq .user)
	PASSWD=$(cat $CONFIG_FILE | jq .password)

	echo "[*] Running routersploit"
	$SPLOIT_DIR/rsf.py -a -f $EXPLOIT -t $IP_ADDR -p $PORT -u $UNAME -w $PASSWD

	cd $WORKDIR/$ID/$FM_NAME
	read -p "Stop container ? (Y/N): " CONT
	echo "[*] Stopping docker"
	docker-compose down
	docker network prune -f
	docker container prune -f

	cd $CUR_DIR
}

readarray -t my_array < $WORK_LIST
for line in "${my_array[@]}"; do
  # echo "Running $line"
  run_one $line
  echo "[*] Finished $line"
  read -p "Continue ? (Y/N)" CONT
  if [ "$CONT" = "N" ]; then
	  break
  fi
done
