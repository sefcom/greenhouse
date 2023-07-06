#!/bin/bash

set -euo

CUR_DIR=$PWD
IMG_DIR=$PWD/tar_files
WORKDIR=$PWD/workdir
SPLOIT_DIR=$(realpath $PWD/routersploit_ghpatched/routersploit_ghpatched)
WORK_LIST=$PWD/data.csv


if [ $# -eq 1 ]; then
	DEBUG=1
else
	DEBUG=0
fi


do_print () {
	MSG=$1
	RED='\033[0;31m'
	NC='\033[0m'
	echo -e "${RED}${MSG}${NC}"
	# echo $MSG
}


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

	do_print "[*] Extracting $IMG_ID"
	tar -xf $IMG_ID 

	cd $ID/$FM_NAME/debug

	do_print "[*] Building docker"
	num=$(grep '1900:1900' docker-compose.yml|wc -l)
	if [ "$num" -eq 2 ]; then
		sed -i '0,/1900:1900/{/1900/d;}' docker-compose.yml
	fi
	# read -p "Waiting: "
	docker compose build 1>/dev/null 2>/dev/null

	do_print "[*] Running docker"
	docker compose up 1>>$ID.out 2>>$ID.out &

	do_print "[*] Sleeping"

	sleep 30s

	cd $SPLOIT_DIR
	CONFIG_FILE=$WORKDIR/$ID/$FM_NAME/config.json
	UNAME=$(grep "$ID" $CUR_DIR/uname.csv | cut -d',' -f2)
	do_print "[*] Verifying credentials : $UNAME"

	echo "AAA: $(python $CUR_DIR/scripts/verify_login.py $UNAME $IP_ADDR)"

	if [ $DEBUG -eq 1 ]; then
		read -p "Stop container ? (Y/N): " CONT
	fi
	do_print "[*] Stopping docker"
	cd $WORKDIR/$ID/$FM_NAME/debug
	docker compose down 2>/dev/null
	docker network prune -f
	docker container prune -f

	cd $CUR_DIR
}

readarray -t my_array < $WORK_LIST
for line in "${my_array[@]}"; do
  do_print "[*] Running $line"
  run_one $line
  do_print "[*] Finished $line"
  if [ $DEBUG -eq 1 ]; then
  	read -p "Continue ? (Y/N)" CONT
  	if [ "$CONT" = "N" ]; then
  	        break
  	fi
  fi
done
