#!/bin/bash

echo "Testing docker"

DOCKER_TEST=`docker image list`
if [[ $DOCKER_TEST != *ubuntu* ]]; then
	echo "docker is not running or loaded correctly"
	echo $DOCKER_TEST
	exit 1
fi

echo "Testing psql"
PSQL_STATUS=`sudo service postgresql status`
if [[ $PSQL_STATUS != *online* ]]; then
	echo "psql is not running or loaded correctly"
	echo $PSQL_STATUS
	exit 1
fi

echo "Testing binwalk"
BINWALK_STATUS=`binwalk 2>&1`
if [[ $BINWALK_STATUS != *"Binwalk v2.3.3"* ]]; then
	echo "binwalk is not installed correct, or the wrong version of binwalk is installed"
	echo $BINWALK_STATUS
	exit 1
fi


echo "Testing losetup"
losetup -Pf /testimage.raw
TESTLOOP=`losetup | grep testimage.raw | awk '{print $1}'`
LOSETUP_STATUS=`ls /host${TESTLOOP}p1`
losetup -d $TESTLOOP
if [[ $LOSETUP_STATUS != *"/host/dev"* ]]; then
	echo "losetup is unable to setup loop devices properly"
	echo $TESTLOOP
	echo $LOSETUP_STATUS
	exit 1
fi

echo "All tests passed!"
exit 0
