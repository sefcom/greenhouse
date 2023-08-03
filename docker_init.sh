#!/bin/bash

if [[ -z $TERM ]]; then
	export TERM=xterm
fi

mkdir /tmp/docker
mount -t tmpfs -o rw,size=12G tmpfs /tmp/docker

# cgroup v2: enable nesting
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
	# move the processes from the root group to the /init group,
	# otherwise writing subtree_control fails with EBUSY.
	# An error during moving non-existent process (i.e., "cat") is ignored.
	mkdir -p /sys/fs/cgroup/init
	xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
	# enable controllers
	sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
		> /sys/fs/cgroup/cgroup.subtree_control
fi

dockerd --data-root /tmp/docker &

sleep 1
docker load -i /ubuntu.tar


mkdir /results
mkdir /logs
mkdir /patches
mkdir /cache

if [[ ! -e /host/dev ]]; then
 	ln -s /dev /host/dev
fi

PG_STATUS=/tmp/PG_STATUS_LOG
sed -i "s/#huge_pages = try/huge_pages = off/" /usr/share/postgresql/12/postgresql.conf.sample
sudo pg_dropcluster 12 main
sudo pg_createcluster 12 main
sudo /etc/init.d/postgresql restart
sudo -u postgres bash -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" > /dev/null
sudo -u postgres createdb -O firmadyne firmware > /dev/null
sudo -u postgres psql -d firmware < /work/FirmAE/database/schema  > /dev/null

sudo service postgresql stop
sudo service postgresql start
sleep 5
sudo service postgresql status > $PG_STATUS 2>&1 
sleep 1

PG_FAILED=`grep ": down" $PG_STATUS`
if [[ $PG_FAILED != "" ]]; then
	echo "pg_ctl failed!"
	echo "PG STATUS:"
	cat $PG_STATUS
	exit 1
fi

echo "PG STATUS:" $PG_STATUS
cat $PG_STATUS
echo "--------------------------------------------------------------------" 
