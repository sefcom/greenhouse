#!/bin/bash

IFS=$'\n'

ORPHANS=`losetup | grep FirmAE | grep deleted | awk '{print $1}'`

for ORPH in $ORPHANS
do
	losetup -d $ORPH
done