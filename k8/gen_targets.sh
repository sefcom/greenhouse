#!/bin/bash

TARGET_FOLDER=${1}
OUTFILE="targets.list"

echo "Generating $OUTFILE for targets in $TARGET_FOLDER..."
if [[ -f $OUTFILE ]]; then
	echo "    removing old $OUTFILE"
	rm $OUTFILE
fi

touch $OUTFILE

for BRAND in `ls $TARGET_FOLDER`;
do
	echo "    processing $BRAND"
	for TARGET in `ls $TARGET_FOLDER/$BRAND`;
	do
		TARGETPATH=$TARGET_FOLDER/$BRAND/$TARGET
		NAME="${TARGET%.*}"
		echo $BRAND $NAME $TARGETPATH >> $OUTFILE
	done
done
echo $OUTFILE "done"
