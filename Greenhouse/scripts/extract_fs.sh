#!/bin/bash

IMG_PATH=${1}
TARGETFS_PATH=${2}
TMPFS_PATH=${3}
TARGET_FOLDER=${4}
USERTAG=`whoami`

sudo guestmount -a "$IMG_PATH" -m "/dev/sda1" --ro "$TARGETFS_PATH"
sleep 2

for FOLDER in `sudo ls "$TMPFS_PATH"`
do
    NEWFOLDER=""
    if [[ $FOLDER = "tmp" ]]; then
        NEWFOLDER="GHTMPSTORE"
    fi
    echo "        - copying " $TMPFS_PATH/$FOLDER " to " $TARGET_FOLDER/$NEWFOLDER
    sudo cp -r "$TMPFS_PATH/$FOLDER" "$TARGET_FOLDER/$NEWFOLDER"
done

sudo chown -R "$USERTAG:$USERTAG" "$TARGET_FOLDER"
sudo chmod -R 777 "$TARGET_FOLDER"
sudo guestunmount "$TARGETFS_PATH"
