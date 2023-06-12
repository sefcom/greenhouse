#!/bin/sh

while (true); do
    # echo "CHECK1" `ps -aux | grep "qemu-system" | grep -v "grep" | grep -sqi "qemu"`
    if ( ! (ps -aux | grep "qemu-system" | grep -v "grep" | grep -sqi "qemu") ); then
        exit 0;
    fi
    sleep 1
done