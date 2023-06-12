#!/bin/bash

CHROMEVERSION=`/usr/bin/google-chrome --version | tr "." " " | awk '{print $3}'`; DRIVERVERSION=`curl https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROMEVERSION`; wget https://chromedriver.storage.googleapis.com/$DRIVERVERSION/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
