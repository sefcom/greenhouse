#!/bin/bash

DIR_PATH=${1}
LIST_PATH=${2}
JOB_INDEX=$(($3+1))
SKIP_FLAG=0
RETRY_FLAG=1

/gh/docker_init.sh
/gh/docker_k8_run.sh ${DIR_PATH} ${LIST_PATH} ${JOB_INDEX} ${SKIP_FLAG} ${RETRY_FLAG}
