#!/bin/bash

while true; do
	eval $(minikube docker-env) && docker container prune --force
	sleep 3600
done
