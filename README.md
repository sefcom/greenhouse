# Greenhouse
Automated Single-Service Rehosting of Firmware in User-Space

# Installation Requirements
- Tested on: Ubuntu 20.04
Please refer to the READMEs inside each component for the individual installation packages

# Component Overview
## Greenhouse
`Greenhouse` is the primary codebase for the Greenhouse implementation in Python.
It handles the bulk of the automated rehosting process and contains all the relevant Python source-code

## FirmAEReplacements
Modified scripts to update FirmAE to work with our platform and on kubernetes

## dockerization
Dockerfile, scripts and associated folders for building Greenhouse for standalone use

Use `make release` to build the standalone artifact used in our evaluation

## routersploit_ghpatched
Modified version of routersploit (https://github.com/threat9/routersploit) framework used to replay commonly known router exploits on rehosted Greenhouse firmware images 

## gh3fuzz
Fuzzing component for use with rehosted Greenhouse images via AFL++

## gh-qemu5
Source code for Greenhouse's QEMU user implementation (a number of interventions were implemented on the QEMU level instead)

# Running

Refer to MINIKUBE.md for instructions on setting up minikube to batch run Greenhouse. Note that minikube has been observed to have performance issues compared to running in a full kubernetes cluster - some samples may not rehost correctly inside a minikube setup.

Otherwise, refer to MANUAL.md for instructions on running Greenhouse manually

## Known Issues

### "no disk space" message seen in logs

If rehosting is failing due to lack of disk space, please assign more disk space to the minikube instance (~16gb per pod) and run fewer parallel pods. You may also need to check if the docker prune script to periodically clean up docker containers on the minikube instance is working.

`minikube ssh`
`docker container list -a`

If the containers are not being pruned, run a periodic pruning script inside the minikube ssh terminal:

`while true; do docker container prune --force; sleep 60; done;`

### "Out of Memory" errors

Assign more RAM per pod inside `gh_job.yml`. We also recommend minimizing the number of parallelisms if running in minikube.
