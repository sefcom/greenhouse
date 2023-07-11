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

## Running

Refer to MINIKUBE.md for instructions on setting up minikube to batch run Greenhouse

Otherwise, refer to MANUAL.md for instructions on running Greenhouse manually
