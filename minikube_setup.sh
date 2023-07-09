#!/bin/bash

minikube start

minikube image load usenix-eval-jul2023

minikube mount k8:/shared

# minikube delete --all
