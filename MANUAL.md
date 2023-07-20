## REQUIREMENTS:
docker version 24.0.2, build cb74dfc
docker-compose version 1.29.2, build 5becea4c

## GREENHOUSE RUN:
1) Load the provided docker image artifact using:

`docker load -i greenhouse-ae.tar`

2) Once the image is loaded, make sure to start the container in privileged mode with /dev mounted

`docker run -it --privileged -v /dev:/host/dev greenhouse:usenix-eval-jul2023 bash`

3) Setup the runtime environment from the command line inside the container

`/gh/docker_init.sh`

(OPTIONAl) Check all tests pass

`/gh/test.sh`

4) Copy target firmare of interest into the container

`docker cp <image-path> <container-name>:<image-path-in-container>`

5) Inside the docker container, run Greenhouse on the target firmware image 

`/gh/run.sh <brand> <image-path-in-container>`

6) Rehosted image can be found in /gh/results/<sha256hash>

## RUNNING REHOSTED FIRMWARE:
7) Copy the rehosted image to the host machine for inspection

docker cp <container-name>:/gh/results/<sha256hash> <local-path>

8) Enter the debug directory

`cd <local-path>/<sha256hash>/<firmware-name>/debug`

9) Exit and stop the Greenhouse container

10) Build and run the rehosted image inside the exported docker container

`docker-compose build`

`docker-compose up`

11) Wait for a few minutes for the firmware to fully start up

12) Firmware should be accessible on its associated IP found in config.json (default 172.21.0.2:80)

`curl 172.21.0.2:80`

or

Visit that url on Firefox/Chrome, you should see the landing page for the router web server appear.

13) Once done, cleanup

`docker-compose down`

In some cases, previous running containers may share network devices with the current one. Be sure to stop and cleanup old containers and network devices:

`docker container prune`

`docker network prune`

## ROUTERSPLOIT RUN:

1) Setup the docker container as per steps 1-3 in the previous experiment

2) Either copy in an already rehosted image or use the rehosted image from an earlier Greenhouse run

3) Run the routersploit evaluation on a specific rehosted image using the helper script:

`/routersploit/run_routersploit.sh <path-to-rehosted-image-folder>`

4) Wait ~4 hours for all 125 routersploit scripts to be replayed against the target

5) Results should be automatically consolidated inside /routersploit/results/vulnerable.csv


## CRASHING INPUTS:

1) Rehost a firmware image using Greenhouse following steps 1-6 of the first experiment

2) Run the rehosted firmware within the artifact container

`cd  /gh/results/<sha256hash>/<firmware-name>/debug`

`docker-compose build`

`docker-compose up`

3) Wait for a few minutes for the firmware to fully start up

4) In a seperate terminal window, exec into the docker container

`docker exec -it <greenhouse-artifact-container-name> bash`

5) Emit the crashing input (found inside /crashing_inputs)

`cat <path-to-crashing-input-file> | nc -w2 <ip> <port>`

6) Web server segfaults
