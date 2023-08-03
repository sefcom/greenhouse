1) Install `minikube` as per https://minikube.sigs.k8s.io/docs/start and `kvm2` as per https://minikube.sigs.k8s.io/docs/drivers/kvm2/

Make sure you have kubectl installed (as per https://kubernetes.io/docs/reference/kubectl/), or use the built-in `minikube kubectl`

2) run minikube. We recommend ensuring you have ~8gb of memory, 16gb of disk space and 1 cpus per Greenhouse pod intended to run.

`minikube start --memory 32768 --cpus 4 --driver=kvm2 --disk-size 64G`

3) setup the minikube environment

`./minikube_setup.sh`

this builds the Greenhouse image directly inside the minikube environment and mounts the k8 directory which will contain our samples and results. Building might take a while (~30mins). Keep this process alive until you are done - ctr+c to exit will automatically clean up the rest of the environment.

You may also build the image locally, then pull/transfer the image into the minikube environment instead. Note that if you do this, you will still need to mount the k8 and dev directories as per the `minikube_setup.sh` script.

4) setup your targets. This is done by copying targets of interest into the `samplesfull` folder inside the `k8` folder and generating a corresponding `targets.list` file. Targets should be placed in `samplesfull` in the form `samplesfull/<BRAND>/<TARGETFILE>` for example, `samplesfull/asus/FW_BLUECAVE_300438446630.zip`

Once the firmware samples have been placed, use the helper script provided to generate a `targets.list` file based on the contents of the `samplesfull` folder.

`./gen_targets.sh <path-to-samplesfull-folder>`

An example list `examples.list` has been provided, along with the `full.list` file that was used for our original experiment on 7,140 firmware samples.

5) prepare the .yaml file

You can make your own, or use the provided `gh_job.yaml`. Make sure that the number under `completions` equals the number of lines in the `targets.list` file generated in the previous step. `parallelism` indicates how many parallel pods are to be run, which should be scaled according to the resources your minikube instance has.

For more information on using .yaml jobs with kubernetes or minikube, refer to the official documentation.

6) run Greenhouse using kubernetes

`kubectl apply -f gh_job.yaml`

if using the minikube kubectl

`minikube kubectl -- apply -f gh_job.yaml`

After about a minute, check that the pods are running with

`kubectl get pods` or `minikube kubectl -- get pods`

When all pods are finished, it will indicate 'Complete' for all of them. Note that some pods may show Error as part of the fail/retry mechanism in Greenhouse.

The results should complete within 24 hours, usually 4-6 hours on average. Rehosted images will be present in the mounted k8 folder, k8/results/<imageid_sha256hash>. Logs are present in k8/logs/<imageid>

All logs inside the logs folder will end with a message printing if a run was a SUCCESS, a PARTIAL success or FAILED.

Note that even if an image failed to rehost, Greenhouse will still copy whatever it managed to do into the results folder for future reference/debugging.

7) Once all pods are complete, delete the job with

`kubectl delete -f gh_job.yaml`

if using the minikube kubectl

`minikube kubectl -- delete -f gh_job.yaml`

then, delete and cleanup minikube by CTR+C on the minikube_setup.sh script, which will perform cleanup.

(You may also manually delete the minikube instance with `minikube delete --all`, then use losetup to cleanup any dangling loop devices/mounts.)

8) You may process the results in `k8/logs` using the provided script `process_logs.py` as follows:

`python3 process_logs.py <path-to-logs-folder>`

The results will be printed directly to stdout in .csv format.
