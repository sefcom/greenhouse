1) Install minikube as per https://minikube.sigs.k8s.io/docs/start/

Make sure you have kubectl installed, or use the built-in `minikube kubectl`

2) run minikube

minikube start --memory 32768 --cpus 4

We recommend ensuring you have ~4gb of memory and 0.5 cpus per Greenhouse pod intended to run at minimum.

3) setup the minikube environment

./minikube_setup.sh

this builds the Greenhouse image directly inside the minikube environment.

You may also build the image locally, then pull/transfer the image into the minikube environment instead.

4) setup your targets. This is done by copying targets of interest into the `samplesfull` folder inside the `k8` folder and generating a corresponding `targets.list` file. Targets should be placed in `samplesfull` in the form `samplesfull/<BRAND>/<TARGETFILE>` for example, `samplesfull/asus/FW_BLUECAVE_300438446630`

Once the firmware samples have been placed, use the helper script provided to generate a targets.list file based on the contents of the `samplesfull` folder.

./gen_targets.sh <path-to-samplesfull-folder>

A sample `targets.list` has been provided, along with the `full.list` file that was used for our original experiment on 7,140 firmware samples.

5) prepare the .yaml file

You can make your own, or use the provided `gh_job.yaml`. Make sure that the number under `completions` equals the number of lines in the `targets.list` file generated in the previous step. `parallelism` indicates how many parallel pods are to be run, which should be scaled according to the resources your minikube instance has.

For more information on using .yaml jobs with kubernetes or minikube, refer to the official documentation.

6) run Greenhouse using kubernetes

kubectl apply -f gh_job.yaml

The results should complete within 24 hours, usually 4-6 hours on average.

Rehosted images will be present in the mounted k8 folder, k8/results/<imageid_sha256hash>

Logs are present in k8/logs/<imageid>

All logs inside the logs folder will end with a message printing if a run was a SUCCESS, a PARTIAL success or FAILED.

Note that even if an image failed to rehost, Greenhouse will still copy whatever it managed to do into the results folder for future reference/debugging.
