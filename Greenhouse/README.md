# Greenhouse (Code)
Platform for Automated Single-Service Rehosting of Firmware in User-Space

## Build Requirements
- Last tested on Ubuntu 20.04
- angr-dev (last tested locally on commit 2462061b0680988b9ac8d4fbdd2c204f37e8100e)
- FirmAE (last tested locally on commit 7f2e02295d7b334a99b440e6acdf79812add1f96)
- Python3.7 or higher
- radare2 4.2.1 or higher
- curl 7.68.0 or higher
- docker 20.10.21 or higher
- docker-compose 1.29.2 or higher
- binwalk v2.3.3 (also installed by FirmAE)
- chrome + chromedriver (the version of the chromedriver in the `analysis` folder is ChromeDriver 107.0.5304.62 for Chrome 107.0.5304.121. A command-line script for updating it for a particular system can be run via `getchromedriver.sh` in the same folder)

## pip install (see requirements.txt)
r2pipe==1.6.0
docker==5.0.0
nclib==1.0.1
requests==2.24.0
python-nmap==0.7.1
selenium==3.141.0
lxml==4.7.1
networkx==2.8.4
ifaddr==0.2.0
pwntools==4.9.0

## Other repositories

### FirmAE
- pull FirmAE from the repo https://github.com/pr0v3rbs/FirmAE
- install FirmAE using the following instructions

`cp FirmAEreplacements/install.sh FirmAE/install.sh`
`cp FirmAEreplacements/v2.3.3.tar.gz FirmAE/v2.3.3.tar.gz`

`cd /work/FirmAE && ./download.sh`
`cd /work/FirmAE && ./install.sh`

- once installer runs
- cp and override the files inside the FirmAE folder with the ones inside FirmAEplacement

`cp FirmAEreplacements/makeNetwork.py FirmAE/scripts/makeNetwork.py`
`cp FirmAEreplacements/delete.sh FirmAE/scripts/delete.sh`
`cp FirmAEreplacements/inferFile.sh FirmAE/scripts/inferFile.sh`
`cp FirmAEreplacements/test_emulation.sh FirmAE/scripts/test_emulation.sh`
`cp FirmAEreplacements/umount.sh FirmAE/scripts/umount.sh`

`cp FirmAEreplacements/extractor.py FirmAE/sources/extractor/extractor.py`

`cp FirmAEreplacements/firmae.config FirmAE/firmae.config`
`cp FirmAEreplacements/run.sh FirmAE/run.sh`
`cp FirmAEreplacements/initializer.py FirmAE/analyses/initializer.py`

### angr

- pull angr from the angr-dev repo https://github.com/angr/angr-dev
- install angr with ./setup.sh -i -e angr

# Running

python3 /gh/gh.py --outpath <path-to-final-results-folder> --workspace /tmp/scratch --logpath=<path-to-patchlog-file> --cache_path=<path-to-cache-folder> --ip <default-docker-ip-to-use-initially> --ports=<comma-seperated-list-of-initial-ports-to-try> --max_cycles=<maximum-number-of-patch-cycles-before-timeout> -rh --brand=<brand-of-target-image> --img_path=<path-to-firmware-image-file>

Greenhouse should attempt to run FirmAE first, then perform several "PATCH LOOPS" where it iteratively attempts to rehost/modify the fs and binary to get a working rehosted web service inside a docker container

## fields
- --outpath : path to output folder where exported folder containing debug and minimal docker image info is stored
- --workspace : path to scratch folder where intermediate files are stored and cleared
- --qemu_path : path to folder where qemu user files are. qemu user binaries should be named "qemu-<arch>-static"
- --gh_path : absolute path to the greenhouse files where pre-loaded NVRAM values and configs are stored
- --analysis_path : absolute path to the analysis folder containing a compatible version of chromedriver for selenium
- --firmae : path to the firmae installation folder, to enable full-system snapshots
- --logpath : path to condensed patch file
- --external_qemu : if exporting for fuzzing, path to generic/optimized qemu that other platforms might use
- --cache_path : path to folder containing 'cached' snapshots from past FirmAE runs, automatically stores and updates them during successful runs
- --ip : string containing the default docker ip address to target (172.17.0.2 on most machines, e.g. "172.17.0.2")
- --ports : comma-seperated string of initial ports to try e.g. "80,443"
- --max_cycles : maximum iterative patch cycles to try before giving up (default 25)
- --brand : brand of the firmware image. if empty, will attempt to parse brand from img_path as follows <path>/<brand>/<imagefile>
- --img_path : path to firwmare image to rehost

## flags
- -rh : rehost_first, always attempt full rehosting using FirmAE first before patch loop
- -nf : nofullrehosting, disable full rehosting (will overwrite -rh)
- -nr : norepeat, run patch loop only once. Otherwise, Greenhouse will run patch loop until success or no patch possible.
- -ns : nostrict, disable strict checking. will not check that web services are 'well-formed' for succes
- -nd : nodedaemon, disables dedaemoning attempts after a successful rehost is done.
- -nb : no hack_bind, disables hack bind that is used by our QEMU patch to get around unsupported ipv6 socket binds

## (the following flags disable features that help ensure the created rehosted image is suitable for fuzzing)
- -np : no hackdevproc, disables hackdev and hackproc in our QEMU patch that creates dummy /ghdev and /ghproc folders. 
- -ni : no hacksysinfo, disables hacksysinfo in our QEMU patch that always returns 0 system resource usages.
- -nc : no cleanup firame, disables automatic cleanup of FirmAE folders.
