# Overview

Modified, repackaged version of routersploit framework to test Greenhouse rehosted Docker images on a kubernetes cluster

# Requirements
- Ubuntu 20.04
- docker 20.10.21 or higher
- kubernetes
Client Version: version.Info{Major:"1", Minor:"22", GitVersion:"v1.22.3", GitCommit:"c92036820499fedefec0f847e2054d824aea6cd1", GitTreeState:"clean", BuildDate:"2021-10-27T18:41:28Z", GoVersion:"go1.16.9", Compiler:"gc", Platform:"linux/amd64"}

Server Version: version.Info{Major:"1", Minor:"23", GitVersion:"v1.23.7", GitCommit:"42c05a547468804b2053ecf60a3bd15560362fc2", GitTreeState:"clean", BuildDate:"2022-05-24T12:24:41Z", GoVersion:"go1.17.10", Compiler:"gc", Platform:"linux/amd64"}

# Build

1) docker build . -t <your-dockerhub-repo>/gh2routersploit:latest
2) docker push <your-dockerhub-repo>/gh2routersploit:latest

## Modifying the run
The following files affect the routersploit exploits run

$WORKDIR/exploits.list		: list of all exploits run by routersploit. Provided in this repo

gh2routersploit takes a Greenhouse rehosted exported image in the form <name>.tar.gz

An example Greenhouse image has the following filestructure:

greenhouse-DCS_932L_REVA_FIRMWARE_1.01.tar.gz
--> 1/
    --> DCS_932L_REVA_FIRMWARE_1.01/
        --> debug/
        --> minimal/
        --> config.json
        --> sendcurls.sh

# Output

Once complete, the `sploit_logs` folder should contain the stdout outputs of each of the samples for every routersploit exploit run inside `exploit.list`

There should also be an output tar file `<hash>_sploits.tar` that contains the results of the routersploit-log-parser, parsed as a csv file that maps vulnerable targets to their respective exploits. To manually generate these same results, use the script inside the folder `routersploit-log-parser/`

`python3 parse-routersploit-logs.py -ld </path/to/sploit_logs/`

This will generate inside the `sploit_logs` folder a `processed_data` folder containing three csv files each mapping the Firmware `ID` and `Name` (as in `map.csv`) to the IP address and corresponding successful routersploit sploit:

- vulnerable.csv 		: maps "confirmed" vulnerable cases that returned True in routersploits automated framework
- not-vulnerable.csv		: maps "confirmed" not vulnerable cases that returned False in routersploits automated framework
- needs-verification.csv	: maps "unconfirmed" cases that returne None in routersploits automated framework, usually because the exploit itself cannot be verified automatically
