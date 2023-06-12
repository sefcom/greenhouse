import os

import traceback

httpcode = "-1"
binarg = ""
path = ""
name = ""
fullrehosted = False
old_code = "-1"
number_of_cycles=-1
premature_exit = False
dedaemon = False
greenhouse_only = True
bincmd_latch = False
cwdcmd_latch = False
nvram_imported = False
unpacked = True
sanitization = False
missing_libs = False
run_time_args = False
missing_config = False
missing_cert = False
nvram_key = False
nvram_values = False
patched_crash = False
patched_exit = False
patched_wait = False
custom_bind = False
base_cwd = "/"
child_threads = 0
brand = ""
gh_id = 0
no_cwd = False
no_ps = False
arch = "?"
extracted = False
canrun = False
curlpassed = False
webpassed = False
username = ""
password = ""
ipaddr = ""
ipport = ""
sha256sum = ""
dummy_network = False
transplanted = False
borderbins = []
borderMap = dict()

RB_PATH = "patches"
LOG_PATH = "logs"
ROOT_PATH = "http_full"
NUM_TARGETS = 7143 #7651

def process_rb_dump(iid):
    global sanitization, missing_libs
    global missing_config, missing_cert
    global nvram_key, nvram_values
    global patched_crash, patched_exit, patched_wait
    global dedaemon, run_time_args

    lineCount = 0
    targetPath = os.path.join(ROOT_PATH, RB_PATH, iid)
    if not os.path.exists(targetPath):
        return
    with open(targetPath, "r") as bFile:
        for line in bFile:
            lineCount += 1
            try:
                if line.startswith("[ROADBLOCK]"):
                    if "requires missing directory" in line:
                        sanitization = True
                    if "requires missing file" in line:
                        sanitization = True
                    if "requires missing library" in line:
                        missing_libs = True
                    # if "requires missing config" in line:
                    # if "Copying /gh/greenhouse_files/httpd.conf" in line:
                        # missing_config = True
                    # if "requires missing cert" in line:
                    # if "Copying /gh/greenhouse_files/openssl" in line:
                        # missing_cert = True
                    if "requires NVRAM KEY" in line:
                        nvram_key = True
                    if "requires NVRAM VALUE" in line:
                        nvram_values = True
                    if "patching of crash-causing instruction" in line:
                        patched_crash = True
                    if "requires de-daemon patch" in line:
                        dedaemon = True
                    if "patching of check that leads to exit" in line:
                        patched_exit = True
                    if "patching of wait-loop that timed-out" in line:
                        patched_wait = True
                    if "requires specific run time args" in line:
                        run_time_args = True
            except Exception as e:
                print(e)
                print(traceback.format_exc())
                print("Line: ", lineCount)
                ()
                exit()

def process_log_dump(iid):
    global httpcode, fullrehosted, old_code
    global cwdcmd_latch, bincmd_latch, binarg, base_cwd
    global greenhouse_only, number_of_cycles
    global nvram_imported, no_cwd, no_ps
    global unpacked, gh_id, name, path, brand
    global missing_config, missing_cert, dummy_network
    global arch, username, password, ipaddr, ipport
    global extracted, canrun, curlpassed, webpassed
    global xmldb, datalib, transplanted, custom_bind
    global borderbins, sha256sum

    lineCount = 0
    ipaddrfields = []
    targetPath = os.path.join(ROOT_PATH, LOG_PATH, iid)
    if not os.path.exists(targetPath):
        return
    with open(targetPath, "rb") as bFile:
        for line in bFile:
            lineCount += 1
            try:
                line = line.decode('utf-8',errors='ignore')
                if line.startswith("Status Code"):
                    httpcode = line[12:].strip()
                if cwdcmd_latch and "> CWD:" in line:
                    base_cwd = line.strip().split(":", 1)[1].strip()
                    cwdcmd_latch = False
                if bincmd_latch and ">" in line:
                    binarg = line.strip().strip(">").strip()
                    bincmd_latch = False
                    cwdcmd_latch = True
                if "TARGET HASH" in line:
                    sha256sum = line.split(":")[1].strip()
                if line.startswith("Running command:  chroot fs"):
                    if "/qemu-" in line:
                        index = line.find("/qemu")
                        qemuline = line[index:]
                        qemucmd = qemuline.split()[0]
                        arch = qemucmd.split("-")[1]
                    bincmd_latch = True
                if "exec,nochain,page" in line:
                    greenhouse_only = False
                # if "PATCH LOOP [" in line:
                #    index = line.index("PATCH LOOP")
                #    line = line[index:]
                #    count = int(line.split("[")[1].split("]")[0])
                #    number_of_cycles = count+1
                #    canrun = True
                if "[GreenHouseQEMU] IP" in line or curlpassed:
                    canrun = True
                if "FirmAE Rehost IID" in line:
                    fullrehosted = True
                    old_code = httpcode
                if "FirmAE Rehost failed" in line:
                    fullrehosted = False
                if "nvram extraction complete" in line:
                    nvram_imported = True
                if "Generic exception handler" in line:
                    httpcode = "-2"
                if "cwd.log not found" in line:
                    no_cwd = True
                if "ps.log not found" in line:
                    no_ps = True
                if "creating docker bridge ghbridge1" in line:
                    dummy_network = True
                if "using  xmldb" in line:
                    xmldb = True
                if "using  datalib" in line:
                    datalib = True
                if "PATCH LOOP [0]" in line:
                    extracted = True
                if "[GreenHouse] target:" in line:
                    transplanted = True
                if "[+] Probing " in line:
                    fields = line.split()
                    ipaddrfields = fields[2].strip(".").split(":")
                if "trying dns query via " in line or "sending upnp discover check" in line:
                    fields = line.split("@")
                    tmpfields = fields[1].strip().strip("[").strip("]").split(":")
                    ipaddrfields = [""]
                    ipaddrfields.extend(tmpfields)
                if "[connected]: True" in line:
                    curlpassed = True
                    ipaddr = ipaddrfields[1].strip("/")
                    ipport = ipaddrfields[2].strip("/")
                if not curlpassed and number_of_cycles == 1 and "failed to parse trace_path" in line:
                    canrun = False
                if "[wellformed]: True" in line:
                    webpassed = True
                if "Logged in with" in line:
                    fields = line.split()
                    userpass = fields[4]
                    userpassfields = userpass.split(":")
                    username = userpassfields[0]
                    if len(userpassfields) > 1:
                        password = userpassfields[1]
                # REMOVE IN FUTURE RUNS WHERE THE PATCH LOG HAS THE NECESSARY INFO
                if "Copying /gh/greenhouse_files" in line and ".conf" in line:
                    missing_config = True
                # REMOVE IN FUTURE RUNS WHERE THE PATCH LOG HAS THE NECESSARY INFO
                if "Copying /gh/greenhouse_files/" in line and "openssl" in line:
                    missing_cert = True
                # if "[Batch] Run Complete for" in line:
                if "Unpacking image" in line:
                    path = line.split()[-1]
                    name = path.split("/")[-1].rsplit(".", 1)[0]
                    name = name.replace("(", "_").replace(")", "_").replace("-", "_")
                    dirpath = os.path.dirname(path)
                    brand = dirpath.split("/")[-1].split("_")[0].strip()
                if "[qemu]" in line:
                    if "forcing ipv6 protocol to ipv4" in line:
                        custom_bind = True
                if "- Error, unable to " in line:
                    unpacked = False
                if "RUNNING ON K8 POD " in line:
                    if "-full-" in line:
                        gh_id = int(line.split("-")[4]) + 1
                    else:
                        gh_id = int(line.split("-")[3]) + 1
            except Exception as e:
                print(e)
                print(traceback.format_exc())
                print("Line: ", lineCount)
                print(line)
                exit()
    bFile.close()

def reset():
    global httpcode
    global binarg
    global path
    global name
    global fullrehosted
    global old_code
    global number_of_cycles
    global premature_exit
    global dedaemon
    global breakloop
    global crashpatch
    global greenhouse_only
    global bincmd_latch
    global cwdcmd_latch
    global nvram_imported
    global unpacked
    global sanitization
    global missing_libs
    global run_time_args
    global missing_config
    global missing_cert
    global nvram_key
    global nvram_values
    global patched_crash
    global patched_exit
    global patched_wait
    global custom_bind
    global base_cwd
    global child_threads
    global brand
    global gh_id
    global no_cwd
    global no_ps
    global arch
    global sha256sum
    global extracted
    global canrun
    global curlpassed
    global webpassed
    global username
    global password
    global ipaddr
    global ipport
    global dummy_network
    global xmldb
    global datalib
    global transplanted

    httpcode = "-1"
    binarg = ""
    path = ""
    name = ""
    fullrehosted = False
    old_code = "-1"
    number_of_cycles=-1
    premature_exit = False
    dedaemon = False
    breakloop = False
    crashpatch = False
    greenhouse_only = True
    extracted = False
    canrun = False
    curlpassed = False
    webpassed = False
    bincmd_latch = False
    cwdcmd_latch = False
    nvram_imported = False
    unpacked = True
    sanitization = False
    missing_libs = False
    run_time_args = False
    missing_config = False
    missing_cert = False
    nvram_key = False
    nvram_values = False
    patched_crash = False
    patched_exit = False
    patched_wait = False
    custom_bind = False
    base_cwd = "/"
    child_threads = 0
    brand = ""
    gh_id = 0
    no_cwd = False
    no_ps = False
    arch = "?"
    username = ""
    password = ""
    ipaddr = ""
    ipport = ""
    dummy_network = False
    xmldb = False
    datalib = False
    transplanted = False
    sha256sum = ""
    borderbins = []


def main():
    for i in range(1, NUM_TARGETS+1):
        iid = str(i)
        reset()
        process_log_dump(iid)
        process_rb_dump(iid)
        print("%d | %s | %s | %s | %s | %s | %s | %d | | %s | %s | %s | %s | %s | %s | %s | %s | | | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s" % (i, brand, name, sha256sum, arch, base_cwd, binarg, number_of_cycles, old_code, httpcode,
                                                                                extracted, canrun, curlpassed, webpassed, username, password, ipaddr, ipport,
                                                                                unpacked, sanitization, transplanted, missing_libs, missing_config, missing_cert, fullrehosted, run_time_args, no_ps, no_cwd, nvram_key, nvram_values,
                                                                                patched_crash, patched_exit, patched_wait, custom_bind, dummy_network, xmldb, datalib, path))
    print("="*50)
    for borderKey in borderMap.keys():
        count = borderMap[borderKey]
        borderName = borderKey[0]
        hasBind = borderKey[1]
        print(borderName, hasBind, count)
main()
