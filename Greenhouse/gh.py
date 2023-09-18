from socket import has_ipv6
from telnetlib import IP
from backend import *
from patcher import *
from plugins import *
from sidebins import *
import argparse
import os, stat
import traceback
import time
import subprocess
# import pathlib


GH_SUCCESS_TAG = "GH_SUCCESSFUL_CACHE"

class Greenhouse():
    REHOST_TYPE_MAP = {"HTTP" : "HTTP",
                       "UPNP" : "UPNP",
                       "DNS" : "DNS",
                       "DHCP" : "DHCP"}

    def __init__(self, args):
        self.ghbasepath = os.path.dirname(os.path.abspath(__file__))
        self.qemu_src_path = os.path.join(self.ghbasepath, "qemu")
        self.gh_src_path = os.path.join(self.ghbasepath, "greenhouse_files")
        self.scripts_path = os.path.join(self.ghbasepath, "scripts")
        self.analysis_path = os.path.join(self.ghbasepath, "analysis")
        self.external_qemu = os.path.join(self.ghbasepath, "greenhouse_files", "external_qemu")

        self.firmae_path = args.firmae
        self.output_dst_path = args.outpath
        self.fs_path_override = args.fs_path
        self.target_bin_override = args.target_bin
        self.skipfile = args.skipfile
        self.trunk_only = args.bintrunk
        self.max_depth = args.max_depth
        self.max_cycles = args.max_cycles
        self.workspace = args.workspace
        self.batchfolder_path = args.batchfolder
        self.make_dot_graph = args.make_dot
        self.logpath = args.logpath
        self.docker_ip = args.ip
        self.brand = args.brand
        self.partial_configs = args.partial_configs
        self.bintrunk = None
        self.runner = None
        self.cache_path = args.cache_path
        self.name = ""
        self.target_cache_path = ""
        self.sha256hash = ""

        # flags
        self.rehost_first = args.rehost_first
        self.repeat = not args.norepeat
        self.diagnose_only = args.diagnose
        self.strict = not args.nostrict
        self.hackbind = not args.nohack_bind
        self.hackdevproc = not args.nohack_devproc
        self.hacksysinfo = not args.nohack_sysinfo
        self.skip_fullsystem = args.nofullrehosting
        self.cleanup_firmae = not args.nocleanupfirmae
        self.baseline = args.baseline
        self.nodaemon = not args.nodedaemon
        self.rh_success = False
        self.ps_success = False
        self.cwd_success = False

        # actual paths used by submodules
        self.img_path = args.img_path
        self.fs_path = ""
        self.bin_path = ""
        self.qemu_path = ""
        self.qemu_arch = ""

        # self.urls = self.setup_urls(args.ip, args.ports)
        self.urls = [args.ip]
        self.ports_base = self.setup_ports(args.ports)
        self.ports = self.ports_base.copy()
        self.extra_args = args.bin_args
        self.extra_args_base = args.bin_args
        self.timeout = args.timeout
        self.bg_scripts = dict()
        self.rehost_type = self.get_rehost_type(args.rehost_type)

        # defaults
        self.changelog = []

    def reset_paths(self):
        self.target_bin_override = ""
        self.fs_path = ""
        self.bin_path = ""
        self.qemu_path = ""
        self.qemu_arch = ""
        self.logpath = ""
        self.brand = ""
        self.bg_scripts = dict()
        self.rh_success = False
        self.ps_success = False
        self.cwd_success = False
        self.ip_targets_path = "" 
        self.ports_path = "" 

    def get_rehost_type(self, rehost_string):
        if rehost_string in self.REHOST_TYPE_MAP.keys():
            return self.REHOST_TYPE_MAP[rehost_string]
        print("    - unrecognized rehost_type request [%s], defaulting to [HTTP]..." % rehost_string)
        return "HTTP"

    def setup_ports(self, portstring):
        try:
            ports = portstring.split(",")
        except:
            print("    - ERROR: invalid comma-seperated port string, defaulting to ''")
            return []
        return ports

    def setup_target(self, img_path):
        # hash
        sha256hash = Files.hash_file(img_path)
        print("TARGET HASH: ", sha256hash)
        self.sha256hash = sha256hash

        # get brand
        if len(self.brand) == 0:
            if len(img_path) != 0:
                self.brand = self.get_firmware_brand_from_path(img_path)
                print("    - assuming firmware brand: ", self.brand)
            else:
                print("    - missing brand for fs, please supply --brand")
                return False
        else:
            print("    - target firmware brand: %s" % self.brand)
        
        # get name
        name = os.path.basename(self.img_path)
        for tag in [".tar", ".zip", ".bin", ".gz", ".xz"]:
            if name.lower().endswith(tag):
                name = name.rsplit(".", 1)[0]

        # sanitize
        self.name = name.replace("(", "_").replace(")", "_").replace("-", "_")
        self.target_cache_path = ""

        # check sudo
        print("-"*100)
        print("Check sudo...")
        subprocess.call(["sudo", "-v"])
        print("checked!")
        print("-"*100)

        # unpack image & find target filesystem
        self.gh = Planter(gh_path=self.gh_src_path, scripts_path=self.scripts_path, qemu_src_path=self.qemu_src_path, brand=self.brand)
        self.fs_path = self.gh.unpack_image(img_path, fs_path_override=self.fs_path_override, workspace=self.workspace)
        if self.fs_path == "":
            print("    - Error, unable to unpack image for %s" % img_path)
            return False 

        # find target binary to run
        if self.target_bin_override == "":
            self.bin_path = self.gh.get_target_binary(self.fs_path, self.rehost_type)
        else:
            if self.fs_path not in self.target_bin_override:
                self.target_bin_override = self.target_bin_override.strip("/")
                self.target_bin_override = os.path.join(self.fs_path, self.target_bin_override)
            self.bin_path = self.target_bin_override

        if self.bin_path == "":
            print("    - Error, unable to find binary path for %s" % img_path)
            return False

        # setup for qemu emulation and patching
        self.gh.clean_fs(self.fs_path)

        setupresult = self.gh.setup_env(self.qemu_src_path, self.fs_path, self.bin_path, self.baseline)
        if not setupresult:
            return False
        self.qemu_path = self.gh.get_qemu_run_path()
        self.qemu_arch = self.gh.get_qemu_arch()

        return True

    def setup_urls(self, ip, ports):
        urls = []
        port_list = ports.split(",")
        for port in port_list:
            port = port.strip()
            url = "http://%s:%s" % (ip, port)
            urls.append(url)
        return urls

    def read_skiplist(self, path):
        skiplist = []
        if path:
            if os.path.exists(path):
                with open(path, "r") as skipFile:
                    for line in skipFile:
                        line = line.strip()
                        skiplist.append(line)
        return skiplist

    # run
    def run(self, img_path):
        ret = 1
        try:
            print("#"*100)
            if "POD_NAME" in os.environ.keys():
                podname = os.environ.get("POD_NAME")
                print("RUNNING ON K8 POD", podname)
                print("#"*100)
                print("Outputting results to", self.output_dst_path)
            if self.setup_target(img_path):
                ret = self.patch_loop()
        except Exception as e:
            print("!"*100)
            print("Generic exception handler for future debugging")
            print(e)
            print(traceback.format_exc())
            output_dir_path = ""
            if len(self.img_path) > 0:
                output_dir = self.name
                output_dir_path = os.path.join(self.output_dst_path, output_dir)
            if self.runner is not None and len(output_dir_path) > 0:
                print("    - Writing broken fs for debug purposes to", output_dir_path)
                self.runner.export_current_dockerfs(output_dir_path, result="CRASHED", name=output_dir, brand=self.brand, hash=self.sha256hash, \
                                                    checker=None, external_qemu=self.external_qemu, urls=self.urls, time_to_up=-1)
            print("!"*100)
            return -1
        return ret


    # batchrun
    def batchrun(self, batchfolder_path):
        print("="*100)
        print("Batch running on", batchfolder_path)
        paths = Files.get_all_files(batchfolder_path)
        for p in paths:
            print("    - ", p)
        print("="*100)
        skiplist = self.read_skiplist(self.skipfile)
        print("[Batch] START ", time.ctime())
        starttime = time.time()
        for target in paths:
            if target in skiplist:
                print("    [Batch] Skipping %s in skiplist" % target)
                continue
            print("#"*100)
            print("    [Batch] Running GreenHouse on %s" % target)
            self.img_path = target
            self.run(target)
            print("    [Batch] Run Complete for %s" % target)
            self.reset_paths()
        print("[Batch] ALL PATHS COMPLETE")
        print("[Batch] END ", time.ctime())
        totaltime = time.time() - starttime
        print("[Batch] TIME TAKEN = ", (totaltime / 60), "mins")
        print("="*100)

    # generate bintrunk and graph
    def generate_bintrunk(self, trace_json_path, trace, always_rebuild=False):
        if always_rebuild == True or self.bintrunk == None:
            self.bintrunk = BinTrunk(self.bin_path, trace_path=trace_json_path, max_depth=self.max_depth)
            if not self.bintrunk.angr_cfg:
                print("    - Aborting patch attempt")
                return  [], -1
            print("Building graph")
            self.bintrunk.build_graph(verbose=False)

        trace_pid = trace.parent_pid
        if "-1" in trace_pid:
            print("    - no parent_pid found in trace")
            print("      ", trace.traces.keys())
            print("    - Aborting patch attempt")
            return [], -1

        parent_trace_path = trace.read_trace(trace.traces[trace.parent_pid])
        print("Mapping trace to graph")
        trace_trunk_path, index = self.bintrunk.map_trace_to_graph(parent_trace_path, trace_base_addr=trace.base_addr)

        if len(trace_trunk_path) <= 0: # failed to map, abort
            return [], -1

        if len(trace_trunk_path) > 50:
            print("    - truncating to last 50 addrs")
            print(trace_trunk_path[-50:])
        else:
            print(trace_trunk_path) #last 50 addrs
        print("Mapped %d/%d paths" % (index, len(parent_trace_path)))

        # highlight all traced addresses
        all_traces = set()
        for addr_trace in trace.traces.values():
            addr_set = set(addr_trace)
            all_traces.update(addr_set)

        all_nodes = self.bintrunk.get_trace_nodes_in_graph(all_traces)
        callsites = set()

        if self.make_dot_graph:
            self.bintrunk.highlight_trace_and_dump_graph(all_nodes, mark=callsites)
        return  trace_trunk_path, index

    def write_changelog(self, changelog):
        if self.logpath == "":
            self.logpath = os.path.join(self.fs_path, "patch.log")
        print("Logging changes and emulation notes at %s" % self.logpath)
        with open(self.logpath, "w") as changeFile:
            for line in changelog:
                changeFile.write(line+"\n")
        changeFile.close()

    def get_firmware_brand_from_path(self, path):
        basepath = os.path.dirname(path)
        basedir = basepath.split("/")[-1]
        brand = basedir.split("_")[0]
        return brand

    def get_background_plugins(self):
        bg_scripts = dict()
        for subclass in BackgroundScript.__subclasses__():
            bg = subclass()
            name = bg.binary
            bg_scripts[name] = bg
        print(bg_scripts)
        return bg_scripts

    def get_bin_paths(self):
        fileList = []
        for root, dirs, files in os.walk(self.fs_path, topdown=False):
            for file in files:
                path = os.path.join(root, file)
                fileList.append(path)
        return fileList

    def get_checker(self):
        if self.rehost_type == "HTTP":
            return HTTPInteractionCheck(self.brand, self.analysis_path)
        elif self.rehost_type == "UPNP":
            return UPNPInteractionCheck(self.brand, self.analysis_path)
        elif self.rehost_type == "DNS":
            return DNSInteractionCheck(self.brand, self.analysis_path)
        print("    - no checker found for %s, defaulting to HTTP..." % self.rehost_type)
        return HTTPInteractionCheck(self.brand, self.analysis_path)

    def apply_fullsystem_rehost(self):
        self.target_cache_path = os.path.join(self.cache_path, self.name)
        print("Looking for cache", self.target_cache_path)
        if self.skip_fullsystem:
            print("    - skipping full system rehosting!")
            return "", "", False
        IID = ""
        mount_path = os.path.join(self.firmae_path, "mountfs")
        binary_name = os.path.basename(self.bin_path)
        firmae = FirmAEwrapper(binary_name, self.brand, self.firmae_path, mount_path, self.scripts_path, self.analysis_path, self.bg_scripts)

        use_cache = False
        if os.path.exists(self.target_cache_path):
            success_tag = os.path.join(self.target_cache_path, GH_SUCCESS_TAG)
            if os.path.exists(success_tag):
                use_cache = True
            else:                
                Files.rm_folder(self.target_cache_path)

        if use_cache:
            print("    - working cache exists, using cached fullhost values...")
            success = True
        else:
            IID, success, has_web = firmae.run_firmae(self.img_path, self.cleanup_firmae)
            print("FirmAE Rehost IID: %s" % IID)
            firmae.check_shutdown()
            new_run_args = ""
            cwdpath = ""

            Files.mkdir(self.target_cache_path, silent=True)
            if success:
                print("    - FirmAE Rehost successful! Copying to cache...")
                relative_bin = os.path.relpath(self.bin_path, self.fs_path)
                protected = [relative_bin, "dev/null", "dev/random", "dev/urandom"]
                firmae.mount_and_cache_fs(IID, self.firmae_path, self.target_cache_path, protected=protected)
                self.gh.clean_fs(self.target_cache_path)
            
            # nvram values
            qemu_log_path = os.path.join(self.firmae_path, "scratch", IID, "qemu.final.serial.log")
            dest = os.path.join(self.target_cache_path, "qemu.final.serial.log")
            if os.path.exists(qemu_log_path): # copy nvram values if we can find them
                Files.copy_file(qemu_log_path, dest)
            if self.cleanup_firmae:
                firmae.cleanup_IID(IID)

        time.sleep(2) # pause for dramatic effect

        # extract values from fullrehost
        if success:
            if os.path.exists(self.target_cache_path):
                print("    - copying from", self.target_cache_path)
                self.gh.clean_fs(self.target_cache_path)
                Files.copy_overwrite_dir_contents(self.target_cache_path, self.fs_path)
                devPath = os.path.join(self.fs_path, "dev")
                ghdevPath = os.path.join(self.fs_path, "ghdev")
                Files.copy_overwrite_dir_contents(devPath, ghdevPath)
                update_success = firmae.update_ps(self.target_cache_path)
                found_ps, new_run_args = firmae.get_run_args(self.target_cache_path, binary_name)
                print("      | [found_ps]:", found_ps)
                print("                   - ", new_run_args)
                print("      | [update_success]: ", update_success)
                self.ps_success = update_success # and found_ps
                cwdpath = firmae.get_cwd(self.target_cache_path)
            else:
                print("    - error, fullrehost was successful but unable to copy results")
                success = False
        else:
            print("    - FirmAE Rehost failed, skipping copying...")

        if use_cache or len(IID) > 0:
            # update nvrams
            print("    - attempting nvram extraction...")
            qemu_nvram_logpath = os.path.join(self.target_cache_path, "qemu.final.serial.log")
            new_nvrams = firmae.extract_lognvram(qemu_nvram_logpath)
            if new_nvrams is not None:
                self.gh.fixer.update_nvram_map(new_nvrams)
                self.gh.fixer.write_nvram(new_nvrams.keys(), self.changelog)
            print("    - done!")

        print("      | [cwdpath]:", cwdpath)
        if cwdpath is None:
            cwdpath = ""
        else:
            self.cwd_success = True
        self.rh_success = success
        print("      | [rh_success]:", self.rh_success)

        return new_run_args, cwdpath, success

    ## patch loop
    def patch_loop(self):
        targets = set(".")
        configs = set()
        self.changelog = []
        last_failed = set()
        last_folders= set()
        last_targets= set()
        last_configs = set()
        no_skip = []
        failed = set()
        targets = set()
        configs = set()
        folders = set()
        interfaces = set()
        bg_cmds = []
        bin_paths = []
        interface_cmds = []

        self.urls = [self.docker_ip]
        self.ports = self.ports_base.copy()

        success = False
        fullrehosted = False
        greenhouse_mode = True
        cwd_rh_replaced = False
        firmae_success = False
        success = False
        wellformed = False
        connected = False
        rehost_result = "FAILED"
        count = 0
        bg_sleep = 1
        binary = None
        bin_cwd = "/"
        mac = ""
        last_mac = ""
        nodaemon_args = ""
        needs_dedaemon = False
        needs_nodaemon_patch = False
        testing_nodaemon_patch = False
        nd_flags = ["-D", "-X", "-n", "-d"]
        ndflag_index = 0
        patch_blacklist = []
        self.ip_targets_path = os.path.join(self.fs_path, "target_urls")
        self.ports_path = os.path.join(self.fs_path, "target_ports")

        if self.nodaemon:
            needs_dedaemon = True
        else:
            patch_blacklist = ["daemon_fork"]

        print("[GREENHOUSE] RUNNING ", time.ctime())
        starttime = time.time()

        checker = self.get_checker()
        sparser = TraceParser(fs_path=self.fs_path)
        patcher = Patcher(blacklist=patch_blacklist)
        self.runner = QemuRunner(self.fs_path, self.bin_path, self.qemu_arch, self.sha256hash,
                                 checker, changelog=self.changelog, docker_ip=self.docker_ip,
                                 baseline_mode=self.baseline,
                                 hackbind=self.hackbind,
                                 hackdevproc=self.hackdevproc,
                                 hacksysinfo=self.hacksysinfo)
        
        # setup ip targets
        if not os.path.exists(self.ip_targets_path):
            self.gh.parse_ips(self.ip_targets_path, self.urls)

        # setup port targets
        if not os.path.exists(self.ports_path):
            self.gh.parse_ports(self.ports_path, self.ports)

        if self.trunk_only:
            greenhouse_mode = False

        # setup background scripts
        self.bg_scripts = self.get_background_plugins()

        new_run_args = ""
        if self.rehost_first and len(self.firmae_path) > 0:
            print("###################### FULLREHOST ######################")
            new_run_args, cwdpath, firmae_success = self.apply_fullsystem_rehost()
            if firmae_success:
                self.changelog.append("[ROADBLOCK] requires copying of full-system fs/nvram values/runtime args ")
            if len(new_run_args) > 0:
                pslog = "    - replacing runtime extra args " + self.extra_args + " with " + new_run_args
                print(pslog)
                if self.extra_args.strip() != new_run_args.strip():
                    self.changelog.append("[ROADBLOCK] requires specific run time args")
                    self.changelog.append(pslog)
                self.extra_args = new_run_args
            if len(cwdpath) > 0:
                cwdlog = "    - replacing bin_cwd " + bin_cwd + " with " + cwdpath
                print(cwdlog)
                if bin_cwd.strip() != cwdpath.strip():
                    self.changelog.append("[ROADBLOCK] requires specified CWD for webserver binary")
                    self.changelog.append(cwdlog)
                    if firmae_success:
                        cwd_rh_replaced = True
                bin_cwd = cwdpath
            fullrehosted = True

        if not fullrehosted or len(new_run_args) <= 0:
            # check for command-line args like conf paths/flags
            print("    - checking for cl_args...")
            command_args = self.gh.setup_cl_args(self.brand, self.fs_path, self.bin_path, self.changelog, self.extra_args_base, self.rehost_type)
            self.extra_args = self.extra_args_base
            for arg in command_args:
                if arg not in self.extra_args:
                    self.extra_args += " %s" % arg

        if not self.baseline:
            print("Extracting bg script commands...")
            bin_paths = self.get_bin_paths()
            for name, bg in self.bg_scripts.items():
                cmds, sleeptime = bg.get_single_cmds(bin_paths, self.fs_path)
                if len(cmds) > 0:
                    print("    - using ", name)
                    bg_cmds.extend(cmds)
                    bg_sleep += sleeptime
            print("...done!")

        while True:
            label = "###################### PATCH LOOP [%d] ######################" % count
            self.write_changelog(self.changelog)
            self.changelog.append(label)
            print(label)
            time_to_up = -1
            count += 1
            ## run target binary in docker via qemu-user
            emulation_output, exit_code, timedout, trace_path, time_to_up = self.runner.run(timeout=self.timeout, bin_cwd=bin_cwd,
                                                                            potential_urls=self.urls,
                                                                            ports_file=self.ports_path,
                                                                            extra_args=self.extra_args,
                                                                            nd_args=nodaemon_args,
                                                                            bg_cmds=bg_cmds,
                                                                            bg_sleep=bg_sleep,
                                                                            interface_cmds=interface_cmds,
                                                                            mac=mac,
                                                                            has_ipv6=has_ipv6,
                                                                            greenhouse_mode=greenhouse_mode)
            print("Exit code", exit_code, "timedout", timedout)

            # generate program trace
            trace_json_path = trace_path.rsplit(".", 1)[0] + ".json"
            parse_success = sparser.convert(trace_path, trace_json_path)
            if not parse_success:
                print("    - failed to parse trace_path")
                break
            trace = Trace(trace_json_path)

            errored = exit_code in self.runner.ERROR_CODES

            # bintrunk mode only
            if self.trunk_only:
                self.generate_bintrunk(trace_json_path, trace, always_rebuild=True)
                if self.batchfolder_path:
                    Files.rm_files([trace_path, trace_json_path])
                print("    - generate_bintrunk complete.")
                break

            last_mac = mac
            last_failed = failed.copy()
            last_targets = targets.copy()
            last_configs = configs.copy()
            last_folders = folders.copy()
            forkmap = dict()
            is_daemonized = False

            ## gather filesystem and nvram targets
            targets, folders, configs, ip_addrs, ipv6_addrs, ports, interfaces, failed, segfaulted, is_daemonized = sparser.parse(emulation_output, trace_path, forkmap=forkmap)
            if segfaulted:
                errored = True
                exit_code = -11

            # process subcall traces for missing files
            subcount = 0
            basetracepath = trace_path[:-1]
            subpath = "%s%d" % (basetracepath, subcount)
            print("Processing subtraces...")
            while os.path.exists(subpath):
                if subcount == 1:
                    subcount += 1
                    subpath = "%s%d" % (basetracepath, subcount)
                    continue
                subtargets, subfolders, subconfigs, subip_addrs, subipv6_addrs, sub_ports, subinterfaces, subfailed, subfaulted, _ = sparser.parse("", subpath, forkmap=forkmap)
                targets.update(subtargets)
                folders.update(subfolders)
                configs.update(subconfigs)
                ip_addrs.update(subip_addrs)
                ipv6_addrs.update(subipv6_addrs)
                ports.update(sub_ports)
                interfaces.update(subinterfaces)
                failed.update(subfailed)            
                if subfaulted:
                    errored = True
                    exit_code = -11
                # we don't need to track extra failed libs here
                subcount += 1
                subpath = "%s%d" % (basetracepath, subcount)
            print("exit_code", exit_code, "timeout", timedout, "errored", errored)
            
            print("    - [targets]: ")
            print("    - ", targets)
            print("    - [folders]: ")
            print("    - ", folders)
            print("    - [configs]: ")
            print("    - ", configs)
            print("    - [ip_addrs]: ")
            print("    - ", ip_addrs)
            print("    - [ipv6_addrs]: ")
            print("    - ", ipv6_addrs)
            print("    - [ports]: ")
            print("    - ", ports)
            print("    - [interfaces]: ")
            print("    - ", interfaces)
            print("    - [failed]: ")
            print("    - ", failed)
            print("    - [forkmap]: ")
            print("    - ", forkmap)
            
            ## test for success
            success = False
            wellformed = False
            connected = False
            success, wellformed, connected = checker.check(trace, exit_code, timedout, errored, self.strict)
            print("  - [connected]:", connected)
            print("  - [success]:", success)
            print("  - [wellformed]:", wellformed)

            # check for threading/child procs
            if subcount > 2:
                self.changelog.append("[ROADBLOCK] requires multi-threading/child-processes to handle server response")
                sublog = "    - %d subtargets" % (subcount-1)
                self.changelog.append(sublog)

            ## check for different root dir
            changed_cwd, bin_cwd = self.gh.check_cwd(self.fs_path, targets, bin_cwd, cwd_rh_replaced, success)

            # check for new ip/interfaces/ports
            ip_addrs.update(ipv6_addrs) # we currently handle ipv4 and ipv6 the same way via HACKBIND
            new_ips = self.gh.parse_ips(self.ip_targets_path, ip_addrs, self.urls)
            self.urls.extend(list(new_ips))
            new_ports = self.gh.parse_ports(self.ports_path, ports, self.ports)
            self.ports.extend(list(new_ports))

            # add new interfaces
            urls_with_interfaces, interface_cmds = self.gh.add_interfaces(interfaces, self.urls)
            new_ips += (set(urls_with_interfaces) - set(self.urls))
            self.urls = urls_with_interfaces

            # if daemon patch messes stuff up
            if not success and needs_dedaemon and len(nodaemon_args) > 0:
                if  ndflag_index < len(nd_flags):
                    print("    - trying a different nodaemon flag...")
                    nodaemon_args = nd_flags[ndflag_index]
                    ndflag_index += 1
                    count -= 1
                else:
                    print("    - nodaemon flag(s) cause issues, reverting...")
                    needs_dedaemon = False
                    nodaemon_args = ""
                    count -= 1
                continue

            if not success and testing_nodaemon_patch:
                print("    - nodaemon patch cause issues, reverting...")
                binary.restoreCount(count-1)
                testing_nodaemon_patch = False
                count -= 1
                continue


            print("    - [new_ips]: ")
            print("    - ", new_ips)
            print("    - [new mac]: ")
            print("    - ", last_mac == mac)
            print("    - [changed_cwd]: ")
            print("    - ", changed_cwd)
            
            # check for success
            if (len(new_ips) == 0 and last_mac == mac and not changed_cwd and \
                (self.partial_configs or len(configs) == 0 or configs == last_configs)):
                if success and not needs_nodaemon_patch: # no obvious transplants left and success was reached
                    if not greenhouse_mode:
                        print("    - rehost done, rerunning in greenhouse mode to finalize...")
                        greenhouse_mode = True
                        continue

                    # nodaemon flag guessing
                    if needs_dedaemon and is_daemonized and ndflag_index < len(nd_flags):
                        print("    - rehost done, trying to guess nodaemon flag...")
                        nodaemon_args = nd_flags[ndflag_index]
                        ndflag_index += 1
                        count -= 1
                        continue
                    elif needs_dedaemon and not is_daemonized:
                        print("    - nodaemon flag successful...")
                        needs_dedaemon = False
                    elif needs_dedaemon and ndflag_index == len(nd_flags):
                        print("    - unable to find nodaemon flag, engaging patcher...")
                        nodaemon_args = ""
                        needs_dedaemon = False
                        needs_nodaemon_patch = True
                        patcher = Patcher(whitelist="daemon_fork")
                        greenhouse_mode = False
                        continue

                    success_msg = "Success, filesystem runs!"
                    rehost_result = "SUCCESS"
                    if not wellformed:
                        success_msg = "Partial " + success_msg
                        rehost_result = "PARTIAL"
                    print(success_msg)

                    good_rh = firmae_success and self.rh_success and self.ps_success and self.cwd_success
                    print("firmae_success:", firmae_success, "self.rh_success:", self.rh_success, \
                          "self.ps_success:", self.ps_success, "self.cwd_success:", self.cwd_success)
                    if success and wellformed and good_rh and os.path.exists(self.target_cache_path):
                        # mark cached fullrehost result as good
                        success_tag = os.path.join(self.target_cache_path, GH_SUCCESS_TAG)
                        print("    - tagging %s as a good fullrehost" % self.target_cache_path)
                        Files.touch_file(success_tag)

                    break

            if self.baseline:
                print("    - baseline run complete.")
                break


            if greenhouse_mode and (self.max_cycles < 0 or count < self.max_cycles):
                ## greenhouse targets
                skipped = self.gh.transplant(self.fs_path, targets, folders, configs, failed, success, no_skip, self.hackdevproc, self.changelog)
                mac = self.gh.get_mac_from_nvrams(self.fs_path)
                nvram_ips = self.gh.get_ips_from_nvram()
                new_ips = self.gh.parse_ips(self.ip_targets_path, nvram_ips, self.urls)
                self.urls.extend(list(new_ips))

                ## repeat until no targets left or success reached
                # no further transplants possible
                if len(targets) == 0 and len(folders) == 0 and len(configs) == 0 and len(new_ips) == 0 and last_mac == mac and not changed_cwd:
                    # no transplants left but no success, engage patching
                    print("    - no transplants left to try, engage patching")
                    if greenhouse_mode or self.repeat:
                        greenhouse_mode = False
                        print("    - rerunning...")
                        continue # repeat with flag set
                    else:
                        # already in patch mode or not meant to repeat, end
                        print("    - cycle complete...")
                        return 0

                # break out of infinite greenhouse loop in case where greenhousing does not seem to change anything
                if not changed_cwd and last_mac == mac and len(new_ips) == 0: # no ips or cwd changes
                    if targets == last_targets and last_folders == folders and \
                       last_failed == failed and last_configs == configs: #attempted fs fixing failed, skip and continue anywayz
                        print("    - no change in failed cases despite greenhousing, skip to patching")
                        if greenhouse_mode or self.repeat:
                            greenhouse_mode = False
                            print("    - rerunning...")
                            continue # repeat with flag set
                        else:
                            # already in patch mode or not meant to repeat, end
                            print("    - cycle complete...")
                            return 0

                # further transplants possible, keep greenhousing
                if self.repeat:
                    print("    - rerunning...")
                    continue # otherwise keep greenhousing
                else:
                    print("    - cycle complete...")
                    return 0

            ## repeat until success, or no further Greenhouseing is possible / max cycles reached
            if self.max_cycles >= 0 and count >= self.max_cycles:
                print("[Greenhouse] !! MAX CYCLES %d REACHED !!" % count)
                if connected and not wellformed:
                    rehost_result = "PARTIAL"
                if self.batchfolder_path:
                    Files.rm_files([trace_path, trace_json_path])
                break

            ## first, try to obtain more configs from fullrehosting
            if not success and not fullrehosted and len(self.firmae_path) > 0:
                print("Attempting a fullrehost to fix issues...")
                new_run_args, cwdpath, firmae_success = self.apply_fullsystem_rehost()
                if firmae_success:
                    self.changelog.append("[ROADBLOCK] requires copying of full-system fs/nvram values/runtime args ")
                if len(new_run_args) > 0:
                    pslog = "    - replacing runtime extra args " + self.extra_args + " with " + new_run_args
                    print(pslog)
                    if self.extra_args.strip() != new_run_args.strip():
                        self.changelog.append("[ROADBLOCK] requires specific run time args")
                        self.changelog.append(pslog)
                    self.extra_args = new_run_args
                if len(cwdpath) > 0:
                    cwdlog = "    - replacing bin_cwd" + bin_cwd + "with" + cwdpath
                    print(cwdlog)
                    if bin_cwd.strip() != cwdpath.strip():
                        self.changelog.append("[ROADBLOCK] requires specified CWD for webserver binary")
                        self.changelog.append(cwdlog)
                        if firmae_success:
                            cwd_rh_replaced = True
                    bin_cwd = cwdpath
                success = False
                greenhouse_mode = True
                fullrehosted = True
                print("    - rerunning...")
                continue

            ## if no targets left and success not reached, attempt patch
            ## generate bintrunk of target binary
            trace_trunk_path, index = self.generate_bintrunk(trace_json_path, trace, always_rebuild=True)


            if not binary is None:
                binary.close()
            binary = Binary(self.bin_path, trace.base_addr, count=count)

            ## determine type of patch needed
            ## 1) patch out a wait loop
            ## 2) dodge an exit
            ## 3) patch out a crashing instruction/exit jump
            ## perform appropriate patch
            if len(trace_trunk_path) <= 0 or \
                not patcher.diagnose_and_patch(binary, self.bintrunk, trace, trace_trunk_path, index, exit_code, \
                                              timedout, errored, is_daemonized, skip=self.diagnose_only, changelog=self.changelog):
                if needs_nodaemon_patch:
                    # revert
                    print("    - unable to patch daemon call, reverting...")
                    greenhouse_mode = True
                    needs_nodaemon_patch = False
                    count -= 1
                    continue
                else:
                    # unable to patch
                    print("No patch successful")
                    self.changelog.append("[Greenhouse] No patch successful")
                    if self.batchfolder_path:
                        Files.rm_files([trace_path, trace_json_path])
                    break

            ## rerun outer loop, including checking for new files and nvrams
            greenhouse_mode = True
            if needs_nodaemon_patch:
                testing_nodaemon_patch = True
                needs_nodaemon_patch = False

            if self.repeat:
                print("    - rerunning...")
                continue
            else:
                if self.batchfolder_path:
                    Files.rm_files([trace_path, trace_json_path])
                print("    - cycle complete...")
                return 0

        print("[Greenhouse] Rehosting Complete, exiting...")

        if connected and not wellformed:
            rehost_result = "PARTIAL"

        self.write_changelog(self.changelog)
        if self.batchfolder_path:
            Files.rm_files([trace_path, trace_json_path])
        if self.output_dst_path and rehost_result != "FAILED":
            output_dir = self.name
            output_dir_path = os.path.join(self.output_dst_path, output_dir)
            print("."*50)
            print(" - copying modified fs to target directory: %s" % output_dir_path)
            print("."*50)
            self.runner.export_current_dockerfs(output_dir_path, result=rehost_result, name=output_dir, brand=self.brand, hash=self.sha256hash, \
                                                checker=checker, external_qemu=self.external_qemu, urls=self.urls, time_to_up=time_to_up)
            Files.rm_folder(self.workspace)
            Files.mkdir(self.workspace)
        else:
            print("."*50)
            print(" - Rehost Failed, skipping copying of fs")
            print("."*50)
        
        #exit
        print("="*50)
        print("[GREENHOUSE] RUN FINISH ", time.ctime())
        totaltime = time.time() - starttime
        print("[GREENHOUSE] TIME TAKEN = ", (totaltime / 60), "mins")
        print("[GREENHOUSE] REHOST STATUS - %s: %s" % (self.sha256hash, rehost_result))
        print("="*50)
        if success and wellformed:
            return 0
        return 1


def main():
    parser = argparse.ArgumentParser(description='given an firmware image and target, generate and patch a runnable instance of the firmware')
    parser.add_argument('--img_path', default="",
                    help='path to the image file to be extracted, not compatible with batchrun mode')
    parser.add_argument('--fs_path', default="",
                    help='path to an existing filesystem that has already been extracted, overwrites --img_path, not compatible with batchrun')
    parser.add_argument('--batchfolder', default="",
                    help='path to the root directory to batch run on, not compatible with img_path')
    parser.add_argument('--ip', default="172.20.0.2",
                    help='ip address for testing connections')
    parser.add_argument('--ports', default="80",
                    help='comma-seperated list of port(s) for testing connections')
    parser.add_argument('--skipfile', default="",
                    help='path to file containing a skiplist of filepaths to ignore')
    parser.add_argument('--brand', default="",
                    help='brand of target firmware. If not provided, will derive brand from the folder name of target')

    parser.add_argument('--target_bin', default="",
                    help='path to the target binary (manual override)')
    parser.add_argument('--bin_args', default="",
                    help='additional arguments to pass to the binary (manual override)')
    parser.add_argument('--timeout', type=int, default=5,
                    help='num seconds to simulate the target binary in qemu before timeout (default 20mins)')
    parser.add_argument('--max_depth', type=int, default=-1,
                    help='maximum bintrunk context-sensitive cfg to construct')
    parser.add_argument('--max_cycles', type=int, default=30,
                    help='maximum number of patch cycles to attempt before giving up')
    parser.add_argument('--rehost_type', default="HTTP",
                    help='type of protocol binary to target [HTTP/UPNP/DNS/DHCP]')

    parser.add_argument('--cache_path', default="/tmp/cache",
                    help='path to folder to cache fullrehost results')
    parser.add_argument('--workspace', default="/tmp/workspace",
                    help='path to work folder where extracted images are placed')
    parser.add_argument('--outpath', default="/tmp/outpath",
                    help='path to the output folder containing all the results to be generated. leave empty if no save folder is needed')
    parser.add_argument('-l', '--logpath', default="/tmp/logpath",
                    help='specify filepath to place logging info for roadblocks/interventions encountered')
    parser.add_argument('--firmae', default="",
                    help='path to the firmae folder, if non-empty attempts to use firmae to further patch fs')
    
    parser.add_argument('-bl', '--baseline', action="store_true", default=False,
                        help='enables baseline rehosting - only chroot and emulate')
    parser.add_argument('-v', '--verbose', action="store_true", default=False,
                        help='activate verbose construction of BinTrunk CFG graph')
    parser.add_argument('-bt', '--bintrunk', action="store_true", default=False,
                        help='only construct bintrunk and graph for human use')
    parser.add_argument('-md', '--make_dot', action="store_true", default=False,
                        help='generate a .dot graph with colored traces and sinks for human viewing.')
    parser.add_argument('-dg', '--diagnose', action="store_true", default=False,
                        help='diagnose only. Will suggest patches but not apply them.')
    parser.add_argument('-rh', '--rehost_first', action="store_true", default=False,
                        help='always attempt full rehosting using FirmAE first before patch loop.')
    parser.add_argument('-pc', '--partial_configs', action="store_true", default=False,
                        help='just run until a wellformed webpage, do not further iterate for better nvram/configs')
    
    # flags to disable stuff
    parser.add_argument('-nf', '--nofullrehosting', action="store_true", default=False,
                        help='disable full rehosting')
    parser.add_argument('-nr', '--norepeat', action="store_true", default=False,
                        help='run patch loop until success or no patch possible. Otherwise, patch loop only runs once')
    parser.add_argument('-ns', '--nostrict', action="store_true", default=False,
                        help='strict patching - keep trying until HTTP return code is 200 and well-formed')
    parser.add_argument('-nd', '--nodedaemon', action="store_true", default=False,
                        help='try to find and run nodaemon flags')
    parser.add_argument('-nb', '--nohack_bind', action="store_true", default=False,
                        help='disables hack bind')
    parser.add_argument('-np', '--nohack_devproc', action="store_true", default=False,
                        help='disables hack dev and proc')
    parser.add_argument('-ni', '--nohack_sysinfo', action="store_true", default=False,
                        help='disables hack sysinfo')
    parser.add_argument('-nc', '--nocleanupfirmae', action="store_true", default=False,
                        help='disable cleanup after each fullrehosting attempt')

    args, unknownargs = parser.parse_known_args()


    ff = Greenhouse(args)
    ret = 0
    if args.batchfolder == "":
        if args.img_path == "" and args.fs_path == "":
            parser.print_help()
        else:
            ret = ff.run(args.img_path)
    else: # batch mode
        ff.batchrun(args.batchfolder)

    exit(ret)

main()
