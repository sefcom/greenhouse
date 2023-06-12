from . import *
import os, stat, subprocess
from subprocess import Popen, PIPE

import re
import struct
import telnetlib
from telnetlib import DO, DONT, IAC, WILL, WONT, NAWS, SB, SE
import socket, select
import time
import getpass
import psutil
import datetime
import psutil
import pwn

TARGET_FS = b"targetfs"
TMPFS = b"tmpfs"
EXTRACT_SCRIPT = "extract_fs.sh"

# if "FIRMAE_DOCKER" in os.environ.keys():
#     SUDO_CMD = []
# else:
SUDO_CMD = ["sudo"]
MAX_WINDOW_WIDTH = 65000  # Max Value: 65535
MAX_WINDOW_HEIGHT = 5000


class FirmAEwrapper:
    def __init__(self, binary, brand, firmae_path, mount_path, scripts_path, analysis_path, bg_scripts, firmae_address="", firmae_port=31338):
        self.firmae_path = firmae_path
        self.scripts_path = scripts_path
        self.analysis_path = analysis_path
        self.addr = firmae_address
        self.port = firmae_port
        self.mountdir = mount_path
        self.binary = binary
        self.brand = brand
        self.ps_map = dict()
        self.bg_scripts = bg_scripts

    def run_firmae(self, target_path, cleanup_firmae=False):
        if len(SUDO_CMD) > 0:
            print("Check sudo...")
            subprocess.call(["sudo", "-v"])
            print("checked!")

        self.clear_lo()

        firmae_run = os.path.join(self.firmae_path, "run.sh")
        target_type = self.brand
        IID = ""

        if not os.path.exists(firmae_run):
            print(firmae_run, "does not exist!")
            return -1
        if not os.path.exists(target_path):
            print(target_path, "does not exist!")
            return -1

        if cleanup_firmae:
            self.clear_firmware_cache()
        curr_dir = os.getcwd()
        os.chdir(self.firmae_path)

        firmae_cmd = []
        firmae_cmd.extend(SUDO_CMD)
        firmae_cmd.extend([firmae_run, "-d", target_type, target_path])
        print("Running", firmae_cmd)
        start = time.time()
        print("    - time: ", datetime.datetime.now())

        r = subprocess.Popen(firmae_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        os.chdir(curr_dir)
        firmaedbg_up = False
        run_telnet = False
        success = False
        telnet_up = False
        initialized = False
        has_web = False
        start_time = 0
        initialized_time = 0
        bgcmds = []
        TIMEOUT = 3600 # seconds, should not take over an hour

        while True:
            try:
                output = r.stdout.readline()
                if output == b'' and r.poll() is not None:
                    print("Firmae Exited")
                    break
                if initialized_time != 0:
                    time_passed = time.time() - initialized_time
                    if time_passed > TIMEOUT:
                        print("Initialization TIMEOUT, attempt to connect anyway...")
                        run_telnet = True
                if output:
                    print(output.strip())
                    if b'FirmAE IID:' in output:
                        IID = output.split(b":")[1].strip()
                        IID = IID.decode("utf-8").strip()
                    if b"Web service on" in output:
                        has_web = True
                    if b"infer network start!!!" in output:
                        # get binary list and bgcmds
                        if IID != "":
                            fileList = []
                            binListPath = os.path.join(self.firmae_path, "scratch", IID, "fileList")
                            if os.path.exists(binListPath):
                                print("    - setting up bg script data using fileList", binListPath)
                                with open(binListPath, "r") as listFile:
                                    for line in listFile:
                                        fileList.append(line.strip())
                                listFile.close()
                                for name, bg in self.bg_scripts.items():
                                    cmds = bg.get_fullsystem_cmds(fileList, TMPFS.decode('utf-8'))
                                    if len(cmds) > 0:
                                        print("    - [+] using", name)
                                    bgcmds.extend(cmds)
                                print("    - done!")
                                print(b"continue inferring network...")
                                start_time = time.time()
                                time.sleep(10)
                                continue
                    if b"connecting to netcat" in output:
                        addrport = output.split(b"(")[1].strip().strip(b")")
                        array = addrport.split(b":")
                        self.addr = array[0].strip()
                    if b'6. exit' in output:
                        run_telnet = True
                    if firmaedbg_up and run_telnet:
                        if not initialized:
                            self.firmae_initialize()
                            time.sleep(1)
                            initialized = True
                        if not telnet_up:
                            # setup shell for telnet
                            print("Setting up telnet")
                            r.stdin.write(b"2\n")
                            r.stdin.flush()
                            time.sleep(1)
                            r.stdin.write(b"exit\n")
                            r.stdin.flush()
                            time.sleep(1)
                            telnet_up = True
                            continue
                        if initialized: # and telnet_up:
                            # connect to firmae using own script
                            print("Connecting to emulation")
                            time_passed = (time.time() - start_time) / 60 # mins
                            print("    - time taken since started inferring: %smins" % time_passed)
                            success = False
                            if telnet_up:
                                success = self.connect_and_save(self.addr, self.port, bgcmds)
                            if not success:
                                success = self.socat_and_save(IID, bgcmds)
                                time.sleep(1)
                            r.stdin.write(b"6\n")
                            r.stdin.flush()
                            r.stdout.flush()
                            telnet_up = False
                            self.check_shutdown()
                            print("Firmae Done")
                            break
                    if b'FirmAE Debugger' in output:
                        firmaedbg_up = True
            except Exception as e:
                print(e)
                break
        
        print("Run FirmAE complete")
        print("    - time: ", datetime.datetime.now())
        end = time.time()
        print("    - duration: ", end - start)
        return IID, success, has_web

    def print_process_pid(self):
        # Iterate over all running process
        print('-'*50)
        print("Running processes:")
        for proc in psutil.process_iter():
            try:
                # Get process name & pid from process object.
                processName = proc.name()
                processID = proc.pid
                print(processName , ' ::: ', processID)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        print('-'*50)

    def socat_read_until(self, sc, until):
        r = b""
        while until not in r:
            buf = sc.recv(timeout=5)
            if not buf:
                break
            r += buf
        return r
        # return sc.recvuntil(until, timeout=5)

    def socat_sendall(self, sc, buf):
        buf = buf.decode("utf-8").strip("\n")
        for c in buf:
            sc.send(c.encode("utf-8"))
            time.sleep(0.1)
        sc.sendline(b"")

    def socat_send_recv(self, sc, buf):
        for i in range(3):
            self.socat_sendall(sc, buf)
            time.sleep(1)
            r = self.socat_read_until(sc, b"#")
            print(r)
            if b"No such" in r or b"not found" in r:
                self.socat_sendall(sc, b"\n")
                time.sleep(1)
                r = self.socat_read_until(sc, b"#")
                continue
            if r.endswith(b">"):
                self.socat_sendall(sc, b"\`")
                r = self.socat_read_until(sc, b"#")
                time.sleep(1)
                self.socat_sendall(sc, b"\n")
                time.sleep(1)
                r = self.socat_read_until(sc, b"#")
                continue

            return r


    def socat_and_save(self, IID, bgcmds):
        mkdir_cmd = b"/firmadyne/busybox mkdir %s\n" % TMPFS
        ps_cmd = b"/firmadyne/busybox ps > %s/ps.log\n" % TMPFS
        cp_cmd = b"/firmadyne/busybox cp -r -R `/firmadyne/busybox ls | /firmadyne/busybox egrep -v 'proc|tmpfs|firmadyne|sys|lib'` %s\n" % TMPFS
        sync_cmd = b"/firmadyne/busybox sync\n"
        filter_ps = b"/firmadyne/busybox ps | /firmadyne/busybox grep %s | /firmadyne/busybox grep -v grep\n" % self.binary.encode("utf-8")
        success = False


        time.sleep(1)
        subprocess.run(["sudo", "chmod", "-R", "a+rwx", "/tmp/qemu."+str(IID)+".S1"])
        time.sleep(1)

        try:
            # sc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # sc.settimeout(60)
            # sc.connect("/tmp/qemu."+str(IID)+".S1")
            sc = pwn.process(["socat", "-", "UNIX-CLIENT:/tmp/qemu."+str(IID)+".S1"])
            time.sleep(1)
            self.socat_sendall(sc, b"\n")
            time.sleep(1)
            r = self.socat_read_until(sc, b"#")
            print(r)

            print("    - Socat ready, performing connect and save...")
            r = self.socat_send_recv(sc, b"ls\n")
            time.sleep(1)
            
            r = self.socat_send_recv(sc, mkdir_cmd)
            time.sleep(1)

            print("\n      # copying dirs...\n")
            r = self.socat_send_recv(sc, cp_cmd)
            time.sleep(1)

            print("\n      # sync...\n")
            r = self.socat_send_recv(sc, sync_cmd)
            time.sleep(1)

            print("\n      # getting ps logs...\n")
            r = self.socat_send_recv(sc, ps_cmd)
            time.sleep(1)

            print("\n      # sync...\n")
            r = self.socat_send_recv(sc, sync_cmd)
            time.sleep(1)

            print("\n      # getting pid for binary...\n")
            r = self.socat_send_recv(sc, filter_ps)
            time.sleep(1)
            print("\n      # getting cwd for binary...\n")
            lines = r.splitlines()
            for line in lines:
                print(b"LINE:", line)
                if self.binary.encode("utf-8") not in line:
                    continue
                array = line.split()
                if len(array) > 3 and array[3].split(b"/")[-1].strip() == self.binary.encode("utf-8"):
                    pid = array[0]
                    print("\n      # PID: %s\n" % pid)
                    get_cwd_cmd = b"ls -l /proc/%s/cwd > %s/cwd.log\n" % (pid, TMPFS)
                    r = self.socat_send_recv(sc, get_cwd_cmd)
                    time.sleep(1)
                    break
            # time.sleep(1)
            # r = self.socat_read_until(sc, b"#")
            # print(r)
            # do side functions
            print("\n      # running background script commands\n")
            for cmd in bgcmds:
                print("    - sending:", cmd )        
                r = self.socat_send_recv(sc, cmd)
                time.sleep(1)
            # r = self.socat_read_until(sc, b"#")
            # print(r)
            # sync tmpfs
            print("\n      # checking tmpfs folder...\n")        
            r = self.socat_send_recv(sc, b"ls tmpfs\n")
            time.sleep(1)
            lines = r.splitlines()
            for line in lines:
                print(b"LINE:", line)
            r = self.socat_send_recv(sc, sync_cmd)
            time.sleep(1)
            print(r)
            success = True
        except ConnectionRefusedError as e:
            print("    - Socat Connection refused")
            print(e)
            success = False
        except socket.timeout as e:
            print("    - Socat Timed Out")
            print(e)
            success = False
        except IOError as e:
            print("    - IO Error")
            print(e)
            success = False
        except EOFError as e:
            print("    - Socat EOF")
            print(e)
            
        print("...done, exit socat")
        sc.kill()
        # for proc in psutil.process_iter():
        #     if "socat" in proc.name():
        #         pid = proc.pid
        #         print("    - killing", pid)
        #         subprocess.call(["kill", "-9", pid])
        # print("\n      # exit...\n")
        # time.sleep(1)
        # self.socat_sendall(sc, exit_cmd)
        # r = self.socat_read_until(sc, b"#")
        # print(r)
        # success = True
        # tn.read_all()
        return success

    def connect_and_save(self, target_ip, target_port, bgcmds):
        mkdir_cmd = b"/firmadyne/busybox mkdir %s\n" % TMPFS
        ps_cmd = b"/firmadyne/busybox ps > %s/ps.log\n" % TMPFS
        cp_cmd = b"/firmadyne/busybox cp -r -R `/firmadyne/busybox ls | /firmadyne/busybox grep -v proc | /firmadyne/busybox grep -v tmpfs | /firmadyne/busybox grep -v firmadyne | /firmadyne/busybox grep -v sys | /firmadyne/busybox grep -v lib` %s\n" % TMPFS
        tar_cmd = b"/firmadyne/busybox tar -cf %s.tar %s\n" % (TMPFS, TMPFS)
        exit_cmd = b"/firmadyne/busybox poweroff\n"
        sync_cmd = b"/firmadyne/busybox sync\n"
        filter_ps = b"/firmadyne/busybox ps | /firmadyne/busybox grep %s | /firmadyne/busybox grep -v grep\n" % self.binary.encode("utf-8")
        resize_command = struct.pack('!BBBHHBB', 255, 250, 31, 600, 200, 255, 240)  # IAC SB NAWS + width + height + IAC SE
        success = False

        tn = telnetlib.Telnet()
        if not tn:
            print("    - Telnet failed")
            return success
        try:
            time.sleep(2)
            print("    - Telnet ready, performing connect and save on %s:%s..." % (target_ip.decode("utf-8"), target_port))
            tn.open(target_ip, target_port)
            # https://stackoverflow.com/questions/11575558/is-it-possible-to-send-resize-pty-command-with-telnetlib
            # resize screen
            tn.get_socket().send(resize_command)
            i, m, r = tn.expect([b"#"], 5)
            tn.write(mkdir_cmd)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            print(r)
            print("\n      # copying dirs...\n")
            tn.write(cp_cmd)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            print(r)
            print("\n      # sync...\n")
            tn.write(sync_cmd)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            r += tn.read_until(b"#", 1)
            print(r)
            print("\n      # getting ps logs...\n")
            tn.write(ps_cmd)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            print(r)
            r = tn.read_until(b"#", 1)
            print(r)
            print("\n      # sync...\n")
            tn.write(sync_cmd)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            r += tn.read_until(b"#", 1)
            print(r)
            print("\n      # getting pid for binary...\n")
            tn.write(filter_ps)
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            r += tn.read_until(b"#", 1)
            print(r)
            print("\n      # getting cwd for binary...\n")
            lines = r.splitlines()
            for line in lines:
                print(b"LINE:", line)
                if self.binary.encode("utf-8") not in line:
                    continue
                array = line.split()
                if len(array) > 3 and array[3].split(b"/")[-1].strip() == self.binary.encode("utf-8"):
                    pid = array[0]
                    print("\n      # PID: %s\n" % pid)
                    get_cwd_cmd = b"ls -l /proc/%s/cwd > %s/cwd.log\n" % (pid, TMPFS)
                    tn.write(get_cwd_cmd)
                    i, m, r = tn.expect([b"#"], 5)
                    print(r)
                    break
            time.sleep(1)
            r = tn.read_until(b"#", 1)
            print(r)
            # do side functions
            print("\n      # running background script commands\n")
            for cmd in bgcmds:                
                tn.write(cmd)
                time.sleep(1)
                r = tn.read_until(b"#", 1)
                print(r)
            # sync tmpfs
            print("\n      # checking tmpfs folder...\n")
            tn.write(b"ls tmpfs; /firmadyne/busybox sync\n")
            time.sleep(1)
            i, m, r = tn.expect([b"#"], 5)
            lines = r.splitlines()
            for line in lines:
                print(b"LINE:", line)
            time.sleep(1)
            r = tn.read_lazy()
            print(r)
            print("\n      # exit...\n")
            time.sleep(1)
            tn.write(exit_cmd)
            success = True
            r = tn.read_lazy()
            print(r)
            # tn.read_all()
        except ConnectionRefusedError as e:
            print("    - Telnet Connection refused")
            print(e)
            success = False
        except socket.timeout as e:
            print("    - Telnet Timed Out")
            print(e)
            success = False
        except IOError as e:
            print("    - IO Error")
            print(e)
            success = False
        except EOFError as e:
            print("    - Telnet EOF")
            print(e)

        print("    - Done!")
        tn.close()
        return success

    def firmae_initialize(self):
        old_environ = os.environ['PATH']
        os.environ['PATH'] = self.analysis_path + ':' + os.environ['PATH']
        init_script = os.path.join(self.firmae_path, "analyses", "initializer.py")
        init_cmd = ([init_script, self.brand, self.addr])
        print("-"*50)
        print("Initializing...")
        subprocess.run(init_cmd, timeout=3600)
        print("done.")
        print("-"*50)
        os.environ['PATH'] = old_environ

    def clear_firmware_cache(self):
        cache_path = os.path.join(self.firmae_path, "scratch")
        if os.path.exists(cache_path):
            rm_cmd = []
            rm_cmd.extend(SUDO_CMD)
            rm_cmd.extend(["rm", "-r", cache_path])
            print(rm_cmd)
            print("Clearing cache", cache_path)
            subprocess.call(rm_cmd)
        Files.mkdir(cache_path)


    def mount_and_cache_fs(self, IID, firmae_folder, cache_folder, protected=[]):
        imgpath = os.path.join(firmae_folder, "scratch", str(IID), "image.raw")
        targetfs_path = os.path.join(firmae_folder, TARGET_FS.decode('utf-8'))
        tmpfs_path = os.path.join(targetfs_path, TMPFS.decode('utf-8'))
        extract_path = os.path.join(self.scripts_path, EXTRACT_SCRIPT)
        extract_cmd = [extract_path, imgpath, targetfs_path, tmpfs_path, cache_folder]

        print("    - caching files in %s" % cache_folder)
        print("      with files from %s" % tmpfs_path)
        print("      using image %s" % imgpath)
        sp = subprocess.run(extract_cmd, stdout=PIPE, stderr=PIPE)
        stdout = sp.stdout
        print("    - extracting...")
        for line in stdout.splitlines():
            print(line)

        # do not cache files that are protected
        for protected_target in protected:
            protected_target_path = os.path.join(cache_folder, protected_target)
            print("    - protecting", protected_target)
            if os.path.exists(protected_target_path):
                Files.rm_target(protected_target_path)

    def get_cwd(self, fs_path):
        cwdinfo_path = os.path.join(fs_path, "cwd.log")
        if not os.path.exists(cwdinfo_path):
            print("    - !! ERROR !! cwd.log not found")
            return None
        cwdline = ""
        with open(cwdinfo_path, "rb") as cwdFile:
            cwdline = cwdFile.read()
        cwdFile.close()

        if len(cwdline) > 0:
            if b"->" in cwdline:
                cwdPath = cwdline.rsplit(b"->", 1)[1].strip()
                return cwdPath.decode("utf-8")
        print("     - no cwdpath found in cwd.log!")
        return None

    def update_ps(self, fs_path):
        ps_path = os.path.join(fs_path, "ps.log")

        if not os.path.exists(ps_path):
            print("    - !! ERROR !! ps.log not found")
            return False
        print("    - reading ps.log")
        self.ps_map = dict()
        skip = True
        with open(ps_path, "rb") as psFile:
            for line in psFile:
                print(b"    - ", line)
                if skip: # skip first line
                    skip = False
                    continue
                line = line.decode("utf-8", errors="ignore")
                fields = line.split()
                if len(fields) <= 3:
                    continue
                binary = fields[3].strip()
                args = ""
                if len(fields) > 4:
                    args = fields[4:]
                # we only get the first instance of a binary in order they appear in the ps output
                # in the case there are multiple of the same binary we assume the earlier one is correct
                if binary not in self.ps_map.keys():
                    self.ps_map[binary] = args
        psFile.close()
        return True

    def get_run_args(self, fs_path, binary):
        if len(self.ps_map.keys()) <= 0:
            self.update_ps(fs_path)
        print("ps map")
        print(self.ps_map)

        print("    - looking for binary \"%s\" in ps.log" % binary)
        for ps, args in self.ps_map.items():
            # if binary in ps:
            if os.path.basename(ps).strip() == binary:
                print("    - found", ps, args)
                return True, " ".join(args).strip().replace("(", "\\(").replace(")", "\\)")
        return False, ""

    def clear_lo(self):
        script_path = os.path.join(self.scripts_path, "cleanup_lo.sh")
        script_cmd = []
        script_cmd.extend(SUDO_CMD)
        script_cmd.extend([script_path])
        subprocess.call(script_cmd)


    def cleanup_IID(self, IID):
        if len(IID) <= 0:
            print("    - no such IID [%s], skip" % IID)
            return
        curr_dir = os.getcwd()
        os.chdir(self.firmae_path)
        script_path = os.path.join(self.firmae_path, "scripts", "delete.sh")
        script_cmd = []
        script_cmd.extend(SUDO_CMD)
        script_cmd.extend([script_path, str(IID)])
        subprocess.call(script_cmd)
        os.chdir(curr_dir)

    def update_bg_scripts(self, fs_path, bg_scripts):
        for binpath in bg_scripts.keys():
            bin_name = os.path.basename(binpath)
            found_ps, new_args = self.get_run_args(fs_path, bin_name)
            if len(new_args) > 0:
                print("    - updating bgscript [%s] with args %s" % (binpath, new_args))
                bg_scripts[binpath] = new_args
        return found_ps

    def force_kill_firmae(self):
        time.sleep(2)
        kill_path = os.path.join(self.scripts_path, "kill_firmae.sh")
        kill_cmd = []
        kill_cmd.extend(SUDO_CMD)
        kill_cmd.extend([kill_path, str(pid)])
        for proc in psutil.process_iter():
            if "run.sh" in proc.name() and "firmae" in proc.name():
                pid = proc.pid
                subprocess.call(kill_cmd)

    def check_shutdown(self):
        chk_path = os.path.join(self.scripts_path, "check_shutdown.sh")
        check_cmd = [chk_path]
        try:
            ret_code = subprocess.run(check_cmd, timeout=30)
        except Exception as e:
            print("Exception occured while checking for shutdown")
            print(e)
            return False
        print("...FirmAE Shutdown confirmed!")
        return True


    def extract_lognvram(self, qemu_serial_logpath, ):
        print("         # parsing %s for nvram values" % qemu_serial_logpath)
        nvram_tags = set()
        nvram_map = dict()

        if not os.path.exists(qemu_serial_logpath):
            print("         - %s does not exist, skipping...!" % qemu_serial_logpath)
            return

        with open(qemu_serial_logpath, "rb") as qemuFile:
            count = 0
            for line in qemuFile:
                count += 1
                if b"nvram_" in line:
                    tag = line.split(b":")[0].strip()
                    nvram_tags.add(tag)
                if str(line).count("\\x") > 3:
                    continue
                if len(line) > 200:
                    continue
                if b"nvram_set" in line or b"nvram_match" in line:
                    line = line.decode("ascii", errors="ignore")
                    if ":" in line and "=" in line:
                        line = ''.join(c for c in line if c.isprintable())
                        content = line.split(":", 1)[1].strip()
                        parsed = content.split("=")
                        if len(parsed) >= 2:
                            key = parsed[0].strip().strip("\"")
                            if " " in key:
                                continue
                            value = parsed[1].strip().strip("\"")
                            if "sem_get:" in value:
                                index = value.find("sem_get")
                                value = value[:index]
                            if ": " in value:
                                index = value.find(": ")
                                value = value[:index]
                            if "[  " in value:
                                index = value.find("[  ")
                                value = value[:index]
                            value = value.strip().strip("\"")
                            # print("        - found Key: %s = Value: %s" % (key, value))
                            if key not in nvram_map.keys() or value != "":
                                nvram_map[key] = value
                        else:
                            print("Unable to parse nvram value for line:", line)
        qemuFile.close()

        print("         # nvram extraction complete")
        return nvram_map