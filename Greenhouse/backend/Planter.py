from telnetlib import IP
from . import *

import os, shutil, stat, getpass
import subprocess
from subprocess import Popen, PIPE
import pathlib
import ipaddress
import re
import time
import ipaddress
import string
import angr
import ifaddr



WEBROOTS = ["www", "www.eng" "web", "webs"]
WEB_EXTS = ["html", "htm", "xhtm", "jhtm", "cgi", "xml", "js", "wss", "php", "php4", "php3", "phtml", \
            "rss", "svg", "dll", "asp", "aspx", "axd", "asx", "asmx", "ashx", "cfm", "swf"]
BACKUP_TAGS = ["bak", "bak2", "bkup"]
POTENTIAL_HTTPSERV = ["httpd", "uhttpd", "lighttpd", "jjhttpd", "shttpd", "thttpd","minihttpd", "mini_httpd", \
                    "mini_httpds", "dhttpd", "alphapd", "goahead", "boa", "appweb", "shgw_httpd", \
                    "tenda_httpd", "funjsq_httpd", "webs", "hunt_server", "hydra"]
POTENTIAL_UPNPSERV = ["miniupnpd", "miniupnpc", "mini_upnpd", "miniupnpd_ap", "miniupnpd_wsc", \
                      "upnp", "upnpc", "upnpd", "upnpc-static", "upnprenderer", \
                      "bcmupnp", "wscupnpd", "upnp_app", "upnp_igd", "upnp_tv_devices"]
POTENTIAL_DNSSERV = ["ddnsd", "dnsmasq"]
POTENTIAL_DHCPSERV = ["udhcpd", "dnsmasq"]
BACKGROUND_SCRIPTS = {"xmldb" : "-n gh_xml_root_node -t", "userconfig" : ""}
GH_BUSYBOX = "busybox"
GH_IP = "ip"
GREENHOUSE = "greenhouse"
NVRAM_FOLDER = "libnvram_faker"
NVRAM_FAKER_LIB = "libnvram-faker.so"
NVRAM_INIT = "nvram.ini"
NVRAM_KEY_VALUE_FOLDER = "gh_nvram"
NVRAM_IP_KEYS = ["ip_addr", "ipaddr"]
RAND = "8467206204610564372101238468369273619216273019100147216372162374"*100 # "random number" string for 'entropy'
MUSL_LD_DEFAULT = "/lib:/usr/local/lib:/usr/lib"
ARCH_MAP = {"arm": "qemu-arm-static",
                        # "armeb32": "qemu-armeb-static",
                        # "arm64": "qemu-aarch64-static",
                        # "armeb64": "qemu-aarch64_be-static",
                         "x86": "qemu-i386-static",
                        # "x86_64": "qemu-x86_64-static",
                         "mips": "qemu-mips-static",
                         "mipsel": "qemu-mipsel-static",
                        # "mips64": "qemu-mips64-static",
                        # "mips64el": "qemu-mips64el-static",
                        }
RESERVED_IPS = ["0.0.0.0", "127.0.0.1", "1.1.1.1", "1.0.0.1"]
PORTS_BLACKLIST = ['0', '22']
MAC_NVRAM_KEYS = ["lan_hwaddr"]

class Fixer():
    def __init__(self, qemu_src_path, gh_path, scripts_path, brand, baseline_mode):

        self.qemu_src_path = qemu_src_path
        self.qemu_run_path = ""
        self.scripts_path = scripts_path
        self.gh_path = gh_path
        self.nvram_faker_path = os.path.join(self.gh_path, NVRAM_FOLDER)
        self.nvram_init_path = ""
        self.nvram_key_value_path = ""
        self.nvram_map = dict()
        self.nvram_brand_map = dict()
        self.qemu_arch = None
        self.arch = None
        self.brand = brand
        self.clib = "glibc" # default
        self.baseline_mode = baseline_mode

    def initial_setup(self, fs_path, binary_path):

        # get architecture involved
        full_path = os.path.join(fs_path, binary_path)
        full_path = str(pathlib.Path(full_path).resolve()) # handle symlinks
        print("Checking binary at ", full_path)
        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
        stdout = sp.stdout
        print("    - ", stdout)
        self.arch = Fixer.get_arch_from_file_command(stdout)
        self.clibc = Fixer.get_clib_from_file_command(stdout)
        if self.arch is None:
            print("    - ERROR: unsupported arch", stdout)
            return False
        self.qemu_arch = ARCH_MAP[self.arch]

        # copy relevant qemu static
        self.qemu_run_path = self.copy_qemu_user_static(self.arch, fs_path)

        #chmod +rw entire directory so its editable
        sp = subprocess.run(["chmod", "-R", "a+rw", fs_path])

        # copy statically compiled helper binaries
        greenhousePath = os.path.join(fs_path, GREENHOUSE)
        iproutePath = os.path.join(self.gh_path, GH_IP)
        busyboxPath = os.path.join(self.gh_path, GH_BUSYBOX)
        iprouteDest =os.path.join(fs_path, GREENHOUSE, GH_IP)
        busyboxDest =os.path.join(fs_path, GREENHOUSE, GH_BUSYBOX)
        Files.mkdir(greenhousePath)
        Files.copy_file(iproutePath, iprouteDest)
        Files.copy_file(busyboxPath, busyboxDest)
        Files.touch_file(os.path.join(fs_path, "GREENHOUSE_WEB_CANARY"), root=fs_path) # create index page 'canary'

        #chmod +x
        sp = subprocess.run(["chmod", "+x", self.qemu_run_path])
        sp = subprocess.run(["chmod", "+x", full_path])

        # initial environment setup
        self.setup_devfiles(fs_path)
        self.remove_reboots(fs_path)
        if not self.baseline_mode:
            self.setup_custom_libraries(fs_path)
        self.propgate_contents(fs_path)

        return True

    def setup_devfiles(self, fs_path):
        # setup dev files
        print("    - setup /dev and /ghdev files")
        Files.rm_target(os.path.join(fs_path, "dev", "null"))
        Files.rm_target(os.path.join(fs_path, "dev", "urandom"))
        Files.rm_target(os.path.join(fs_path, "dev", "random"))
        Files.touch_file(os.path.join(fs_path, "dev", "null"), root=fs_path, silent=True) # empty file
        Files.write_file(os.path.join(fs_path, "dev", "urandom"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.write_file(os.path.join(fs_path, "dev", "random"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.copy_directory(os.path.join(fs_path, "dev"), os.path.join(fs_path, "ghdev"))
        Files.copy_directory(os.path.join(fs_path, "proc"), os.path.join(fs_path, "ghproc"))
        Files.mkdir(os.path.join(fs_path, "ghtmp"))

        setup_dev_path = os.path.join(self.gh_path, "setup_dev.sh")
        setup_dev_dest = os.path.join(fs_path, "setup_dev.sh")
        Files.copy_file(setup_dev_path, setup_dev_dest)

    def remove_reboots(self, fs_path):
        # setup dev files
        print("    - removing reboot and shutdown scripts")
        reboot_files = self.find_files("reboot", fs_path, resolve_symlinks=False)
        shutdown_files = self.find_files("shutdown", fs_path, resolve_symlinks=False)
        dummy_script_path = os.path.join(self.gh_path, "dummy.sh")

        for rf in reboot_files:
            Files.rm_target(rf)
            Files.copy_file(dummy_script_path, rf)

        for sf in shutdown_files:
            Files.rm_target(sf)
            Files.copy_file(dummy_script_path, sf)


    def propgate_contents(self, fs_path):
        #NOTE: currently mostly found in tendas
        webroot_path = os.path.join(fs_path, "webroot_ro")
        if os.path.exists(webroot_path):
            dest = os.path.join(fs_path, "var")
            if not os.path.exists(dest):
                Files.mkdir(dest, root=fs_path)
            dest = os.path.join(dest, "webroot")
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.copytree(webroot_path, dest, symlinks=True)
            print("Created", dest)

    def find_library(self, libname, fs_path, resolve_symlinks=True, skip=[]):
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f.startswith(libname):
                    lib_path = os.path.join(root, f)
                    if os.path.islink(lib_path):
                        if resolve_symlinks:
                            lib_path = str(pathlib.Path(lib_path).resolve()) # handle symlinks
                        if not lib_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while lib_path.startswith("/") or lib_path.endswith("/"):
                                lib_path = lib_path.strip("/")
                            lib_path = os.path.join(fs_path, lib_path)
                    if lib_path in skip:
                        continue
                    if not os.path.exists(lib_path):
                        continue
                    return lib_path
        return ""

    def find_file(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    return file_path
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            return file_path
        return ""

    def find_webroot(self, fs_path):
        for root, dirs, files in os.walk(fs_path):
            for d in dirs:
                if d in WEBROOTS:
                    path = os.path.join(root, d)
                    relative_path = os.path.join("/", os.path.relpath(path, fs_path))
                    return relative_path
        return ""
    
    def find_files_with_extension(self, basename, extensions, fs_path, resolve_symlinks=True, skip=[]):
        found = []
        targets = [basename+"."+ext for ext in extensions]
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                for t in targets:
                    if f == t:
                        file_path = os.path.join(root, f)
                        if os.path.dirname(file_path) == fs_path:
                            continue # skip files in 'root' dir
                        if os.path.islink(file_path):
                            if resolve_symlinks:
                                file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                            if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                while file_path.startswith("/") or file_path.endswith("/"):
                                    file_path = file_path.strip("/")
                                file_path = os.path.join(fs_path, file_path)
                        if file_path in skip or file_path in found:
                            continue
                        if not os.path.exists(file_path):
                            continue
                        found.append(file_path)
        return found


    def find_files(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found


    def find_files_ending_with(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f.endswith(filename):
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found

    def get_clib_from_file_command(outline):
        if b"uClibc" in outline:
            return "uclibc"
        elif b"GNU/Linux" in outline:
            return "glibc"
        elif b"musl" in outline:
            return "musl"
        return "glibc" #default


    def get_arch_from_file_command(outline):
        if b"64-bit" in outline:
            if b" ARM" in outline and b" LSB" in outline:
                return "arm64"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips64"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mips64el"
        else:
            if b" ARM" in outline and b" MSB" in outline:
                return "armeb"
            elif b" ARM" in outline and b" LSB" in outline:
                return "arm"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" 80386" in outline:
                return "x86"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mipsel"
        return None

    def copy_qemu_user_static(self, arch, fs_path):
        qemu_binary = ARCH_MAP[arch]
        path = os.path.join(self.qemu_src_path, qemu_binary)
        target_path = os.path.join(fs_path, qemu_binary)

        print("    - Copying %s to %s" % (path, target_path))
        Files.copy_file(path, target_path)

        return target_path

    def setup_custom_libraries(self, fs_path):
        # make nvram ini
        self.nvram_init_path = os.path.join(fs_path, NVRAM_INIT)
        self.nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        nvram_ref_path = os.path.join(self.nvram_faker_path, "conf", NVRAM_INIT)
        nvram_brand_path = os.path.join(self.nvram_faker_path, "conf", self.brand, NVRAM_INIT)
        Files.touch_file(self.nvram_init_path, root=fs_path)
        if not os.path.exists(self.nvram_key_value_path):
            Files.mkdir(self.nvram_key_value_path, root=fs_path)
            subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])

        # copy in libnvram.so
        lib_path = os.path.join(fs_path, "lib")
        target_nvram_faker_path = os.path.join(self.nvram_faker_path, "lib", self.arch, self.clibc, "libnvram-faker.so")
        print("Using ", target_nvram_faker_path)
        shutil.copy(target_nvram_faker_path, lib_path)

        # backup and replace the original libnvram in case hook does not work
        real_libnvram_path = os.path.join(lib_path, "libnvram.so")
        if os.path.exists(real_libnvram_path):
            os.rename(real_libnvram_path, real_libnvram_path+".bak")
        shutil.copy(target_nvram_faker_path, real_libnvram_path)

        # read in reference nvram values
        if nvram_ref_path != "" and os.path.exists(nvram_ref_path):
            with open(nvram_ref_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_map[key] = value
        nvramIniFile.close()

        if nvram_brand_path != "" and os.path.exists(nvram_brand_path):
            with open(nvram_brand_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_brand_map[key] = value
        nvramIniFile.close()

    def update_nvram_map(self, new_values):
        if not new_values:
            print("    - invalid new_values for nvram_map: ", new_values)
            return

        print("    - updating nvram_map")
        for key, value in new_values.items():
            self.nvram_brand_map[key] = value

    def write_nvram(self, keys, changelog=[]):
        for key in keys:
            key = key.strip().strip("/")
            if len(key) <= 0:
                print("    ! skipping empty key")
                continue
            if "/" in key:
                key = key.replace("/", "_")
            key_path = os.path.join(self.nvram_key_value_path , key)
            value = ""
            if key in self.nvram_brand_map.keys():
                value = self.nvram_brand_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            elif key in self.nvram_map.keys():
                value = self.nvram_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            else:
                entry = "%s=\n" % (key)
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % entry)
                # entry = ""
            print("    - adding nvram key: %s=%s" % (key, value))
            if os.path.isdir(key_path):
                print("    ! skipping invalid key", key)
                continue
            with open(key_path, "w") as keyFile:
                keyFile.write(value)
            keyFile.close()
        subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])

        keylog = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                line = line.strip()
                if line not in keylog:
                    keylog.append(line)
            for key in keys:
                if key not in keylog:
                    keylog.append(key)
        nvramFile.close()


        with open(self.nvram_init_path, "w") as nvramFile:
            for key in keylog:
                nvramFile.write(key+"\n")
        nvramFile.close()

    def check_ip(self, ip):
        if len(ip) > 0:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                pass
        return False

    def get_ips_from_nvram(self):
        nvramIPfiles = []
        nvram_ips = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                for iptag in NVRAM_IP_KEYS:
                    if iptag in line:
                        nvramIPfiles.append(line.strip())
        nvramFile.close()

        for key in nvramIPfiles:
            path = os.path.join(self.nvram_key_value_path, key)
            nvramVal = ""
            with open(path, "r") as nvramFile:
                nvramVal = nvramFile.read().strip()
            if len(nvramVal) > 0 and nvramVal not in nvram_ips and self.check_ip(nvramVal):
                nvram_ips.append(nvramVal)

        return nvram_ips



class Planter():

    def __init__(self, gh_path, scripts_path, qemu_src_path, brand):
        self.gh_path = gh_path
        self.gh_templates_path = os.path.join(self.gh_path, "templates")
        self.scripts_path = scripts_path
        self.qemu_src_path = qemu_src_path
        self.fixer = None
        self.brand = brand
        self.indicators = ["/bin/sh", "/bin/busybox"]

    def identify_target_folder(self, extracted_path):
        found_fs = ""
        for root, dirs, subdirs in os.walk(extracted_path):
            dirs_sorted = sorted(dirs)
            for d in dirs_sorted:
            # if re.findall("^.*-root[-_0-9]*$", d):
                target_path = os.path.join(root, d)
                for target_root, target_dirs, target_files in os.walk(target_path):
                    for td in sorted(target_dirs):
                        if "bin" in td:
                            binfolder_path = os.path.join(target_root, td)
                            binfolder_path = os.path.realpath(binfolder_path)
                            if not binfolder_path.startswith(extracted_path):
                                continue
                            bin_files = os.listdir(binfolder_path)
                            for f in sorted(bin_files):
                                bin_path = os.path.join(target_root, td, f)
                                for indicator in self.indicators:
                                    if bin_path.endswith(indicator):
                                        full_path = str(pathlib.Path(bin_path).resolve()) # handle symlinks
                                        print("Checking arch of binary at ", full_path)
                                        if not os.path.exists(full_path):
                                            print("    - does not exist, skipping...")
                                            continue
                                        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                        stdout = sp.stdout
                                        print("    - ", stdout)
                                        arch = Fixer.get_arch_from_file_command(stdout)
                                        if arch in ARCH_MAP.keys():
                                            found_fs = target_root
                                            return found_fs
        return ""

    def unpack_image(self, img_path, fs_path_override, workspace=""):

        img_path = os.path.realpath(img_path)
        print("    - Unpacking image", img_path)
        image_name = os.path.basename(img_path)
        dir_name = os.path.dirname(img_path)
        if workspace:
            dir_base = os.path.basename(dir_name)
            dir_name = os.path.join(workspace, dir_base)
        extracted_name = "_"+image_name+".extracted"
        extracted_path = os.path.join(dir_name, extracted_name)

        if os.path.exists(extracted_path):
            print("Extracted directory %s already exists, skipping extraction" % extracted_path)
        else:
            curruser = getpass.getuser()
            binwalk_command = ["binwalk"]
            if curruser == "root":
                binwalk_command.extend(["--run-as=root"])
            binwalk_command.extend(["--preserve-symlinks", "-eMq", img_path, "-C", dir_name])
            subprocess.run(binwalk_command)
            time.sleep(1)

        fs_path = ""
        if fs_path_override != "":
            if os.path.exists(fs_path_override):
                print("    - Using known rootfs path", fs_path_override)
                fs_path = fs_path_override.rstrip("/")
                return fs_path
            else:
                print("known rootfs path %s does not exist, defaulting to search..." % fs_path_override)

        if os.path.exists(extracted_path):
            # make entire folder RWXtable
            print("Calling chmod  on", extracted_path)
            sp = subprocess.run(["chmod", "-R", "a+rwx", extracted_path])
            stdout = sp.stdout
            print("    - ", stdout)
            found_fs = self.identify_target_folder(extracted_path)
            if found_fs:
                fs_path = found_fs #os.path.join(root, d)
                print("Found root dir at %s" % found_fs)
                return fs_path

        else:
            print("ERROR %s does not exist!" % extracted_path)

        print("Unable to find a proper root directory for ", extracted_path)
        return ""

    def get_bg_scripts(self, fs_path, blacklist=[]):
        bg_scripts = dict()
        for binaryname, args in BACKGROUND_SCRIPTS.items():
            results = pathlib.Path(fs_path).rglob(binaryname)
            for ppath in results: # return first valid result
                if not ppath.is_symlink() and fs_path in str(ppath):
                    relative_path = "/"+str(ppath.relative_to(fs_path)).strip("/")
                    bg_scripts[relative_path] = args
                    break
        return bg_scripts

    def get_potential_binaries(self, rehost_type):
        if rehost_type == "HTTP":
            return POTENTIAL_HTTPSERV
        elif rehost_type == "UPNP":
            return POTENTIAL_UPNPSERV
        elif rehost_type == "DNS":
            return POTENTIAL_DNSSERV
        elif rehost_type == "DHCP":
            return POTENTIAL_DHCPSERV
        return "UNKNOWN"
    
    def is_network_facing_binary(self, binary):
        proj = angr.Project(binary)
        for sym in proj.loader.symbols:
            if "bind" in sym.name or "listen" in sym.name:
                return True
        return False    

    def get_target_binary(self, fs_path, rehost_type):
        potential_binaries = self.get_potential_binaries(rehost_type)
        pot_targets = dict()
        for root, dirs, files in os.walk(fs_path, topdown=False):
            for name in files:
                if name.lower() in potential_binaries:
                    if name.lower() not in pot_targets.keys():
                        pot_targets[name.lower()] = []
                    pot_targets[name.lower()].append(os.path.join(root, name))

        print("Potential Binaries: ", pot_targets)
        # return "best" match in order listed in potential_binaries
        for binary in potential_binaries:
            if binary in pot_targets.keys():
                for bin_path in pot_targets[binary]:
                    sp = subprocess.run(["file", bin_path], stdout=PIPE, stderr=PIPE)
                    stdout = sp.stdout
                    details = stdout.split(b":")[1].strip()
                    if details.startswith(b"ELF "):
                        print("    - Found binary: %s" % bin_path)
                        return bin_path
        return ""

    def get_mac_from_nvrams(self, fs_path):
        # heuristic for targets the require a specific mac address
        nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        if os.path.exists(nvram_key_value_path):
            nvram_keys = os.listdir(nvram_key_value_path)
            for key in nvram_keys:
                key = key.strip()
                if key in MAC_NVRAM_KEYS:
                    keypath = os.path.join(nvram_key_value_path, key)
                    value = ""
                    if os.path.exists(keypath):
                        with open(keypath, "r") as vFile:
                            value = vFile.read().strip()
                            match = re.match(r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}", value)
                            if match is not None:
                                value = match.group(0)
                        vFile.close()
                    else:
                        print("    - unable to open keypath", keypath)
                    if len(value) > 0:
                        return value
        return ""

    def setup_env(self, qemu_src_path, fs_path, bin_path, baseline_mode):
        self.fixer = Fixer(qemu_src_path, self.gh_path, self.scripts_path, self.brand, baseline_mode)
        r = self.fixer.initial_setup(fs_path, bin_path)
        return r 

    def check_cwd(self, fs_path, targets, old_cwd, cwd_rh_replaced, already_success):
        if cwd_rh_replaced or already_success:
            print("    - already got correct directory, skipping...")
            return False, old_cwd
        relative_targets = []
        for target in targets:
            if not target.startswith("/") and target not in relative_targets:
                relative_targets.append(target)

        cwds = dict()
        for target in relative_targets:
            # skip none html and cgi files, we can pretty much copy everything else
            ext = target.split(".")[-1]
            if ext not in WEB_EXTS:
                continue
            # check if file might exists somewhere else
            path = os.path.join(fs_path, target)
            sourcefiles = self.fixer.find_files(os.path.basename(target), fs_path, include_backups=True, skip=[path])
            for sourcefile in sourcefiles:
                print("target", target, "source", sourcefile)
                if len(sourcefile) > 0:
                    cwd_path = os.path.dirname(sourcefile)
                    relative_path = os.path.relpath(cwd_path, fs_path)
                    if relative_path not in cwds and relative_path != ".":
                        cwds[relative_path] = 0
                    if relative_path != ".":
                        print("    - adding relative path", target)
                        cwds[relative_path] += 1

        if len(cwds) <= 0:
            print("No relative cwd targets found")
            return False, old_cwd

        # else len(cwds) > 1:
        print("More than one possible CWD: ", cwds)
        majority_cwds = []
        highest = 0
        for k, v in cwds.items():
            if v > highest:
                majority_cwds.clear()
                highest = v
            if v >= highest:
                majority_cwds.append(k)
        cwds_sorted = sorted(majority_cwds, key=lambda x: ("www" not in x and "web" not in x and "htm" in x, x.count('/'), len(x), x))
        cwd_path = cwds_sorted[0]
        print("CWD target found", cwd_path)
        return True, cwd_path

    def add_interfaces(self, interfaces, urls):
        # we rebuild the interface <-> ip address mapping each time
        # just to be safe
        new_urls = []
        noninterface_urls = []
        iface_cmds = []
        for url in urls:
            fields = url.split(".")
            if fields[0] == "172":
                id = int(fields[1])
                if id >= 100 and id < 200:
                    # is a special interface, skip
                    continue
            noninterface_urls.append(url)

        i = 1
        for iface in interfaces:
            url = ""
            url = "172.%s.0.1" % (100+i)
            if i > 100:
                print("ERROR - too many interfaces. skipping extra interface")
                continue
            # index of iface matches index in urls
            new_urls.append(url)
            iface_cmds.append("/greenhouse/ip link set eth%d down" % i)
            iface_cmds.append("/greenhouse/ip link set eth%d name %s" % (i, iface))
            iface_cmds.append("/greenhouse/ip link set %s up" % iface)            
            i += 1
        new_urls.extend(noninterface_urls)
        
        return new_urls, iface_cmds

    def get_subnet(self, ipaddr, netmask="255.255.255.0"):
        subnet_string = "%s/%s" % (ipaddr, netmask)
        subnet = ""
        try:
            subnet = str(ipaddress.ip_interface(subnet_string).network)
        except:
            pass
        return subnet

    def parse_ips(self, ip_targets_path, ip_addrs, old_ips=[]):
        # script = "#!/bin/sh\n\n"
        # count = 0
        new_ips = []
        in_use_subnets = []

        # check in use ips
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                in_use_subnet = self.get_subnet(ip.ip)
                if len(in_use_subnet) > 0:
                    in_use_subnets.append(in_use_subnet)

        for ip in ip_addrs:
            subnet = self.get_subnet(ip)
            if ip not in RESERVED_IPS and \
               ip not in old_ips and \
               not ip.startswith("255.") and \
               not ip.endswith(".255") and \
               not ip.endswith(".0") and \
               subnet not in in_use_subnets:
                print("    - adding ip device %s" % ip)
                new_ips.append(ip)

        # update ip targets
        with open(ip_targets_path, "w+") as ipFile:
            for ip in old_ips:
                ipFile.write(ip+"\n")
            for ip in new_ips:
                ipFile.write(ip+"\n")
        ipFile.close()

        return new_ips

    def parse_ports(self, ports_path, ports, old_ports=[]):
        # script = "#!/bin/sh\n\n"
        # count = 0
        new_ports = []
        for p in ports:
            if p not in old_ports and p not in PORTS_BLACKLIST:
                print("    - adding port target %s" % p)
                new_ports.append(p)

        # update ip targets
        with open(ports_path, "w+") as portFile:
            for p in old_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
            for p in new_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
        portFile.close()

        return new_ports


    def get_ips_from_nvram(self):
        return self.fixer.get_ips_from_nvram()

    def find_sourcefile(self, target, fs_path, path):
        sourcefile = self.fixer.find_file(os.path.basename(target), fs_path, include_backups=True, skip=[path])

        # handle edge case where htm and html are equivalent
        if len(sourcefile) <= 0 and (target.endswith(".html") or target.endswith(".htm")):
            targetbasename = os.path.basename(target.rsplit(".")[0])
            sourcefiles = self.fixer.find_files_with_extension(targetbasename, [".htm", ".html"], fs_path, skip=[path])
            for sf in sourcefiles:
                if sf.endswith(targetbasename):
                    sourcefile = sf
                    break
                else:
                    sourcefile = sf
        
        # handle edge case where conf, config and cnf are equivalent
        if len(sourcefile) <= 0 and (target.endswith(".conf") or target.endswith(".cnf") or target.endswith(".config")):
            targetbasename = os.path.basename(target.rsplit(".")[0])
            sourcefiles = self.fixer.find_files_with_extension(targetbasename, [".config", ".conf", "cnf"], fs_path, skip=[path])
            for sf in sourcefiles:
                if sf.endswith(targetbasename):
                    sourcefile = sf
                    break
                else:
                    sourcefile = sf
        return sourcefile

    def transplant(self, fs_path, targets, folders, configs, failed, already_success, no_skip, hackdevproc, changelog):
        print("    - processing nvram configs")
        self.fixer.write_nvram(configs, changelog)

        if already_success:
            print("    - already successful, focusing on get working nvrams up")
            return

        for folder in folders:
            if folder in failed:
                failed.remove(folder)
            
            while folder.startswith("/") or folder.endswith("/"):
                folder = folder.strip("/")
            path = os.path.join(fs_path, folder)
            print("[] Making folder ", path)
            if os.path.exists(path) and os.path.isdir(path):
                print("    - folder exists, skip!")
                continue
            Files.mkdir(path, root=fs_path, silent=True)
            rb = "[ROADBLOCK] requires missing directory"
            if rb not in changelog:
                changelog.append(rb)
            changelog.append("[GreenHouse] MKDIR: %s"  % path)

        skipped = []
        for target in targets:

            target = "".join(filter(lambda x: x in string.printable, target))
            print("[GreenHouse] target: ", target)
            if target in failed:
                failed.remove(target)

            if not target.startswith("/"):
                print("    - target is a relative CWD, skip!")
                continue

            if hackdevproc and target.startswith("/proc/"):
                oldtarget = target
                target = target[6:]
                target = os.path.join("/ghproc", target)
                print("    - switching %s to %s" % (oldtarget, target))

            if hackdevproc and target.startswith("/dev/"):
                oldtarget = target
                target = target[5:]
                target = os.path.join("/ghdev", target)
                print("    - switching %s to %s" % (oldtarget, target))

            while target.startswith("/") or target.endswith("/"):
                target = target.strip("/")
            path = os.path.join(fs_path, target)
            path = str(pathlib.Path(path).resolve()) # handle symlinks

            if os.path.isdir(path):
                print("    ! target %s is directory, skipping" % path)
                continue # skip transplanting full directories

            # handle edge case where symlink resolves to host machine path
            if fs_path not in path:
                path = os.path.join(fs_path, path.strip("/"))
            dirname = os.path.dirname(path)

            # create target folder env
            if not os.path.exists(dirname):
                Files.mkdir(dirname, root=fs_path, silent=True)
                rb = "[ROADBLOCK] requires missing directory"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MKDIR: %s"  % dirname)

            # pid files should be created by the process, however we want to
            # create the root directories they are in
            if target.endswith(".pid") and target not in no_skip:
                print("    - target is a PID file, skip!")
                if target not in skipped:
                    skipped.append(target)
                continue

            if target.startswith("tmp/") and target not in no_skip:
                print("    - target is a /tmp/ file, skip!")
                if target not in skipped:
                    skipped.append(target)
                continue

            # check if file might exists somewhere else we can copy
            sourcefile = self.find_sourcefile(target, fs_path, path)
            if len(sourcefile) <= 0:
                # try looking in templates
                sourcefile = self.find_sourcefile(target, self.gh_templates_path, path)

            # transplant file
            if len(sourcefile) > 0:
                print("    - Found backup, copying from %s to %s" % (sourcefile, path))
                Files.touch_file(path, root=fs_path, silent=True) # create folders to path
                Files.rm_file(path, silent=True) # rm basefile so it can be copied over
                if os.path.isdir(sourcefile):
                    print("    ! backup is a directory, skipping.")
                    continue
                Files.copy_file(sourcefile, path, silent=True)
            elif os.path.basename(path).startswith("ld-musl") and os.path.basename(path).endswith(".path"):
                # handle ld-musl .path file special case
                # Files.write_file(path, MUSL_LD_DEFAULT) # 'random' bytes for entropy
                print("    ! ld-musl-arch.path file, skipping.")
                # currently we skip handling this
                continue
            else:
                print("    - Creating file ", path)
                Files.touch_file(path, root=fs_path, silent=True)
                rb = "[ROADBLOCK] requires missing file"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MKFILE: %s"  % path)

        # handle special cases
        cache = set()
        for f in failed:
            # dont repeat work
            if f in cache:
                continue
            cache.add(f)

            # process
            while f.startswith("/") or f.endswith("/"):
                f = f.strip("/")
            target_path = os.path.join(fs_path, f)
            target_path = str(pathlib.Path(target_path).resolve()) # handle symlinks
            if fs_path not in target_path:
                while target_path.startswith("/") or target_path.endswith("/"):
                    target_path = target_path.strip("/")
                target_path = os.path.join(fs_path, target_path)
            libpath = self.fixer.find_library(os.path.basename(f), fs_path, skip=[target_path])
            print("    - [Greenhouse] Processing failed lib %s" % f)
            if len(libpath) > 0 and os.path.exists(libpath):
                print("    - Found misplaced library %s, moving to %s" % (libpath, target_path))
                print("    - copying from", libpath)
                dirPath = os.path.dirname(target_path)
                if not os.path.exists(dirPath) or not os.path.isdir(dirPath):
                    Files.mkdir(dirPath, root=fs_path, silent=True)
                if os.path.exists(target_path) or os.path.islink(target_path):
                    Files.rm_file(target_path, silent=True)
                if os.path.exists(libpath):
                    Files.copy_file(libpath, target_path, silent=True)
                    if len(targets) <= 0:
                        targets.add(".") # dummy trigger so we loop at least one more time
                    rb = "[ROADBLOCK] requires missing library"
                    if rb not in changelog:
                        changelog.append(rb)
                    changelog.append("[GreenHouse] FIXLIB: %s"  % target_path)
                else:
                    print("    - %s missing. Skipping..." % libpath)

                continue
            elif "libc.so" in f:
                libpath = self.fixer.find_library("libc.so.", fs_path)
                target_path = os.path.join(fs_path, f)
                if libpath:
                    print("Fixing special case for missing libc.so.6 with a hack...")
                    print("    - copying from", libpath)
                    dirPath = os.path.dirname(target_path)
                    if not os.path.exists(dirPath):
                        Files.mkdir(dirPath, root=fs_path, silent=True)
                    Files.copy_file(libpath, target_path, silent=True)
                    targets.add(".") # dummy trigger so we loop at least one more time
                    rb = "[ROADBLOCK] requires missing library"
                    if rb not in changelog:
                        changelog.append(rb)
                    changelog.append("[GreenHouse] FIXLIB: %s"  % target_path)

        return skipped

    def setup_cl_args(self, brand, fs_path, full_binary_path, changelog, extra_args=[], rehost_type="HTTP"):
        if not os.path.exists(full_binary_path):
            print("    - error, no binary found at [%s]" % full_binary_path)
            return []

        cl_args = []
        has_httpd_conf_args = False
        has_cert_args = False
        DEFAULT_IP = "0.0.0.0"
        if rehost_type == "HTTP":
            DEFAULT_PORT = 80
        elif rehost_type == "UPNP":
            DEFAULT_PORT = 1900
        elif rehost_type == "DNS":
            DEFAULT_PORT = 53
        else:
            print("   - unknown rehost type %s, defaulting to port 80" % rehost_type)
            DEFAULT_PORT = 80

        print("Setting up cmd line args...")

        with open(full_binary_path, "rb") as bFile:
            data = bFile.read()
            has_httpd_conf_args = re.findall(b"(?=[ -~\s]*-[fc])(?=[ -~\s]*[Cc]onfiguration)[ -~\s]*", data)
            if not has_httpd_conf_args:
                has_httpd_conf_args = re.findall(b"(?=[ -~\s]*-[fc])(?=[ -~\s]*[Cc]onfig\-file)[ -~\s]*", data)
            has_webroot_args = re.findall(b"(?=[ -~\s]*-h)(?=[ -~\s]*document root)[ -~\s]*", data)
            has_cert_args = re.findall(b"-E cert", data)
            has_port_args = re.findall(b"-p [ -,.-~\s]*port", data)
            has_ext_if_args = re.findall(b"-i ext_ifname", data)
        bFile.close()

        if has_port_args:
            cl_args.append("-p %d" % (DEFAULT_PORT))

        if has_ext_if_args:
            cl_args.append("-d -i %s" % (DEFAULT_IP))

        if has_httpd_conf_args:
            flag = ""
            for results in has_httpd_conf_args:
                for line in results.splitlines():
                    if b"configuration" in line or b"Configuration" in line or b"onfig-file" in line:
                        if b"-c" in line:
                            flag = "-c"
                            break
                        elif b"-f" in line:
                            flag = "-f"
                            break
                        else:
                            flag = ""
                if flag != "":
                    break
            if len(flag) > 0:
                sourcefiles = self.fixer.find_files_ending_with(".conf", fs_path, include_backups=True, skip=[])
                sourcefile = ""
                binary_basename = os.path.basename(full_binary_path)
                for sf in sourcefiles:
                    if binary_basename in sf:
                        sourcefile = sf
                        break

                if sourcefile and fs_path in sourcefile:
                    sourcefile_basename = os.path.basename(sourcefile)
                    dest =  os.path.join(fs_path, sourcefile_basename)

                    if os.path.exists(dest):
                        print("Conf file exists at destination, skipping copy...")
                    else:
                        print("    - Copying %s to %s" % (sourcefile, dest))
                        Files.copy_file(sourcefile, dest)

                    relative_path = os.path.relpath(dest, fs_path)
                    add_arg = True
                    for arg in extra_args.split():
                        if relative_path in arg:
                            add_arg = False

                    if not relative_path.startswith("/"):
                        relative_path = "/"+relative_path

                    if add_arg:
                        cl_args.append("%s %s" % (flag, relative_path))
                    else:
                        print("    - %s already in extra_args, continuing" % relative_path)
                else:
                    print("    - no source found for config arg. Skip adding it as an extra arg")

        if has_webroot_args:
            webroot = self.fixer.find_webroot(fs_path)
            if len(webroot) > 0:
                webroot = webroot.strip("/")
                print("    - found relative webroot", webroot)
                webroot_name = os.path.basename(webroot)
                webroot_link_path = os.path.join(fs_path, webroot_name)
                print("    - linking %s to %s" % (webroot_link_path, webroot))
                Files.mk_link(webroot_link_path, webroot, relative_dir=fs_path)
                cl_args.append("-h %s" % (webroot_name))
                rb = "[ROADBLOCK] requires webroot argument"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING WEBROOT: %s"  % webroot)

        if has_cert_args and brand == "netgear":
            cafile = self.fixer.find_file("ca.pem", fs_path, include_backups=True, skip=[])
            httpsdfile = self.fixer.find_file("httpsd.pem", fs_path, include_backups=True, skip=[])

            cabaseName = ""
            if cafile and fs_path in cafile:
                sourcefile = cafile
                cabaseName = os.path.basename(cafile)
            else:
                sourcefile = os.path.join(self.gh_path, "openssl", "ca.pem")
                cabaseName = os.path.basename("ca.pem")
                rb = "[ROADBLOCK] requires missing cert"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING CERT: %s"  % cabaseName)
            dest = os.path.join(fs_path, cabaseName)

            if os.path.exists(dest):
                print("    - %s file exists at destination, skipping copy..." % cabaseName)
            else:
                print("    - Copying %s to %s" % (sourcefile, dest))
                Files.copy_file(sourcefile, dest)

            httpsdbaseName = ""
            if httpsdfile and fs_path in httpsdfile:
                sourcefile = httpsdfile
                httpsdbaseName = os.path.basename(httpsdfile)
            else:
                sourcefile = os.path.join(self.gh_path, "openssl", "httpsd.pem")
                httpsdbaseName = os.path.basename("httpsd.pem")
                rb = "[ROADBLOCK] requires missing cert"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING CERT: %s"  % httpsdbaseName)
            dest = os.path.join(fs_path, httpsdbaseName)

            if os.path.exists(dest):
                print("    - %s file exists at destination, skipping copy..." % httpsdbaseName)
            else:
                print("    - Copying %s to %s" % (sourcefile, dest))
                Files.copy_file(sourcefile, dest)

            cl_args.append("-S -E %s %s" % (cabaseName, httpsdbaseName))

        print("    - cl_args:", cl_args)
        print("done!")
        return cl_args

    def get_qemu_run_path(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_run_path

    def get_qemu_arch(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_arch

    def clean_fs(self, target_fs):
        # cleanup special files that might have been created:
        target_fs = os.path.realpath(target_fs)
        print("    - cleaning", target_fs)
        for root, dirs, files in os.walk(target_fs, topdown=False):
            for f in files:
                fpath = os.path.join(root, f)
                fpath = os.path.realpath(fpath)
                if os.path.exists(fpath) and fpath.startswith(target_fs):
                    st_mode = os.stat(fpath).st_mode
                    if stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode) or stat.S_ISSOCK(st_mode) or stat.S_ISFIFO(st_mode):
                        print("    - replacing special file", fpath)
                        os.unlink(fpath)
                        if not (stat.S_ISSOCK(st_mode) or stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode)):
                            # do not recreate sock files
                            # blk and chr device creation handled by script now
                            os.mknod(fpath)
                if f.endswith(".conf"):
                    # remove Interface tags from configuration files
                    if os.path.exists(fpath):
                        lines = []
                        with open(fpath, "r", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in confFile:
                                if "Interface " in line or "Interface:" in line:
                                    print("    - removing line", line, "from confFile", fpath)
                                    continue
                                lines.append(line)
                        confFile.close()

                        with open(fpath, "w", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in lines:
                                confFile.write(line)
                        confFile.close()
