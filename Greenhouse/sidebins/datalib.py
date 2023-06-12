import os, shutil
from telnetlib import IP
from . import BackgroundScript

CONFIG_LOG = "extracted_config_log"
CONFIG_DUMP = "extracted_config_dump"

class DataLibHandler(BackgroundScript):
    binary = "datalib"

    def __init__(self):
        self.sleeptime = 3
        pass

    def get_fullsystem_cmds(self, bin_paths, log_folder):
        cmds = []
        bin_paths = sorted(bin_paths, key=len)
        for binp in bin_paths:
            if binp.endswith("/datalib"):
                binp = binp.strip(".")
                logpath = os.path.join("/", log_folder, CONFIG_LOG)
                cmd = "%s show &> %s\n" % (binp, logpath)
                bytecmd = cmd.encode('utf-8')
                cmds.append(bytecmd)

        return cmds

    def get_single_cmds(self, bin_paths, fs_path):
        cmds = []
        datalibPath = ""
        sleepPath = ""
        configbinPath = ""

        bin_paths = sorted(bin_paths, key=len)
        for binp in bin_paths:
            if binp.endswith("/datalib"):
                datalibPath = "/"+os.path.relpath(binp, fs_path)
            if binp.endswith("/sleep"):
                sleepPath = "/"+os.path.relpath(binp, fs_path)
            if binp.endswith("/config"):
                configbinPath = "/"+os.path.relpath(binp, fs_path)

        if len(datalibPath) > 0 and len(sleepPath) > 0:
            args = "%s &" % (datalibPath)
            cmds.append(args)
            args = "%s set dns_hijack=0" % (configbinPath)
            cmds.append(args)
            args = "%s 2" % (sleepPath)
            cmds.append(args)
        else:
            print("    - no matching cmds for datalib")

        return (cmds, self.sleeptime)
