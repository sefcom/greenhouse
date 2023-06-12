import os, shutil
from telnetlib import IP
from . import BackgroundScript

XMLDB_LOG = "xmldb_log"
XMLDBC_LOG = "xmldbc_log"
XMLDB_DUMP = "xmldump"

class XMLDBHandler(BackgroundScript):
    binary = "xmldb"

    def __init__(self):
        self.sleeptime = 5
        pass

    def get_fullsystem_cmds(self, bin_paths, log_folder):
        cmds = []
        self.match = False
        bin_paths = sorted(bin_paths, key=len)
        for binp in bin_paths:
            if binp.endswith("xmldbc"):
                binp = binp.strip(".")
                xmldbclogpath = os.path.join("/", log_folder, XMLDBC_LOG)
                xml_dump_path = os.path.join("/", log_folder, XMLDB_DUMP)
                cmd = "%s -d %s > %s\n" % (binp, xml_dump_path, xmldbclogpath)
                bytecmd = cmd.encode('utf-8')
                cmds.append(bytecmd)
                cmd = "%s -D %s > %s2\n" % (binp, xml_dump_path, xmldbclogpath)
                bytecmd = cmd.encode('utf-8')
                cmds.append(bytecmd)
                # self.match = True

        return cmds

    def get_single_cmds(self, bin_paths, fs_path):
        cmds = []
        xmldbPath = ""
        xmldbcPath = ""
        sleepPath = ""

        xmldumppath = os.path.join(fs_path, XMLDB_DUMP)

        bin_paths = sorted(bin_paths, key=len)
        for binp in bin_paths:
            if binp.endswith("/xmldb"):    
                xmldbPath = "/"+os.path.relpath(binp, fs_path)
            if binp.endswith("/xmldbc"):
                xmldbcPath = "/"+os.path.relpath(binp, fs_path)
            if binp.endswith("/sleep"):
                sleepPath = "/"+os.path.relpath(binp, fs_path)
                
        if len(xmldbPath) > 0 and len(xmldbcPath) > 0 and len(sleepPath) > 0:
            xmlnodename = "gh_xml_root_node"
            if os.path.exists(xmldumppath):
                with open(xmldumppath, "r") as xmlFile:
                    for line in xmlFile:
                        xmlnodename = line.strip().strip(">").strip("<")
                        break
            else:
                # copy xmldump
                pluginDir = os.path.dirname(os.path.abspath(__file__))
                defaultxmlpath = os.path.join(pluginDir, XMLDB_DUMP)
                shutil.copyfile(defaultxmlpath, xmldumppath)

            args = "%s -n %s -t &" % (xmldbPath, xmlnodename)
            cmds.append(args)
            args = "%s 3" % (sleepPath)
            cmds.append(args)
            args = "%s -l %s" % (xmldbcPath, XMLDB_DUMP)   
            cmds.append(args)
            args = "%s -L %s" % (xmldbcPath, XMLDB_DUMP)   
            cmds.append(args)
        else:
            print("    - no matching cmds for xmldb")

        return (cmds, self.sleeptime)
