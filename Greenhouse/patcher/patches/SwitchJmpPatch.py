import r2pipe

class SwitchJmpPatch:
    def __init__(self, arch, initialAddress, targetAddress):
        self.initialAddress = initialAddress
        self.targetAddress = targetAddress
        self.arch =arch
        self.patchString = self.getPatchForArch()

    def getPatchForArch(self):
        if(self.arch ==  "x86"):
            return "wa jmp %s" % hex(self.targetAddress)            
        elif(self.arch ==  "mips"):
            return "wa j %s" % hex(self.targetAddress)                       
        elif(self.arch ==   "arm"):
            return "wa b %s" % hex(self.targetAddress)          
        else:
            print("Error, unrecognized arch")
            return None

    def apply(self, r2):
        if self.patchString == None:
            print("Unable to apply patchstring for arch %s, patchstring is None" % arch)
            return
        r2.cmd('s ' + str(self.initialAddress))
        cmd = self.patchString
        r2.cmd(cmd)
