import r2pipe

class NopInstrPatch:
    def __init__(self, arch, addr, numBytes):
        self.addr = addr
        self.numBytes = numBytes
        self.arch = arch
        self.patchString = self.getPatchForArch()

    def getPatchForArch(self):
        if(self.arch ==  "x86"):
            return "wa nop"            
        elif(self.arch ==  "mips"):
            return "wa nop"                        
        elif(self.arch ==   "arm"):
            return "wa nop"            
        else:
            print("Error, unrecognized arch")
            return None

    def getNopSizeForArch(self):
        if(self.arch ==  "x86"):
            return 1
        elif(self.arch ==  "mips"):
            return 4
        elif(self.arch ==   "arm"):
            return 4
        else:
            print("Error, unrecognized arch")
            return None

    def apply(self, r2):
        if self.patchString == None:
            print("Unable to apply patchstring for arch %s, patchstring is None" % arch)
            return

        nop_size = self.getNopSizeForArch()
        for offset in range(0, self.numBytes, nop_size):
            byte_addr = self.addr + offset
            print("Patching out %x with [nop]" % byte_addr)
            r2.cmd('s ' + str(byte_addr))
            cmd = self.patchString
            r2.cmd(cmd)