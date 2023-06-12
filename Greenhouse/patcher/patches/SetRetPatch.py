import r2pipe


class SetRetPatch:
    def __init__(self, arch, addr, val=0):
        self.addr = addr
        self.arch = arch
        self.val = val
        self.patches = self.getPatchForArch()

    def getPatchForArch(self):
        patches = []
        if self.arch == "x86":
            patches.append("mov eax, %x" % self.val)
        elif self.arch == "mips":
            patches.append("addiu v0, v0, %x" % self.val)
        elif self.arch == "arm":
            patches.append("mov r0, %x" % self.val)
        else:
            print("Error, unrecognized arch")
            return []
        return patches

    def apply(self, r2):
        if len(self.patches) <= 0:
            print("Unable to apply patchstring for arch %s, patchstring is None" % arch)
            return

        byte_addr = self.addr

        out = r2.cmd('s ' + str(byte_addr))
        print(out)
        for patch in self.patches:
            byteString = r2.cmd('pa ' + patch)
            numBytes = len(byteString.strip())/2
            out = r2.cmd('wa ' + patch)
            print(out)
            out = r2.cmd('s+ %d' % numBytes)
            print(out)
