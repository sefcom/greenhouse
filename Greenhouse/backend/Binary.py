import r2pipe
import os, shutil, stat
import angr

import time

#stores all static information about binary
#used as a wrapper interface to r2 to interact with the Binary
#also tracks which patches have been applied (so they can be reversed, future extension)
class Binary:
    MAX_INSTR_SIZE = 15
    JMP_MNEMONICS = ['je', 'jz', 'jne', 'jnz', 'ja', 'jl', 'jge', 'jle', 'jnl', 'jna', 'js'] 
    #hardcoded for now, may have to expand to other cases

    def __init__(self, binary_path, base_addr=0, count=0):
        self.base_addr = base_addr
        self.patches = dict()
        self.patched_addrs = set() # set of patched addresses
        copy_path = self.get_copy_with_count(binary_path, count)

        print("Making copy of binary: %s -> %s" % (binary_path, copy_path))
        shutil.copyfile(binary_path, copy_path)
        perms = os.stat(binary_path)
        os.chown(copy_path, perms[stat.ST_UID], perms[stat.ST_GID])

        #work on the copy, not the original
        self.binary_original_path = copy_path
        self.binary_path = binary_path

        base_addr_flag = "-B 0x%x" % base_addr
        self.r2 = r2pipe.open(self.binary_path, flags=['-w', base_addr_flag])

        i_json = None
        retry = 0
        while i_json is None and retry < 3:
            time.sleep(1)
            i_json = self.r2.cmdj('ij')
            retry += 1
        print("i_json:", i_json)
        self.os = i_json['bin']['os']
        self.arch = i_json['bin']['arch']
        self.bits  = i_json['bin']['bits']
        self.pic  = i_json['bin']['pic']
        self.endian  = i_json['bin']['endian']

        #capstone and keystone, use angr since it automatically sets everything up for us
        self.angr_project = angr.Project(self.binary_path, load_options={'auto_load_libs': False})
        self.cs = self.angr_project.arch.capstone
        self.ks = self.angr_project.arch.keystone

    def get_copy_with_count(self, binary_path, count):
        binary_name = os.path.basename(binary_path)
        directory_path = os.path.dirname(binary_path)
        binary_name_tuple = binary_name.split('.')
        binary_name_stripped = binary_name_tuple[0]
        label = ""
        if len(binary_name_tuple) > 1:
            label = "."+binary_name_tuple[1]
        copy_name = binary_name_stripped+"_"+str(count)+label
        copy_path = os.path.join(directory_path, copy_name)
        return copy_path

    def get_bytecode(self, size):
        if not isinstance(size, int) or size <= 0:
            print("Invalid size", size)
            return None
        bytecode = self.r2.cmdj('pcj ' + str(size))
        if bytecode is None: # retry
            bytecode = self.r2.cmdj('pcj ' + str(size))
            if bytecode is None:
                print("Unknown instruction of size %x" % size)
                return None
        return bytecode

    def get_instr(self, addr):
        if not isinstance(addr, int):
            print("Unknown addr", addr)
            return None, None
        self.r2.cmd('s ' + hex(addr))
        bytecode = self.get_bytecode(self.MAX_INSTR_SIZE)
        if bytecode is None:
            print("Error getting bytecode at addr %x" % addr)
            return None, None
        bytecode = bytes(bytecode)
        instr_array = self.cs.disasm(bytecode, addr)
        ()
        for instr in instr_array:
            return instr.mnemonic, instr.op_str
        #instr not known/found
        print("Unknown instruction at addr %x" % addr)
        return None, None

    def get_instr_len(self, addr):
        if not isinstance(addr, int):
            print("Unknown addr", addr)
            return None
        self.r2.cmd('s ' + hex(addr))
        bytecode = self.get_bytecode(self.MAX_INSTR_SIZE)
        if bytecode is None:
            return -1
        bytecode = bytes(bytecode)
        instr_array = self.cs.disasm(bytecode, addr)
        for instr in instr_array:
            return len(instr.bytes)

    def get_next_instr(self, addr):
        if not isinstance(addr, int):
            print("Unknown addr", addr)
            return None
        self.r2.cmd('s ' + hex(addr))
        bytecode = self.get_bytecode(self.MAX_INSTR_SIZE*2)
        if bytecode is None:
            print("Error getting bytecode at addr %x" % addr)
            return None
        bytecode = bytes(bytecode)
        instr_array = self.cs.disasm(bytecode, addr)
        count = 0
        for instr in instr_array:
            if(count > 0):
                return instr.mnemonic, instr.op_str
            count += 1
        #instr not known/found
        print("Unknown instruction at addr %x" % addr)
        return None

    def get_next_instr_addr(self, addr):
        next_addr_offset = self.get_instr_len(addr)
        if next_addr_offset is None:
            return None
        return addr + next_addr_offset

    def addPatch(self, addrKey, patch):
        self.patches[addrKey] = patch

    def applyPatch(self, addrKey):
        patch = self.patches[addrKey]
        patch.apply(self.r2)
        self.patched_addrs.add(addrKey)

    def restoreCount(self, count):
        countPath = self.get_copy_with_count(self.binary_path, count)
        print("Restoring binary: %s -> %s" % (self.binary_path, countPath))
        if not os.path.exists(countPath):
            print("    - no copy with that count at path [%s] exists, skip!" % countPath)
        shutil.copyfile(countPath, self.binary_path)

    def close(self):
        self.r2.quit()