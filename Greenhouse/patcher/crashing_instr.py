from .patches import *

class CrashingInstr:    
    def __init__(self):
        self.priority = 2

    def diagnose(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized):
        self.patchReady = False
        if exit_code != 0 and errored and not timedout:
            self.patchReady = True
            return True
        return False


    def applyPatch(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, changelog=[]):
        if self.patchReady:
            #parent crashed, patch is needed in parent
            last_addrs = trace.get_last_n_code_addrs(50, trace.parent_pid)[::-1]
            last_addr = -1
            prevNode = None
            currNode = None
            for addr in last_addrs:
                prevNode = currNode
                currNode = bintrunk.angr_cfg.model.get_any_node(addr)
                if currNode is None:
                    continue
                if prevNode is not None:
                    if prevNode in currNode.successors:
                        last_addr = prevNode.addr
                        print("    - searching for crashing instruction in cfg from %x" % last_addr)
                        break

            if last_addr < 0:
                print("err - could not find valid starting addr for where crash might have occured that maps to the cfg")
                return False

            instr = binary.get_instr(last_addr)
            if(instr == None):
                print("err - invalid instr at last_addr %x" % last_addr)
                self.patchReady = False
                return False

            next_instr = "nop"
            running_addr = last_addr
            while next_instr is not None and "nop" in next_instr:
                next_instr = binary.get_next_instr(running_addr)
                if(next_instr == None):
                    print("err - invalid next instr from last_addr %x" % running_addr)
                    self.patchReady = False
                    return False

                next_instr_addr = binary.get_next_instr_addr(running_addr)
                running_addr = next_instr_addr

            target_instr_addr = 0
            target_instr = ""

            patchLine = "nop"
            if bintrunk.is_plt(running_addr):
                n = bintrunk.angr_cfg.model.get_any_node(running_addr, anyaddr=True)
                if n is None:
                    print("Unable to find node for addr %x" % running_addr)
                    self.patchReady = False
                    return False
                caller_block_addr = trace.get_caller(trace.parent_pid, bintrunk, n.function_address)
                if caller_block_addr < 0:
                    print("Unable to find caller for patch for addr %x" % running_addr)
                    self.patchReady = False
                    return False
                call_addr = bintrunk.get_last_call_instr_addr(caller_block_addr)
                if call_addr < 0:
                    print("Unable to find call_addr for patch for addr %x" % running_addr)
                    self.patchReady = False
                    return False

                next_instr = binary.get_instr(call_addr)
                target_instr_addr = call_addr
                target_instr = next_instr
                patchLine = "    - Guessing - libcall %s caused crash at [%x]" % (next_instr, call_addr)
            elif trace.is_code(next_instr_addr):
                target_instr_addr = next_instr_addr
                target_instr = next_instr
                patchLine = "    - Guessing - Instr %s caused crash at [%x]" % (next_instr, next_instr_addr)
            else:
                target_instr_addr = last_addr
                target_instr = instr
                patchLine = "    - Guessing - Instr %s caused crash at [%x]" % (instr, last_addr)

            print(patchLine)
            patchLine = "    - patching instruction [%s] at %x with nops" % (target_instr, target_instr_addr)
            print(patchLine)
            changelog.append("[ROADBLOCK] requires patching of crash-causing instruction")
            changelog.append("[CrashInstr] %s" % patchLine)

            numBytes = binary.get_instr_len(target_instr_addr)
            if numBytes is None:
                self.patchReady = False
                return False
            nopPatch = NopInstrPatch(binary.arch, target_instr_addr, numBytes)
            binary.addPatch(target_instr_addr, nopPatch)
            binary.applyPatch(target_instr_addr)
            print("    - Patch Completed!")
            self.patchReady = False
            return True

        self.patchReady = False
        return False