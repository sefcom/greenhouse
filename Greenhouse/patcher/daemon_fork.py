from .patches import *

class DaemonFork:
    def __init__(self):
        self.priority = 7
        self.patchReady = False
        self.forkFuncs = ["daemon", "daemonize"]
        self.targetAddr = 0
        self.patched = []

    def get_caller_in_trace(self, bintrunk, addr_trace_seq, target_addr):
        if target_addr < 0:
            return -1
        targetIndex = addr_trace_seq.index(target_addr)
        addr_slice = addr_trace_seq[:targetIndex]
        addr_slice = addr_slice[::-1] # search backwards
        for addr in addr_slice:
            if bintrunk.is_program_code(addr):
                caller_addr = bintrunk.get_last_call_instr_addr(addr)
                return caller_addr
        return -1

    def diagnose(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized):
        parent_addr_trace_seq = trace.read_trace(trace.traces[trace.parent_pid])
        parent_addr_trace_seq = bintrunk.unroll_trace(parent_addr_trace_seq)
        self.patchReady = False
        self.targetAddr = -1
        for funcName in self.forkFuncs:
            fork_caller_addr = bintrunk.addr_trace_find_func_callers(parent_addr_trace_seq, funcName)

            # resolve cases where angr cfg does not detect the predecessors correctly
            if fork_caller_addr < 0:
                fork_addr = bintrunk.addr_trace_find_func_callers(parent_addr_trace_seq, funcName)
                fork_caller_addr = self.get_caller_in_trace(bintrunk, parent_addr_trace_seq, fork_addr)

            if fork_caller_addr >= 0 and fork_caller_addr not in self.patched:
                self.targetAddr = fork_caller_addr
                self.patchReady = True
                return True

        return False

    def applyPatch(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, changelog=[]):
        if self.patchReady and self.targetAddr > 0:
            self.patchReady = False

            print("Attempting de-clone patch at %x..." % self.targetAddr)
            numBytes = binary.get_instr_len(self.targetAddr)
            if numBytes is None:
                print("...failed!")
                return False
            nopPatch = NopInstrPatch(binary.arch, self.targetAddr, numBytes)
            binary.addPatch(self.targetAddr, nopPatch)
            binary.applyPatch(self.targetAddr)
            retPatch = SetRetPatch(binary.arch, self.targetAddr, 0x0)
            binary.addPatch(self.targetAddr, retPatch)
            binary.applyPatch(self.targetAddr)
            print("...done!")
            patchLine = "Apply de-clone patch at %x..." % self.targetAddr
            changelog.append("[ROADBLOCK] requires de-daemon patch")
            changelog.append("[DaemonFork] %s" % patchLine)
            return True

        self.patchReady = False
        self.targetAddr = -1
        return False