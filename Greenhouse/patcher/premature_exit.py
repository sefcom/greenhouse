from .patches import *

class PrematureExit:    
    def __init__(self):
        self.priority = 5
        self.is_exit = False
        self.avoid_addr = -1
        self.parent = None
        self.old_node = None
        self.alt_node = None

    def diagnose(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized):
        self.avoid_addr = -1
        self.parent = None
        self.old_node = None
        self.alt_node = None
        exit_addr = -1
        self.exit_tags = ["shutdown", "reboot", "die", "exit", "_exit"]

        if timedout == False and exit_code != None:
            parent_addr_trace_seq = trace.read_trace(trace.traces[trace.parent_pid])
            parent_addr_trace_seq = bintrunk.unroll_trace(parent_addr_trace_seq)
            for tag in self.exit_tags:
                exit_addr = bintrunk.addr_trace_find_func_callsites(parent_addr_trace_seq, tag)
                if exit_addr >= 0:
                    print("    - found addr %x for tag %s" % (exit_addr, tag))
                    break

            if exit_addr < 0:
                # check if last touched address is an exit
                last_addr_node = trace_trunk_path[-1]
                for node in bintrunk.graph.nodes:
                    if last_addr_node in str(node):
                        if "exit" in str(node):
                            exit_addr = bintrunk.node_name_to_addr(node)
                            break

            if exit_addr < 0:
                print("Unable to find exit address to avoid, stopping...")
                return False

            if bintrunk.is_program_code(exit_addr):
                self.avoid_addr = exit_addr
            else:
                self.avoid_addr  = bintrunk.node_trace_get_caller_for_addr_in_sequence(trace_trunk_path, exit_addr)

            print("Dodging an exit...")
            print("Finding closest divergence node that avoids previous termination point %x..." % self.avoid_addr)
            # identify branch points
            # try branch points until we avoid the exit
            self.parent, self.old_node, self.alt_node = bintrunk.find_divergence_avoid_node(parent_addr_trace_seq, trace_trunk_path, self.avoid_addr)

            if self.parent == None or self.old_node == None or self.alt_node == None:
                print("Unable to find divergence to avoid exits/loops, exiting...")
                print("   --> ", self.parent, self.old_node, self.alt_node)
                return False

            print("Divergence Node: %s->%s should become %s->%s" % (self.parent, self.old_node, self.parent, self.alt_node))

            self.is_exit = True
            return True
        return False

    def applyPatch(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, changelog=[]):
        if self.is_exit:
            print("Applying PrematureExit Patch...")
            # set up and perform jump address patch
            parent_addr = bintrunk.node_name_to_addr(self.parent)
            new_target_addr = bintrunk.node_name_to_addr(self.alt_node)

            jmp_instr_addr = bintrunk.get_last_jmp_instr_addr(parent_addr)

            if jmp_instr_addr is None:
                print("    - invalid jmp_instr_addr for parent_addr %x" % parent_addr)
                self.is_exit = None
                return False

            # convert offsets for r2 patching
            jmp_instr_addr = jmp_instr_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset
            parent_addr = parent_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset
            new_target_addr = new_target_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset

            instr_to_patch, op = binary.get_instr(jmp_instr_addr)

            if jmp_instr_addr is None or instr_to_patch is None or op is None:
                print("    - invalid instruction to patch %s, %s at addr %x..." % (instr_to_patch, op, jmp_instr_addr))
                self.is_exit = None
                return False

            patchLine = "    - patching instruction [%s %s] at %x to [jmp %x]" % (instr_to_patch, op, jmp_instr_addr, new_target_addr)
            print(patchLine)
            changelog.append("[ROADBLOCK] requires patching of check that leads to exit")
            changelog.append("[PremExit] %s" % patchLine)

            jmpPatch = SwitchJmpPatch(binary.arch, jmp_instr_addr, new_target_addr)
            binary.addPatch(jmp_instr_addr, jmpPatch)
            binary.applyPatch(jmp_instr_addr)

            print("    - Patch Completed!")
            self.is_exit = False
            return True

        self.is_exit = False
        return False