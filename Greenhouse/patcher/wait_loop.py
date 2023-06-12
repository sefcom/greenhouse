from .patches import *

class WaitLoop:
    def __init__(self):
        self.priority = 3
        self.cycle_nodes = None
        self.parent = None
        self.old_node = None
        self.alt_node = None

    # helper function
    def get_slice_index_for_caller_ret_nodes(self, caller_indexes, return_indexes):
        for i in return_indexes[::-1]:
            for j in caller_indexes[::-1]:
                if j < i:
                    return i, j
        return -1, -1

    def diagnose(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized):
        self.cycle_nodes = None
        self.parent = None
        self.old_node = None
        self.alt_node = None
        if timedout:
            # assuming we looped at least once
            # all addresses in the loop will be present in the trace
            # avoiding any one of them avoids the entire code block that is the loop

            # try checking on two levels - immediate layer and caller layer
            # we do not consider any loops of a higher order
            # we always prioritize patching the inner loop first
            cycle_nodes = bintrunk.get_nodes_in_cycle(trace_path=trace_trunk_path[::-1])
            if len(cycle_nodes) <= 0: # try looking at parents
                last_addr_node = trace_trunk_path[-1]
                caller_node = bintrunk.get_parent_calling_node(last_addr_node, trace_trunk_path)
                
                return_node = bintrunk.get_parent_return_node(last_addr_node, caller_node, trace_trunk_path)
                
                # get nodes between return addr and parent
                caller_indexes = [i for i, x in enumerate(trace_trunk_path) if x == caller_node]
                return_indexes = [i for i, x in enumerate(trace_trunk_path) if x == return_node]
                return_index, caller_index = self.get_slice_index_for_caller_ret_nodes(caller_indexes, return_indexes)

                skip_nodes = []
                if return_index >= 0 and caller_index >= 0:
                    skip_nodes = trace_trunk_path[caller_index+1:return_index]

                if len(skip_nodes) > 0:
                    cycle_nodes = bintrunk.get_nodes_in_cycle(trace_path=trace_trunk_path[::-1], skipList=skip_nodes)

            # second pass
            if len(cycle_nodes) > 0:
                print("Patching a wait loop...")
                self.cycle_nodes = cycle_nodes

                print("Cycle Nodes:")
                print("    --> ", self.cycle_nodes)
                self.parent, self.old_node, self.alt_node = bintrunk.find_cycle_exit(self.cycle_nodes) # alt_node = exit_node

                if self.parent == None or self.old_node == None or self.alt_node == None:
                    print("Unable to find divergence to avoid exits/loops, exiting...")
                    print("   --> ", self.parent, self.old_node, self.alt_node)
                else:
                    print("Divergence Node: %s->%s should become %s->%s" % (self.parent, self.old_node, self.parent, self.alt_node))
                    return True

        return False

    def applyPatch(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, changelog=[]):
        if self.cycle_nodes != None:
            print("Applying WaitLoop Patch...")

            # set up and perform jump address patch
            parent_addr = bintrunk.node_name_to_addr(self.parent)
            new_target_addr = bintrunk.node_name_to_addr(self.alt_node)

            jmp_instr_addr = bintrunk.get_last_jmp_instr_addr(parent_addr)

            if jmp_instr_addr is None:
                print("    - invalid jmp_instr_addr for parent_addr %x" % parent_addr)
                self.cycle_nodes = None
                return False

            # convert offsets for r2 patching
            jmp_instr_addr = jmp_instr_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset
            parent_addr = parent_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset
            new_target_addr = new_target_addr + (binary.base_addr - bintrunk.base_addr) #add base addr offset

            instr_to_patch, op = binary.get_instr(jmp_instr_addr)

            if jmp_instr_addr is None or instr_to_patch is None or op is None:
                print("    - invalid instruction to patch %s, %s at addr %x..." % (instr_to_patch, op, jmp_instr_addr))
                self.cycle_nodes = None
                return False

            patchLine = "    - patching instruction [%s %s] at %x to [jmp %x]" % (instr_to_patch, op, jmp_instr_addr, new_target_addr)
            print(patchLine)
            changelog.append("[ROADBLOCK] requires patching of wait-loop that timed-out")
            changelog.append("[WaitLoop] %s" % patchLine)

            jmpPatch = SwitchJmpPatch(binary.arch, jmp_instr_addr, new_target_addr)
            binary.addPatch(jmp_instr_addr, jmpPatch)
            binary.applyPatch(jmp_instr_addr)

            print("    - Patch Completed!")
            self.cycle_nodes = None
            return True

        self.cycle_nodes = None
        return False