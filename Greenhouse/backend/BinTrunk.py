import angr
import logging
import networkx
import os
import re
import time



breaknext = False

class BinTrunk:
    def __init__(self, binary_path, trace_path="", max_depth=200):

        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("angr.analyses.cfg.cfg_fast").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("cle.backends.externs").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("pyvex.lifting.libvex").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("angr.analyses.propagator.engine_vex").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("pyvex").setLevel(logging.CRITICAL) #squash angr messages
        logging.getLogger("cle.loader").setLevel(logging.CRITICAL) #squash angr messages
        # logging.getLogger("angr.analyses.cfg.indirect_jump_resolvers").setLevel(logging.DEBUG)

        ### old CFG work around for angr, deprecated
        # builtin_resolvers = angr.analyses.cfg.indirect_jump_resolvers
        # trace_resolvers = builtin_resolvers.default_resolvers.default_indirect_jump_resolvers(self.project.loader.main_object, self.project)
        # if trace_path != "":
        #     if os.path.isfile(trace_path):
        #         print("Using %s trace to support TraceResolver" % trace_path)
        #         self.dyntrace_resolver = angr.analyses.cfg.indirect_jump_resolvers.TraceResolver(self.project, trace_path)
        #         trace_resolvers.append(self.dyntrace_resolver)
        #     else:
        #         print("error, invalid trace_path file %s" % trace_path)

        # print(trace_resolvers)
        try:
            self.angr_cfg = self.project.analyses.CFGFast(detect_tail_calls=True,
                                                        normalize=True,
                                                        data_references=True,)
                                                        # indirect_jump_resolvers=trace_resolvers)

            self.binary_path = binary_path
            self.binary_name = os.path.basename(binary_path)
            self.entry_addr = self.project.entry
            self.main_addr = self.get_main_addr(self.project, self.angr_cfg)
            self.main_start_node = None
            self.graph = networkx.DiGraph()
            self.seen = {}
            self.max_depth = max_depth
            self.base_addr = self.project.loader.main_object.mapped_base
            self.max_addr = self.project.loader.main_object.max_addr
            self.min_addr = self.project.loader.main_object.min_addr
            # print(self.project.arch.name.lower())

            # print("min %x max %x" % (self.min_addr, self.max_addr))

            self.set_offsets()
        except Exception as e:
            self.angr_cfg = None
            print("-"*50)
            print("angr error constructing BinTrunk")
            print("-"*50)
            print(e)
            print("-"*50)

    def set_offsets(self):
        if "arm" in self.project.arch.name.lower():
            self.CALL_OFFSET = 0x4
        elif "mips" in self.project.arch.name.lower():
            self.CALL_OFFSET = 0x4
        elif "x86" in self.project.arch.name.lower():
            self.CALL_OFFSET = 0x5
        elif "amd64" in self.project.arch.name.lower():
            self.CALL_OFFSET = 0x5
        else:
            self.CALL_OFFSET = 0x4 #default to 4

    def get_main_addr(self, project, cfg):
        if "main" in self.angr_cfg.functions.keys():
           return self.angr_cfg.functions['main'].addr

        elif "__libc_start_main" in self.angr_cfg.functions.keys():
            sm = angr.SIM_PROCEDURES['glibc']['__libc_start_main']()
            sm.project = project
            sm.arch = project.arch
            blocks = [project.factory.block(project.entry).vex]
            init, main, fini = sm.static_exits(blocks)
            addrbv = main["address"]
            state = project.factory.entry_state()
            main_addr = state.se.eval(addrbv)
            return main_addr

        print("    - Unable to find <main>, using <entry> instead")
        return project.entry

    def is_syscall(self, addr):
        cfg_node = self.angr_cfg.model.get_any_node(addr)
        if cfg_node == None:
            return False
        return cfg_node.is_syscall


    #gets the last instr addr for a given node block
    #used to figure out the caller address for a call successor
    def get_last_addr_for_node_at_addr(self, addr):
        cfg_node = self.angr_cfg.model.get_any_node(addr)
        return self.get_last_addr_for_node(cfg_node)

    def get_last_addr_for_node(self, cfg_node):
        instrs = cfg_node.instruction_addrs
        caller_addr = cfg_node.addr
        caller_addr = -1
        if len(instrs) > 0:
            caller_addr = instrs[-1]
        return caller_addr

    def get_last_call_instr_addr(self, addr):
        cfg_node = self.angr_cfg.model.get_any_node(addr)
        if cfg_node == None:
            return -1
        instrs = cfg_node.block.capstone.insns

        for instr in instrs[::-1]:
            group_ids = instr.insn.groups
            for group_id in group_ids:
                group_name = instr.insn.group_name(group_id)
                if "call" in group_name:
                    return instr.insn.address
        return -1


    def get_last_jmp_instr_addr(self, addr):
        cfg_node = self.angr_cfg.model.get_any_node(addr)
        instrs = cfg_node.block.capstone.insns

        for instr in instrs[::-1]:
            group_ids = instr.insn.groups
            for group_id in group_ids:
                group_name = instr.insn.group_name(group_id)
                if "jump" in group_name:
                    return instr.insn.address
        return None


    #get the addr of the specific caller in the callstack that the node
    #returns to, where rets is the list of all successors in a node that has_return
    def get_caller_addr(self, callstack):        
        if len(callstack) <= 0:
            return -1
        return callstack[-1]

    #pop addresses off a list callstack until <addr> is the last addr removed
    #used to clear the callstack when returning
    def clear_callstack_to_addr(self, callstack, addr):
        reversed_callstack = callstack[::-1].copy()
        for caddr in reversed_callstack:
            callstack.pop()
            if caddr == addr:
                return True
        return False

    #extracts the actual block addr from the node_name
    def node_name_to_addr(self, node_name):
        if node_name == "entry":
            return self.entry_addr
        node_array = re.split("[_\]]", node_name)
        if len(node_array) <= 1:
            #raise error?
            return node_name
        addrstring = node_array[1]
        return int(addrstring, 16)

    def get_cfg_node_w_last_addr_in_parents(self, parents, target_last_addr):
        for node_name in parents[::-1]:
            node_addr = self.node_name_to_addr(node_name)
            cfg_node = self.angr_cfg.model.get_any_node(node_addr)
            last_cfg_node_addr = self.get_last_addr_for_node(cfg_node)
            if target_last_addr == last_cfg_node_addr:
                return cfg_node
        return None

    # checks if next_node is the immediate next block after start_node
    def is_next_block(self, start_node, next_node):
        # check that start_node block actually has instructions
        if len(start_node.block.capstone.insns) <= 0:
            return False

        last_instr_addr = start_node.block.capstone.insns[-1].address
        next_instr_addr = last_instr_addr + start_node.block.capstone.insns[-1].size

        next_node_addr = next_node.addr

        if next_instr_addr == next_node_addr:
            return True

        return False

    def is_valid_ret(self, parents, ret_addr, caller_addr):
        #check ret addr is the right offset from the caller
        if ret_addr != caller_addr + self.CALL_OFFSET:
            print("Wrong Offset")
            return False

        #check a ret node and caller node exists, and that they share the same function
        caller_node = self.get_cfg_node_w_last_addr_in_parents(parents, caller_addr)
        ret_node = self.angr_cfg.model.get_any_node(ret_addr)
        if caller_node == None or ret_node == None:
            print("caller/ret node is NONE")
            return False

        #check ret_node isn't an alignment that bleeds into another function\
        ret_successors = self.angr_cfg.model.get_successors_and_jumpkind(ret_node)
        for s,j in ret_successors:
            # check that successor isnt the result of "stepping" into another function
            # an explicit jump, call or return is fine
            if 'Ijk_Boring' in j and self.is_next_block(ret_node, s) and s.function_address != ret_node.function_address:
                print("successor is the result of stepping into another function")
                return False

        return True

    #tests if an addr is in the main segment of a binary
    def is_program_code(self, addr):
        return addr < self.max_addr and addr >= self.min_addr

    def node_has_call(self, node):
        s_and_j = self.angr_cfg.model.get_successors_and_jumpkind(node)
        for s,j in s_and_j:
            if "Unresolvable" not in str(s) and  "Call" in str(j):
                return True
        return False

    # check if an addr is an instruction in a plt
    def is_plt(self, addr):
        n = self.angr_cfg.model.get_any_node(addr, anyaddr=True)
        if n:
            return self.angr_cfg.functions[n.function_address].is_plt
        return False

    def add_limit_node(self, node_name, child_name):
        limit_node_name = child_name+"_limit"
        self.graph.add_node(limit_node_name)
        self.graph.add_edge(node_name, limit_node_name)

    #appends an '_exit' label node to the given node
    def add_exit(self, node_name, child_name):
        exit_node_name = child_name+"_exit"
        self.graph.add_node(exit_node_name)
        self.graph.add_edge(node_name, exit_node_name)


    #main function for traversing and construction a context-aware CFG of the binary
    def traverse_and_build(self, cfg_node, parents, callstack, fakrets, depth, max_level, verbose):
        """
        cfg_node - the node in the angr_cfg to be processed
        parents - the chain of node names in the networkx graph, self.graph, in the this recursive call
        callstack - the calling context underwhich this node is called
        depth - the current recursive depth (note - might be the same as parent, cut if the case)
        """

        next_jobs = []

        #generate current node name
        curr_addr = cfg_node.addr

        #check if addr has been encountered before under a different context
        if curr_addr not in self.seen.keys():
            self.seen[curr_addr] = {'COUNT' : 0, 'CALLSTACKS' : {}}

        #name is [NumTimesSeen]0x<addr>
        #this forces network to differentiate between nodes called under diff contexts
        seen_count = self.seen[curr_addr]['COUNT']
        self.seen[curr_addr]['COUNT'] += 1
        node_name = "[%d]0x%x" % (seen_count, curr_addr)

        #get parent node name
        parent_node_name = "DANGLING" #should never show up
        if len(parents) > 0:
            parent_node_name = parents[-1]
        else:
            raise(Exception("No parent found for cfg_node %s" % cfg_node))

        #if maxdepth reached, label parent-to-self transition, add max-depth tail and skip
        if self.max_depth >= 0 and depth > self.max_depth: #negative value means no max limit
            if verbose:
                print("MAX DEPTH REACHED")
            self.add_limit_node(parent_node_name, node_name)
            return next_jobs

        #check if already processed under specified callstack context
        #match against map of seen[node_name][callstack_tuple]
        if tuple(set(callstack[-max_level:])) in self.seen[curr_addr]['CALLSTACKS'].keys():
            node_name = self.seen[curr_addr]['CALLSTACKS'][tuple(set(callstack[-max_level:]))]
            if verbose:
                print("    ----! %s already processed!" % node_name) #seen, use previous node name
            self.graph.add_edge(parent_node_name, node_name)
            return next_jobs #do not process successors

        # add node + transition to simplified graph
        # if self.is_program_code(curr_addr): #skip nodes that are outside the .text section
        self.graph.add_node(node_name)
        self.graph.add_edge(parent_node_name, node_name)

        #save a reference to the node corresponding to the main entry point
        if self.main_start_node == None and "entry" in parent_node_name:
            self.main_start_node = node_name

        # add to processed nodes
        self.seen[curr_addr]['CALLSTACKS'][tuple(set(callstack[-max_level:]))] = node_name

        if verbose:
            print("[%d] Added node %s" % (depth, node_name))
            print("    parent [%s]" % parent_node_name)
            print("    edge %s -> %s" % (parent_node_name, node_name))
            print("    callstack ", [hex(addr) for addr in callstack[-max_level:]])

        #process successors
        successors_with_jk = self.angr_cfg.model.get_successors_and_jumpkind(cfg_node)

        has_unresolved = False
        callees = []
        jumps = []
        handle_ret = False

        if len(successors_with_jk) <= 0: #no successors, treat as a terminating leaf
            # edge case, handle simprocedure that is also a tailcall
            # successor should return to caller of tailcall
            if cfg_node.is_simprocedure and cfg_node.has_return:
                handle_ret = True
            else:
                if verbose:
                    print("No Successors found for ", cfg_node)
                self.add_exit(node_name, node_name)
                #NOTE: may instead need to filter on calls to _exit
                return next_jobs

        #sort successors by jk, treat all none calls/rets as jumps
        for sjk in successors_with_jk:
            jk = sjk[1]
            s = sjk[0]
            if 'Unresolvable' in str(s):
                has_unresolved = True
            elif 'Ijk_Call' in jk or 'Ijk_Sys_syscall' in jk:
                callees.append(s)
            elif 'Ijk_Ret' in jk:
                handle_ret = True
            else:
                jumps.append(s)

        #handle case where call is unresolvable (dynamic jump)
        if has_unresolved:
            #skip the call and treat as a jump to the block after (assumes that the call returns to the subsequent block)
            successors_w_jk_w_fakerets = self.angr_cfg.model.get_successors_and_jumpkind(cfg_node, excluding_fakeret=False)
            for sjk in successors_w_jk_w_fakerets:
                jk = sjk[1]
                s = sjk[0]
                if 'Ijk_FakeRet' in jk and s not in jumps and s not in callees:
                    if s.function_address == cfg_node.function_address: #ensure we aren't skipping to a diff function
                        jumps.append(s)
                    else: #if the fakeret leads to another function, its probably meant to return instead
                        handle_ret = True
            if not handle_ret: # no ret handling found, fake ret needs to be handled by parent
                # print("[%d] Handling unresolvable jmp/call @%x by returning to the fakeret site" % (curr_addr, depth))
                caller_addr = self.get_caller_addr(callstack)
                if caller_addr in fakrets.keys() and fakrets[caller_addr][0] != None:
                    (fakret_node, fkr_parents, fkr_callstack, fkr_depth) = fakrets[caller_addr]
                    new_parents = parents.copy()
                    new_parents.append(node_name)
                    next_callstack = callstack.copy()
                    if not self.clear_callstack_to_addr(next_callstack, caller_addr):
                        raise(Exception("unable find address %x to clear in callstack" % caller_addr))
                    if verbose:
                        print("    Next: RET -> %x" % fakret_node.addr)
                    next_jobs.append((fakret_node, new_parents, next_callstack, fakrets, depth+1))
        #process rets

        if handle_ret:
            caller_addr = self.get_caller_addr(callstack)
            if caller_addr < 0: #cannot find ret address from successors
                if verbose:
                    print("Unable to locate return address for %s" % node_name)
                #unable to find any return address, assume is leaf
                self.add_exit(node_name, node_name)
                return next_jobs

            ret_addr = caller_addr+self.CALL_OFFSET
            if not self.is_valid_ret(parents, ret_addr, caller_addr):
                #ret address is invalid as we return to an address outside the calling function
                if verbose:
                    print("Invalid ret address 0x%x for %s (caller_addr = %x, offset = %x)" % (ret_addr, node_name, caller_addr, self.CALL_OFFSET))

                self.add_exit(node_name, node_name)
                return next_jobs

            #clear callstack context as we return
            next_callstack = callstack.copy()
            if not self.clear_callstack_to_addr(next_callstack, caller_addr):
                raise(Exception("unable find address %x to clear in callstack" % caller_addr))

            #recursively process successors
            ret_node = self.angr_cfg.model.get_any_node(ret_addr)
            # print("ret addr %x, node: %s" % (ret_addr, ret_node))
            new_parents = parents.copy()
            new_parents.append(node_name)
            if verbose:
                print("    Next: RET -> %x" % ret_node.addr)
            next_jobs.append((ret_node, new_parents, next_callstack, fakrets, depth+1))

        #process callees
        if len(callees) > 0:
            # prep potential fakerets
            fakeret = None
            successors_w_jk_w_fakerets = self.angr_cfg.model.get_successors_and_jumpkind(cfg_node, excluding_fakeret=False)
            for sjk in successors_w_jk_w_fakerets:
                jk = sjk[1]
                s = sjk[0]
                if 'Ijk_FakeRet' in jk and s not in jumps and s not in callees:
                    if s.function_address == cfg_node.function_address: #ensure we aren't skipping to a diff function
                        fakeret = s

            for c in callees:
                #setup new callstack for called function
                next_callstack = callstack.copy()
                last_addr = self.get_last_addr_for_node(cfg_node)
                next_callstack.append(last_addr)

                # process successors
                new_parents = parents.copy()
                new_parents.append(node_name)
                fakrets[last_addr] = (fakeret, new_parents, next_callstack, depth+1)
                if verbose:
                    print("    Next: CALL -> %x" % c.addr)
                # self.traverse_and_build(c, new_parents, next_callstack, depth+1, verbose)
                next_jobs.append((c, new_parents, next_callstack, fakrets, depth+1))


        #process jumps
        if len(jumps) > 0:
            for j in jumps:
                next_callstack = callstack.copy()

                #recursively process successors
                new_parents = parents.copy()
                new_parents.append(node_name)
                if verbose:
                    print("    Next: JMP -> %x" % j.addr)
                next_jobs.append((j, new_parents, next_callstack, fakrets, depth+1))

        return next_jobs

    def color_exits(self, dot_graph):
        for i, node in enumerate(dot_graph.get_nodes()):
            addrname = str(node)
            if '_exit' in addrname:
                node.set_color("red")
            if '_limit' in addrname:
                node.set_color("orange")

            ## debug code, mark specific addresses
            # if '40447c' in addrname:
            #     node.set_color("green")
            #     print("FOUND TARGET ADDR", addrname)

    def mark_for_pruning_until_node(self, graph, curr_node, target_nodes, prune_set):
        if curr_node in target_nodes:
            return
        if curr_node in prune_set:
            return

        if graph.has_node(curr_node):
            # print("marked for pruning: ", curr_node)
            prune_set.add(curr_node)

        successors = list(graph.successors(curr_node))
        if len(successors) <= 0:
            raise(Exception("trying to prune to node with no predecessor [curr node %s target_nodes %s]" % (curr_node, target_nodes)))

        for s in successors:
            self.mark_for_pruning_until_node(graph, s, target_nodes, prune_set)


    def merge_exits(self, reversed_graph, exit_nodes):
        performed_merge = False
        for node in exit_nodes:
            if reversed_graph.has_node(node): #check if we already processed this exit node via its partner
                for dominance_node in list(reversed_graph.successors(node)):
                    #check all nodes linked to the calling node are _exit nodes
                    # print("Trying merge for ", dominance_node)
                    all_are_exits = True
                    for predecessor in list(reversed_graph.predecessors(dominance_node)):
                        # print("predecessor: ", predecessor)
                        if "_exit" not in str(predecessor):
                            all_are_exits = False
                    if all_are_exits: #all predecessor nodes in the rev graph are exits
                        #remove exits and relabel calling node as an exit
                        # print("Merging nodes for ", dominance_node)
                        for predecessor in list(reversed_graph.predecessors(dominance_node)):
                            if reversed_graph.has_node(predecessor):
                                reversed_graph.remove_node(predecessor)
                        #relabel and relink the dominance_node as the new exit node
                        new_exit_node = dominance_node+"_exit"
                        reversed_graph.add_node(new_exit_node)
                        for successor in list(reversed_graph.successors(dominance_node)):
                            reversed_graph.add_edge(new_exit_node, successor)
                            reversed_graph.remove_edge(dominance_node, successor)
                        reversed_graph.remove_node(dominance_node)
                        performed_merge = True

        return performed_merge

    def prune_exits(self):
        reversed_graph = self.graph.reverse()       
        leaf_nodes = []
        #get all exit leafs
        for node_name in reversed_graph.nodes:
            #leaf nodes in the reversed graph are nodes with no predecessor
            if len(list(reversed_graph.predecessors(node_name))) <= 0:
                leaf_nodes.append(node_name)

        #make all leaves originate from the same 'exit' node
        reversed_graph.add_node("leaf")
        for en in leaf_nodes:
            reversed_graph.add_edge("leaf", en)

        #this lets use use networkx dominance frontier to identify
        #nodes that we can "prune"
        post_dom_map = networkx.dominance_frontiers(reversed_graph, "leaf")
        exit_node_map = {} #note that leaf nodes aren't necessarily exit nodes
        for k in post_dom_map.keys(): 
            if "_exit" in str(k): 
                exit_node_map[k] = post_dom_map[k]
        # for k in exit_node_map.keys():
        #     print(k, exit_node_map[k])

        #recursively prune each exit node to dominance frontier
        prune_set = set()
        frontier_map = {}
        for exit_node in exit_node_map.keys():
            dominance_frontier_nodes = exit_node_map[exit_node]
            for dominance_frontier_node in dominance_frontier_nodes:
                if dominance_frontier_node not in frontier_map.keys():
                    frontier_map[dominance_frontier_node] = []
                frontier_map[dominance_frontier_node].append(exit_node)
                # print(exit_node, dominance_frontier_node)
            self.mark_for_pruning_until_node(reversed_graph, exit_node, dominance_frontier_nodes, prune_set)

        for to_be_pruned_node in prune_set:
            if reversed_graph.has_node(to_be_pruned_node):
                reversed_graph.remove_node(to_be_pruned_node)

        for frontier_node in frontier_map.keys():
            for exit_node in frontier_map[frontier_node]:
                if reversed_graph.has_node(frontier_node):
                    reversed_graph.add_edge(exit_node, frontier_node)

        reversed_graph.remove_node("leaf")
        performed_merge = self.merge_exits(reversed_graph, exit_node_map.keys())
        new_graph = reversed_graph.reverse()
        # print("Performed Merge: ", performed_merge)
        self.graph = new_graph

        if performed_merge:
            self.prune_exits()

        return

    def build_graph(self, verbose=True, max_level=8):
        callstack = []
        depth = 0
        main_start_node = self.angr_cfg.model.get_any_node(self.main_addr)
        print("main addr %x" % self.main_addr)
        print(main_start_node)
        parents = ["entry"]
        next_jobs = []
        fakrets = {}

        next_jobs.append((main_start_node, parents, callstack, fakrets, 0))
        while len(next_jobs) > 0:
            (node, parents, callstack, fakrets, depth) = next_jobs.pop(0)
            # print("[-] Processing Node: %s" % node)
            new_jobs = self.traverse_and_build(node, parents, callstack, fakrets, depth, max_level, verbose)
            next_jobs = new_jobs + next_jobs

        if self.max_depth >= 0:
            print("===== Trunk Graph [depth=%d] Complete =====" % self.max_depth)
        else:
            print("===== Trunk Graph [Full] Complete =====")

    def highlight_trace_and_dump_graph(self, trace, mark=[]):
        print("Drawing dot graph for %s" % self.binary_name)
        start_time = time.time()
        dot_graph = networkx.nx_pydot.to_pydot(self.graph)

        self.color_exits(dot_graph)
        for i, node in enumerate(dot_graph.get_nodes()):
            node_name = str(node)[1:-2]
            if node_name in trace:
                node.set_color("blue")
        for i, node in enumerate(dot_graph.get_nodes()):
            node_name = str(node)[1:-2]
            if node_name in mark:
                node.set_color("green")

        graph_name = '%s_%d' % (self.binary_name, self.max_depth)
        if self.max_depth < 0:
            graph_name = '%s_full' % self.binary_name
        dot_graph.write(graph_name+".dot")

        end_time = time.time()
        time_taken = end_time - start_time
        print("...done.")
        print("Drawing Graph + Trace for %s took %f seconds" % (self.binary_name, time_taken))
        print("===== Done =====")

    def dump_graph(self):
        print("Drawing .dot graph for %s" % self.binary_name)
        start_time = time.time()
        dot_graph = networkx.nx_pydot.to_pydot(self.graph)
        print("done converting!")
        self.color_exits(dot_graph)
        graph_name = '%s_%d' % (self.binary_name, self.max_depth)
        print("done coloring!")
        if self.max_depth < 0:
            graph_name = '%s_full' % self.binary_name

        dot_graph.write_dot(graph_name+".dot")

        end_time = time.time()
        time_taken = end_time - start_time
        print("...done.")
        print("Drawing Graph for %s took %f seconds" % (self.binary_name, time_taken))
        print("===== Done =====")

    def addr_in_block(self, addr, node_name):
        node_addr = self.node_name_to_addr(node_name)
        node = self.angr_cfg.model.get_any_node(node_addr)
        if node == None:
            return False
        if node.block == None:
            return False

        blockaddrs = node.block.instruction_addrs
        if addr in blockaddrs:
            return True
        return False

    def has_multiple_predecessors(self, node_name):
        node_addr = self.node_name_to_addr(node_name)
        node = self.angr_cfg.model.get_any_node(node_addr)
        if node == None:
            return False

        predecessors = self.angr_cfg.get_predecessors(node)
        if len(predecessors) >= 2:
            return True
        return False


    def can_merge_with_successor(self, node_name):
        # we merge with the successor if the curr node
        # has only one successor
        # and that successor has no other predecessor

        node_addr = self.node_name_to_addr(node_name)
        node = self.angr_cfg.model.get_any_node(node_addr)
        if node == None:
            return False

        next_nodes = self.angr_cfg.get_successors(node)
        if len(next_nodes) > 1 or len(next_nodes) <= 0:
            return False

        next_node = next_nodes[0]

        next_node_predecessors = self.angr_cfg.get_predecessors(next_node)
        if len(next_node_predecessors) > 1 or len(next_node_predecessors) <= 0:
            return False
        return True


    def get_node_with_name(self, node_name):
        for node in self.angr_cfg.nodes():
            if node.name == node_name:
                return node
        return None

    def get_caller_addrs_for_node_name(self, node_name):
        callers = []
        node = self.get_node_with_name(node_name)

        if node == None:
            return []

        callers = self.angr_cfg.get_predecessors(node)
        addrs = [c.addr for c in callers]
        return addrs

    def node_trace_get_caller_for_addr_in_sequence(self, node_trace, callee_addr):        
        index = 0
        node_trace = node_trace[::-1] # reverse
        for node in node_trace:
            index += 1
            addr = self.node_name_to_addr(node)
            if addr == callee_addr:
                break

        node_trace = node_trace[index:]

        caller_addr = -1
        for node in node_trace:
            addr = self.node_name_to_addr(node)
            if self.is_program_code(addr):
                caller_addr = addr
                break

        return caller_addr


    def addr_trace_find_func_callers(self, addr_trace, func_name):
        if func_name in self.angr_cfg.functions.keys():
            addr = self.angr_cfg.functions.function(name=func_name).addr
            # check if addr trace contains callers of addr
            n = self.angr_cfg.model.get_any_node(addr)
            callers = self.angr_cfg.model.get_predecessors(n)
            for c in callers:
                if c.addr in addr_trace:
                    last_addr = self.get_last_call_instr_addr(c.addr)
                    return last_addr

        return -1

    def addr_trace_get_caller_for_addr(self, addr_trace, callee_addr):
        if callee_addr not in addr_trace:
            return -1

        addr_trace = addr_trace[::-1] # reverse

        index = 0
        for addr in addr_trace:
            index += 1
            if addr == callee_addr:
                break

        addr_trace = addr_trace[index:]

        caller_addr = -1
        for addr in addr_trace:
            if self.is_program_code(addr):
                n = self.angr_cfg.model.get_any_node(addr)
                if n is None:
                    break
                successors = self.angr_cfg.model.get_successors_and_jumpkind(n)
                if len(successors) != 1:
                    break
                if 'Call' in successors[0][1]:
                    caller_addr = addr

                # else
                break

        return caller_addr

    def unroll_trace(self, addr_trace, max_depth=10):
        new_trace = []
        for i in range(len(addr_trace) - 1):
            curr_addr = addr_trace[i]
            next_addr = addr_trace[i+1]
            curr_node = self.angr_cfg.model.get_node(curr_addr)
            if curr_node:
                successors = curr_node.successors
                nodes = [curr_node]
                depth = 0
                while len(successors) == 1 and depth < max_depth:
                    curr_node = successors[0]
                    if not curr_node.block or curr_node.addr == next_addr:
                        break
                    nodes.append(curr_node)
                    successors = curr_node.successors
                    depth += 1
                for n in nodes:
                    instructions = n.block.instruction_addrs
                    for i in instructions:
                        new_trace.append(i)
        if len(new_trace) <= 0:
            return addr_trace
        return new_trace



    def addr_trace_find_func_callsites(self, addr_trace, func_name):
        callsites = self.get_graph_callsites_for_name(func_name)
        for node_name in callsites:
            addr = self.node_name_to_addr(node_name)
            if addr in addr_trace:
                return addr
        return -1

    def get_trace_nodes_in_graph(self, addr_trace):
        nodes = set()
        for node_name in self.graph.nodes():
            addr = self.node_name_to_addr(node_name)
            if addr in addr_trace:
                nodes.add(node_name)
                for succ in self.graph.successors(node_name):
                    if self.addr_in_block(addr, succ):
                        nodes.add(succ)
                    if self.is_program_code(self.node_name_to_addr(succ)):
                        nodes.add(succ)

        return nodes

    def get_graph_callsites_for_name(self, func_name):
        all_callsites = set()
        if func_name in self.angr_cfg.functions.keys():
            func_addr = self.angr_cfg.functions[func_name].addr
            func_node = self.angr_cfg.model.get_any_node(func_addr)
            if func_node == None:
                return all_callsites

            parent_nodes = self.angr_cfg.model.get_predecessors(func_node)
            for parent_node in parent_nodes:
                parent_addr = parent_node.addr
                caller_nodes = self.get_all_nodes_with_addr(parent_addr)
                all_callsites.update(set(caller_nodes))
        else:
            print("Func_name %s not found in angr_cfg" % func_name)
        return all_callsites


    def map_trace_to_graph(self, addr_trace, trace_base_addr=0):
        #run until main_addr
        main_addr_index = -1
        next_instr = -1
        index = 0
        offset = 0
        if trace_base_addr > 0:
            offset = self.base_addr - trace_base_addr

        #slice addr trace to start from "main"
        for instr_addr in addr_trace:
            if instr_addr+offset == self.main_addr:
                main_addr_index = index
                break
            index += 1

        if main_addr_index < 0:
            print("main addr %x not in trace, aborting..." % self.main_addr)
            return [], -1

        addr_trace = addr_trace[main_addr_index+1:] #start from the next instr in trace

        trace_path = [self.main_start_node]
        #iterate over trace
        curr_node = self.main_start_node
        skip_instr_flag = False

        next_nodes = list()
        for next_instr in addr_trace:
            next_nodes = list(self.graph.successors(curr_node))
            if len(next_nodes) > 1: #multiple succs
                for n in next_nodes: #select one succ and continue
                    # handle case where node goes out of program code
                    if not self.is_program_code(self.node_name_to_addr(n)):
                        next_next_nodes = list(self.graph.successors(n))
                        while len(next_next_nodes) == 1:
                            next_next_succ = next_next_nodes[0]
                            if self.is_program_code(self.node_name_to_addr(next_next_succ)):
                                n = next_next_succ
                                break
                            next_next_nodes = list(self.graph.successors(next_next_succ))
                            # else
                            # keep trying to naively find a return node in program space
                    if hex(next_instr) in n:
                        trace_path.append(n)
                        curr_node = n
                        break
            elif len(next_nodes) == 1:

                n = next_nodes[0]
                # if next node matches, continue
                # print("   - ", n)
                if hex(next_instr) in n:
                    trace_path.append(n)
                    curr_node = n
                    continue
                else:
                    # no match, try to merge single successors until
                    # a match is found
                    skip_node = n
                    skipped_nodes = []
                    found = False
                    seen = set()
                    skipped_next_nodes = next_nodes

                    # skip over single successors until no or multiple successors
                    while True:
                        #either there is only 1 successor, or it jumps to outside funcs that
                        #eventually return here
                        if len(skipped_next_nodes) != 1:
                            all_outside = True
                            for sn in skipped_next_nodes:
                                #if multiple successors, all must be to outside addrs
                                if self.is_program_code(self.node_name_to_addr(sn)):
                                    #else, break the outer loop
                                    all_outside = False
                            if not all_outside or len(skipped_next_nodes) == 0:
                                break
                            else:
                                #handle case with multiple jumps to outside funcs
                                #skip over to the return point
                                #NOTE: we assume only one jump point that immediately returns after
                                ()
                                ret_node = None
                                for sn in skipped_next_nodes:
                                    return_nodes = list(self.graph.successors(sn))
                                    if len(return_nodes) != 1:
                                        print("Error multiple return nodes")
                                        ret_node = None
                                        break

                                    if ret_node != None and return_nodes[0] != ret_node:
                                        print("Error return nodes dont match")
                                        ret_node = None
                                        break

                                    ret_node = return_nodes[0]

                                if ret_node == None:
                                    break

                                #resolved outside jump that converges to return node
                                #skip previous node and restart the outer loop from here
                                skipped_nodes.append(skip_node)
                                for sn in skipped_next_nodes:
                                    skipped_nodes.append(sn)

                                skip_node = ret_node
                                skipped_next_nodes = list(self.graph.successors(skip_node))
                                continue

                        # add the skipped successors to a list
                        skipped_nodes.append(skip_node)
                        skipped_next_nodes = list(self.graph.successors(skip_node))

                        # search for matching addr in successors
                        for sn in skipped_next_nodes:
                            if hex(next_instr) in sn: # if match, we're done
                                curr_node = sn
                                found = True
                                break
                        if found: # break out of the outer loop
                            break

                        # clean up seen nodes to break potential infinite loop
                        for seen_node in seen:
                            if seen_node in skipped_next_nodes:
                                skipped_next_nodes.remove(seen_node)

                        if len(skipped_next_nodes) > 0:
                            # print("    - %s -> %s" % (skip_node, skipped_next_nodes[0]))
                            seen.add(skip_node)
                            skip_node = skipped_next_nodes[0]

                        # check for exit node
                        if "_exit" in skip_node:
                            # special case - we exit, so thats a match for whatever
                            curr_node = skip_node
                            found = True
                            break

                    if found:
                        for skip_node in skipped_nodes:
                            trace_path.append(skip_node)
                        trace_path.append(curr_node)
                    # else: # fail
                    #     print("trying to reach next nodes %s from curr_node %s, next_instr = %x" % (list(next_nodes), curr_node, next_instr))
                    #     break
            else: # 0 successors, error
                print("Error, no successors left for curr_node %s next_instr = %x" % (curr_node, next_instr))
                ()
                break

            index += 1

        print("Last reached Node: ", curr_node)
        print("Last Addr: ", hex(next_instr))
        print("Next Nodes: ", next_nodes)

        return trace_path, index

    def get_function_addr_from_cfg(self, addr):
        node =  self.angr_cfg.model.get_any_node(addr)
        if node == None:
            return -1

        return node.function_address

    def get_parent_calling_node(self, last_addr_node, trace_path):
        if last_addr_node == None:
            return None

        addr = self.node_name_to_addr(last_addr_node)
        func_addr = self.get_function_addr_from_cfg(addr)
        caller_node = None
        prev_addr = -1
        for node_name in trace_path[::-1]:
            if prev_addr == func_addr:
                caller_node = node_name
                break
            prev_addr = self.node_name_to_addr(node_name)

        return caller_node

    def get_parent_return_node(self, last_addr_node, parent_caller_node, trace_path):
        if last_addr_node == None or parent_caller_node == None:
            return None

        parent_indexes = [i for i, x in enumerate(trace_path) if x == parent_caller_node]
        parent_caller_addr = self.node_name_to_addr(parent_caller_node)
        parent_func_addr = self.get_function_addr_from_cfg(parent_caller_addr)

        return_node = None
        for i in parent_indexes[::-1]: # start from the back
            path = trace_path[i:]
            for node in path:
                addr = self.node_name_to_addr(node)
                func_addr = self.get_function_addr_from_cfg(addr)
                if func_addr == parent_func_addr and node != parent_caller_node:
                    return_node = node
                    break
            if return_node != None:
                break

        return return_node

    def get_all_nodes_with_addr(self, address):
        addr_hexname = hex(address)
        nodes = []
        for node in self.graph.nodes:
            if addr_hexname in str(node):
                nodes.append(node)
        return nodes

    def has_path_to_addr(self, start_node, target_address):
        target_nodes = self.get_all_nodes_with_addr(target_address)
        for target_node in target_nodes:
            if networkx.has_path(self.graph, start_node, target_node):
                return True
        return False

    def get_reachable_node_with_addr(self, start_node, target_address):
        target_nodes = self.get_all_nodes_with_addr(target_address)
        # print("   - trying %d nodes for %x" % (len(target_nodes), target_address))
        for target_node in target_nodes:
            if start_node == target_node:
                continue
            if networkx.has_path(self.graph, start_node, target_node):
                return target_node
        return None

    def get_nearest_node_with_addr(self, start_node, target_address, MAX_DISTANCE=100):
        target_nodes = self.get_all_nodes_with_addr(target_address)
        # print("   - trying %d nodes for %x" % (len(target_nodes), target_address))
        shortest_path_length = MAX_DISTANCE
        shortest_node = None
        for target_node in target_nodes:
            if start_node == target_node:
                continue
            if networkx.has_path(self.graph, start_node, target_node):
                path_length = networkx.shortest_path_length(self.graph, start_node, target_node)
                if path_length < shortest_path_length:
                    shortest_path_length = path_length
                    shortest_node = target_node
        return shortest_node

    def has_path_of_max_size(self, node, target_node, max_size=20):
        return  networkx.has_path(self.graph, node, target_node) and \
                networkx.shortest_path_length(self.graph, node, target_node) < max_size


    def find_cycle_exit(self, cycle_nodes, MAX_LOOP_SIZE=30):
        node_in_cycle = cycle_nodes[0]
        MAX_DISTANCE = len(cycle_nodes) + MAX_LOOP_SIZE
        for node in cycle_nodes:
            successors = list(self.graph.successors(node))
            if len(successors) != 2:
                continue
            for s in successors:
                # we ignore cycles of greater than 20 blocks large
                if not self.has_path_of_max_size(s, node_in_cycle, MAX_DISTANCE):
                    old_node = None
                    for other_node in successors:
                        if other_node != s:
                            old_node = other_node
                    return node, old_node, s
        return None, None, None

    def get_nodes_in_cycle(self, trace_path, MAX_LOOP_SIZE=30, skipList=[]):
        # we assume a cycle is when a node is encountered again
        # nodes_encountered = list()
        tempGraph = networkx.DiGraph()

        prevNode = None
        for node in trace_path:
            if prevNode == None:
                tempGraph.add_node(node)
            else:
                tempGraph.add_edge(prevNode, node)
            prevNode = node
            cycles = list(networkx.simple_cycles(tempGraph))
            if len(cycles) > 0:
                print("    ===> [Cycles]", cycles)
                return cycles[0]
        return []

    def find_divergence_avoid_node(self, raw_trace, trace_path, addr, MAX_LOOP_SIZE=10):
        avoid_nodes = []
        raw_trace = raw_trace[::-1]
        cutoff = 0
        if addr in raw_trace:
            cutoff = raw_trace.index(addr)
        raw_trace = raw_trace[cutoff:]
        for raw_addr in raw_trace:
            if self.is_program_code(raw_addr):
                avoid_nodes = self.get_all_nodes_with_addr(raw_addr)
                if len(avoid_nodes) > 0:
                    break

                # else
                # can't find an avoid node with targeted addr in graph
                # likely pruned, search upwards until we find the
                # nearest frontier node

        if len(avoid_nodes) <= 0: # searched upwards, was not able to find
            print("   --> unable to find avoid node at addr %x" % addr)
            return None, None, None

        parent_node = None
        old_node = None
        alt_node = None
        orig_successor = None

        reversed_trace_path = trace_path[::-1] #iterate backwards
        avoid_index = 0
        for trace_node in reversed_trace_path:
            if self.node_name_to_addr(trace_node) == addr:
                break
            avoid_index += 1
        reversed_trace_path = reversed_trace_path[avoid_index:]

        count = 1
        subfunc_latch = False
        angr_avoid_node = self.angr_cfg.model.get_node(addr)
        avoid_func_addr = angr_avoid_node.function_address
        for node in reversed_trace_path:
            # print(node, subfunc_latch)
            angr_node = self.angr_cfg.model.get_node(self.node_name_to_addr(node))
            if angr_node and avoid_func_addr:
                current_func_addr = angr_node.function_address
                # print("    - checking curr: %x vs avoid: %x" % (current_func_addr, avoid_func_addr))
                # print("       - has_return", angr_node.has_return)
                if subfunc_latch:
                    if current_func_addr == avoid_func_addr:
                        # we have returned
                        subfunc_latch = False
                    else:
                        # print("   - skip!")
                        count += 1
                        continue
                elif angr_node.has_return and current_func_addr != avoid_func_addr:
                    subfunc_latch = True
                    # entered a subfunction before the exit call, skip
                    # print("   - skip!")
                    count += 1
                    continue
                elif self.node_has_call(angr_node):
                   avoid_func_addr = angr_node.function_address

            successors = list(self.graph.successors(node))
            if count >= 2:
                orig_successor = reversed_trace_path[count-2]

            if len(successors) != 2:
                count += 1
                continue

            found = False
            for s in successors:
                if not self.is_program_code(self.node_name_to_addr(s)):
                    break
                if s != orig_successor:
                    found = True # look for untried paths
                    break
                # if s in reversed_trace_path[count:]: # check if node is already traversed
                #     # successor does not have a path of MAX_LOOP_SIZE to an avoid node
                #     for avoid in avoid_nodes:
                #         # successor connects to avoid node, reject
                #         if self.has_path_of_max_size(s, avoid, MAX_LOOP_SIZE):
                #             found = False
                #             break

            if found:
                alt_node = s
                parent_node = node
                for other_node in successors:
                    if other_node != alt_node:
                        old_node = other_node

                return parent_node, old_node, alt_node
            count += 1

        return parent_node, old_node, alt_node


    def _find_diverging_node_in_graph_paths(self, trace_path, target_address, MAX_DISTANCE=100):
        reversed_trace_path = trace_path[::-1] #iterate backwards
        seen_nodes = set(trace_path)

        # for index in range(len(trace_path)-1, 0, -1):
        count = 0
        for node in reversed_trace_path:
            # node = trace_path[index]
            if count > MAX_DISTANCE:
                break
            if self.node_name_to_addr(node) == target_address:
                count += 1
                continue
            target_node = self.get_nearest_node_with_addr(node, target_address)
            if target_node != None:
                print("node %s has path to %s" % (node, target_node))
                path = networkx.shortest_path(self.graph, node, target_node)
                path = path[1:] # remove the starting node
                repeats = False
                for p in path:
                    if p in seen_nodes:
                        repeats = True
                        break
                if repeats:
                    continue
                return node, target_node
            count += 1 
        print("No diverging node found")
        return None, None

    def find_divergence_to_target(self, trace_path, target_address):
        diverging_node, target_node = self._find_diverging_node_in_graph_paths(trace_path, target_address)
        if diverging_node == None:
            print("   --> unable to find diverging_node_in_graph_paths")
            return None, None, None

        print("Found diverging_node %s" % diverging_node)
        successors = list(self.graph.successors(diverging_node))

        print("  -> successors: ", successors)

        if len(successors) != 2:
            print("ERROR: incorrect number of successors")
            return diverging_node, None, None

        old_node = None
        alt_node = None
        lowest_dist = networkx.shortest_path_length(self.graph, diverging_node, target_node)

        for s in successors:
            if networkx.has_path(self.graph, s, target_node):
                dist_to_target = networkx.shortest_path_length(self.graph, s, target_node)
                if dist_to_target <= lowest_dist:
                    alt_node = s

        for s in successors:
            if s != alt_node:
                old_node = s

        # print("  -> old node: ", old_node)
        # print("  -> alt node: ", alt_node)

        return diverging_node, old_node, alt_node