from . import *
from .patches import *

import importlib, inspect
import os
import operator

class Patcher:  
    def __init__(self, whitelist=None, blacklist=[]):
        self.pObstacles = []

        all_obstacles=os.listdir("patcher")
        all_obstacles.remove('__init__.py')
        all_obstacles.remove('Patcher.py')

        print(all_obstacles)

        for obstacleName in all_obstacles:
            if obstacleName.endswith(".py"):
                obstacleName = obstacleName[:-3]
                if whitelist and obstacleName not in whitelist:
                    continue
                if obstacleName in blacklist:
                    continue
                obs = importlib.import_module("patcher."+obstacleName)
                members = inspect.getmembers(obs)
                for mem in members:
                    path_name = str(mem[1])+"."+str(mem[0])
                    print("    - ", mem)
                    print("    - ",path_name)
                    if obstacleName in path_name:
                        self.pObstacles.append(mem[1]())
                        break

        self.pObstacles = sorted(self.pObstacles, key=operator.attrgetter('priority'), reverse=True)

    def diagnose_and_patch(self, binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, skip=False, changelog=[]):
        patchers = []

        print("Patch Priority: ", [str(p)+":"+str(p.priority) for p in self.pObstacles])
        for pObs in self.pObstacles:
            print("Diagnosing with", pObs)
            if pObs.diagnose(binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized):
                print("Found appropriate patcher: ", pObs)
                patchers.append(pObs)

        if skip:
            return False

        print("Trying patchers: ", patchers)
        for patcher in patchers:
            result = patcher.applyPatch(binary, bintrunk, trace, trace_trunk_path, index, exit_code, timedout, errored, daemonized, changelog=changelog)
            if result:
                return True

        return False