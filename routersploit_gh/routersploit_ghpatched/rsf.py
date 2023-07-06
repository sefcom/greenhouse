#!/usr/bin/env python3

from __future__ import print_function
import logging.handlers
import sys
if sys.version_info.major < 3:
    print("RouterSploit supports only Python3. Rerun application in Python3 environment.")
    exit(0)

from routersploit.interpreter import RoutersploitInterpreter

from argparse import ArgumentParser

log_handler = logging.handlers.RotatingFileHandler(filename="routersploit.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)

IP_ADDR = "192.168.1.1"
PORT = 80


def routersploit(module = None, target_ip = None, port = None, username = None, password = None, cmd = None, use_autopwn = False):
    rsf = RoutersploitInterpreter()
    if not target_ip:
        rsf.start()
    elif use_autopwn or module is None:
        rsf.run_command('use scanners/autopwn')
        rsf.run_command('set check_creds false')
        rsf.run_command('set threads 1')
        if module:
            rsf.run_command('set single_module %s' % module)
        if target_ip:
            rsf.run_command('set target %s' % target_ip)
        if port:
            rsf.run_command('set http_port %s' % port)
        rsf.run_command('set username %s' % username)
        rsf.run_command('set password %s' % password)
        rsf.run_command('run')
    else:
        rsf.run_command('use {}'.format(module))
        if target_ip:
            rsf.run_command('set target %s' % target_ip)
        if port:
            rsf.run_command('set port %s' % port)
        rsf.run_command('set username %s' % username)
        rsf.run_command('set password %s' % password)
        rsf.run_command('run')

if __name__ == "__main__":
    parser = ArgumentParser(description='Use RSF to run a module')
    parser.add_argument('-f', metavar='MODULE', type=str, help='The module to use', required=False)
    parser.add_argument('-t', metavar='TARGET', type=str, help='The target IP', required=False, default=IP_ADDR)
    parser.add_argument('-p', metavar='PORT', type=int, help='Port number', required=False, default=PORT)
    parser.add_argument('-u', metavar='USERNAME', type=str, help='default username to try', required=False, default="")
    parser.add_argument('-w', metavar='PASSWORD', type=str, help='default password to try', required=False, default="")
    parser.add_argument('-c', metavar='CMD', type=str, help='Additional commands to run', required=False, default="")
    parser.add_argument('-a', help='enable autopwn mode', action="store_true", required=False, default=True)

    args = parser.parse_args()

    autopwn = args.a
    module = args.f
    target = args.t
    port = args.p
    user = args.u
    passwd = args.w
    cmd = args.c if len(args.c) > 0 else None
    routersploit(module=module, target_ip=target, port=port, username=user, password=passwd, cmd=cmd, use_autopwn=autopwn)


