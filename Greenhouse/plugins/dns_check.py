import os
import subprocess


class DNSCheck:
    def __init__(self, ip, port="53"):
        self.connected = False
        self.wellformed = False
        self.ip = ip
        self.port = "53"
        self.user = ""
        self.password = ""
        self.headers = ""
        self.data = ""
        self.loginurl = ip
        self.login_type = ""

    def connection_check(self, args=""):
        print("    - trying dns query via [ nslookup %s ] @ [%s:%s]" % (args, self.ip, self.port))
        nslookup_cmd = ["nslookup"]
        if args:
            nslookup_cmd.extend([args])
        nslookup_cmd.extend(["localhost", self.ip])
        r = subprocess.run(nslookup_cmd, capture_output=True, text=True)
        response = r.stdout
        err = r.stderr
        return response, err

    def is_connected(self):
        return self.connected

    def is_wellformed(self):
        return self.wellformed

    def probe(self):
        for args in ["", "-vc"]:
            response, err = self.connection_check(args=args)
            if response:
                print(b"    >>>> [RESP]:", response.encode("utf-8"))
                self.connected = True
                if "no servers could be reached" in response.lower():
                    self.connected = False
                elif "answer:" in response.lower() or "server can't find" in response.lower():
                    self.wellformed = True
                    return True
            else:
                print(b"    >>>> [ERR]:", err.encode("utf-8"))
            print("-"*50)
        return False

class DNSInteractionCheck:
    def __init__(self, brand, analysis_path, full_timeout=False):
        self.brand = brand
        self.analysis_path = analysis_path
        self.urlchecks = []
        self.full_timeout = full_timeout

    def probe(self, ips, ports):
        self.urlchecks.clear()
        success = []
        for ip in ips:
            dc = DNSCheck(ip, port="53")
            success = dc.probe()
            if success:
                self.urlchecks.append(dc)
        if not self.full_timeout: # always probe to until we timeout
            if len(self.urlchecks) > 0:
                return True
        return False

    def get_working_ip_set(self, strict=True):
        ip_port_url_type_user_pass_headers_payload = ("", "", "", "", "", "", "", "")
        for uc in self.urlchecks:
            if not strict or uc.is_wellformed():
                ip_port_url_type_user_pass_headers_payload = (uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data)
                break
        return ip_port_url_type_user_pass_headers_payload

    def check(self, trace, exit_code, timedout, errored, strict):
        if not errored:
            for uc in self.urlchecks:
                if uc.is_connected():
                    if strict:
                        if uc.is_wellformed():
                            return True, uc.is_wellformed(), uc.is_connected()
                    else:
                        return True, uc.is_wellformed(), uc.is_connected()

        return False, False, False
