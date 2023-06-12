import os, sys
from telnetlib import IP
import requests
from hashlib import md5
import base64
import time
import math
import selenium
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException
from requests.auth import HTTPDigestAuth



from .Initializer import *

USER_AUTHS = ['admin', '']
PASSWORD_AUTHS = ['', 'admin', 'password', '1234']
MAX_RETRIES = 3

class URLCheck:
    def __init__(self, ip, port, brand, analysis_path):
        self.ip = ip
        self.port = port
        self.url = "http://%s:%s" % (ip, port)
        self.brand = brand
        self.analysis_path = analysis_path

        # session
        self.user = ""
        self.password = ""
        self.headers = None
        self.data = ""
        self.working_curl = ""
        self.reply = None
        self.session = None
        self.last_status_code = -1
        self.login_type = ""
        self.loginurl = ""

        # flags
        self.curl_success = False
        self.login_success = False
        self.login_needed = False
        self.initializer_done = False
        self.wellformed = False
        self.timedout = False

    def curlcheck(self):
        count = 0
        is_ssl = False
        retry = True
        r = None
        if self.login_needed and self.login_success:
            auth = (self.user, self.password)
        else:
            auth = None

        while retry:
            if count > MAX_RETRIES:
                break

            if is_ssl and not self.url.startswith("https"):
                self.url = self.url.replace("http://", "https://")
            print("    - sending curl request check @ %s" % (self.url))
            try:
                r = self.session.get(url=self.url, timeout=5, verify=False, headers=self.headers, allow_redirects=True)
                retry = False
            except Exception as e:
                print("Connection failed")
                print(e)
                retry = False
                if "timed out" in str(e):
                    self.timedout = True
                    self.last_status_code = 408
                elif "Remote end closed connection without response"  in str(e):
                    self.last_status_code = 202
                elif "BadStatusLine" in str(e):
                    self.last_status_code = 400
                elif "reset by peer" in str(e):
                    retry = True
                    is_ssl = True

                if self.last_status_code != -1 and not is_ssl and self.url.endswith("443"):
                    retry = True
                    is_ssl = True
            count += 1

        if r is not None and not self.timedout:
            self.last_status_code = r.status_code
            print("    - [curlcheck]: Request returned", r.status_code)
            http_text = r.text.encode("utf-8", errors='ignore')
            if len(http_text) > 200:
                print(http_text[:200])
                print("<truncated>")
            else:
                print(http_text)

        return r

    def logincheck(self, session):
        login_type = Login.check_login_type(self.url, self.brand)
        if login_type == "connection error":
            return False, False
        if login_type == "unknown":
            return True, False

        self.login_type = login_type # only save the login type in the initial success case

        print("    - Login Type: ", self.login_type)
        logged_in = False
        headers = {}
        reply = None
        for user in USER_AUTHS:
            for password in PASSWORD_AUTHS:
                if self.login_success:
                    user = self.user
                    password = self.password
                try:
                    print("      - Trying user: %s password: %s" % (user, password))
                    
                    logged_in, headers, payload, loginurl = Login.login(session, self.brand, self.url, self.login_type, user, password)
                    print("      - logged in", logged_in)
                except Exception as e:
                    print("      - ERROR login attempt failed")
                    print(e)
                time.sleep(2) # delay to subvert brute force protection
                if logged_in:
                    # retry: make sure the curl actually works
                    try:
                        logged_in, _, _, _ = Login.login(session, self.brand, self.url, self.login_type, user, password)
                    except Exception as e:
                        print("      - ERROR login attempt failed")
                        print(e)
                        logged_in = False
                    if not logged_in:
                        print("      x- false login success, retry")
                        continue
                    self.user = user
                    self.password = password
                    self.headers = headers
                    self.loginurl = loginurl
                    if payload is not None:
                        self.data = str(payload)
                    else:
                        self.data = ""
                    break
            if logged_in:
                break

        return logged_in, True



    def webcheck(self):
        wbc = WebCheck()
        retryurl = ""
        wbc.Initialize(self.analysis_path)
        if self.login_needed:
            auth = "%s:%s" % (self.user, self.password)
            print("    - using auth", auth)
        else:
            auth = ""
        wbc.Connect(self.url, auth)
        wellformed, self.last_status_code = wbc.Check()
        if wellformed and self.last_status_code == 200: # do two attempts, since its possible we crashed after the first
            print("="*50)
            print("    - second check")
            print("="*50)
            wellformed, self.last_status_code = wbc.Check()
        wbc.Close()
        if self.last_status_code == 401:
            retryurl = wbc.current_url
        return wellformed, retryurl

    def initialize(self, brand, ip, port, username, password):
        print("-"*50)
        Initializer.full_run(brand, ip, port, username, password, "")
        print("-"*50)

    def probe(self):
        reply = None
        self.curl_success = False
        self.login_success = False
        self.login_needed = False
        self.login_type = ""
        self.loginurl = ""
        self.initializer_done = False
        self.wellformed = False
        self.last_status_code = -1
        self.working_curl = ""
        self.session = requests.Session()

        while True:
            print("[+] curltest")
            print("[+] Probing %s..." % self.url)
            reply = self.curlcheck()

            # check if response is 200 or 401:
            #   - if so, run login script and update the session in use
            #   - rerun curlcheck with new session
            #   - if login script does not find anything and response is 200, proceed
            #   - otherwise, fail
            if reply is None:
                print("    - CurlCheck failed!")
                break

            if reply.status_code != 200 and reply.status_code != 401:
                print("    - CurlCheck failed!")
                break

            # curlcheck passed for this test cycle
            if not self.curl_success:
                self.curl_success = True
                print("[+] Page found, retesting...")
                continue
            print("[+] curlpassed")

            # save working curl
            curlheaders = ""
            if self.headers is not None:
                curlheaders = ['-H "{0}: {1}"'.format(k, v.strip("\"").strip("\'")) for k, v in self.headers.items()]

            curlcommand = "curl -L"
            for header in curlheaders:
                curlcommand += " "+header
            if self.data != "":
                self.data = self.data.replace("\"", "\\\"")
                curlcommand += " -d "+"\""+self.data+"\""
            if self.login_type == "digest":
                curlcommand += " --digest"
            if self.user != "" or self.password != "":
                curlcommand += " --user %s:%s" % (self.user, self.password)
            
            if len(self.loginurl) <= 0:
                self.loginurl = self.url
            curlcommand += " %s" % self.loginurl
            self.working_curl = curlcommand
            print("    [+] Working cURL:", curlcommand)

            print("[+] logintest")
            logged_in, login_needed  = self.logincheck(self.session)

            # either don't need login or do need and successfully logged in
            if login_needed and not logged_in:
                print("    - Login failed!")
                break

            # logincheck passed for this test cycle
            if not self.login_success:
                self.login_success = True
                self.login_needed = login_needed
                if self.login_needed:
                    print("[+] Logged in with %s:%s via <%s> @ \'%s\', retesting" % (self.user, self.password, \
                                                                                     self.login_type, self.loginurl))
                    continue
                else:
                    print("    - no login needed, continuing...")

            print("[+] loginpassed")

            # get webpage with selenium
            # check source page resulting is still code 200 and wellformed
            print("[+] webcheck")
            self.wellformed, retryurl = self.webcheck()
            if len(retryurl) > 0 and self.url != retryurl:
                print("    - retrying with new url", retryurl)
                self.url = retryurl
                self.curl_success = False
                self.login_success = False
                continue

            if not self.wellformed:
                print("    - WebCheck failed!")
                if self.last_status_code == 200:
                    self.last_status_code = 204
                break

            print("[+] webpassed")

            print("[+] All checks passed for %s! Webpage is wellformed and running!" % self.url)

            break

            # RECHECK
        self.session.close()
        return self.last_status_code != -1

class HTTPInteractionCheck:
    def __init__(self, brand, analysis_path, full_timeout=False):
        self.brand = brand
        self.analysis_path = analysis_path
        self.urlchecks = []
        self.full_timeout = full_timeout

    def probe(self, ips, ports):
        self.urlchecks.clear()
        success = []
        for ip in ips:
            for port in ports:
                uc = URLCheck(ip, port, self.brand, self.analysis_path)
                success = uc.probe()
                if success:
                    self.urlchecks.append(uc)
        if not self.full_timeout: # always probe to until we timeout
            if len(self.urlchecks) > 0:
                return True
        return False
    
    def get_port(self, uc):
        return int(uc.port)
    
    def get_url(self, uc):
        return uc.url

    def get_working_ip_set(self, strict=True):
        ip_port_url_type_user_pass_headers_payload = ("", "", "", "", "", "", "", "")
        wellformed_ucs = []
        found = False
        if self.urlchecks:
            self.urlchecks.sort(key=self.get_url)
            self.urlchecks.sort(key=self.get_port)
            for uc in self.urlchecks:
                print("    >>> checking", uc.url, uc.last_status_code)
                if not strict or uc.wellformed:
                    wellformed_ucs.append(uc)
                    if uc.login_type == "unknown" or uc.login_type == "":
                        continue
                    found = True
                    ip_port_url_type_user_pass_headers_payload = (uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data)
                    break
            if not found and wellformed_ucs:
                uc = wellformed_ucs[0]
                ip_port_url_type_user_pass_headers_payload = (uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data)
        return ip_port_url_type_user_pass_headers_payload

    def check(self, trace, exit_code, timedout, errored, strict):
        connected = False
        if not errored:
            if self.urlchecks:
                self.urlchecks.sort(key=self.get_url)
                self.urlchecks.sort(key=self.get_port)
                for uc in self.urlchecks:
                    print("    >>> checking", uc.url, uc.last_status_code)
                    if uc.last_status_code == 200:
                        print("Status Code:", uc.last_status_code)
                        if strict:
                            if uc.wellformed:
                                return True, uc.wellformed, uc.curl_success
                        else:
                            return True, uc.wellformed, uc.curl_success
                    elif uc.curl_success:
                        connected = uc.curl_success
                    
                    if uc.last_status_code != -1:
                        print("Status Code:", uc.last_status_code)

        return False, False, connected
        
if __name__ == "__main__":
	if len(sys.argv) < 4:
		print("USAGE: http_check.py [BRAND] [ANALYSIS_PATH] [URL;URL;URL]")
	brand = sys.argv[1]
	analysis_path = sys.argv[2]
	ips = sys.argv[3]
	potential_urls = [ip for ip in ips.split(";") if ip.strip()]
	ports = ["80","443","1900"]
	print("Running http_check: ", brand, analysis_path, potential_urls, ports)
	checker = HTTPInteractionCheck(brand, analysis_path)
	probe_success = checker.probe(potential_urls, ports)
	if probe_success:
		success, wellformed, curlsuccess = checker.check(trace=None, exit_code=None, timedout=False, errored=False, strict=True)
		if success and wellformed:
			print("Success, filesystem runs!")
	else:
		print("Unable to connect!")
