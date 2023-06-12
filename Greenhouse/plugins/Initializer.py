#!/usr/bin/env python3

import sys
import re
import os
import selenium
import time
import math
import requests
import json
import lxml.html
from hashlib import md5
import base64
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.common.exceptions import InvalidSessionIdException
from selenium.common.exceptions import WebDriverException
from selenium.common.exceptions import ElementNotInteractableException
from selenium.common.exceptions import ElementClickInterceptedException
from requests.auth import HTTPDigestAuth
from argparse import ArgumentParser


# based on FirmAE's initializer script
# https://github.com/pr0v3rbs/FirmAE/blob/6fd365d838636fd203c07c1b2c7ecf3ad548a6d5/analyses/initializer.py
netgear_pattern = re.compile(r"No[,.]( I want to).+(configur)")
WHITELIST = [".jpg", ".gif", ".png", ".jpeg", ".tiff", ".bmp", ".webp", ".bmp", ".svg"]

DEFAULTS = {"netgear" : ("admin", "password"), "asus" : ("admin", "admin"), "dlink" : ("admin", ""), "default" : ("admin", "admin")}
IP_ADDR = "172.18.0.2"
PORT = 80
FULL_RUN = "FULL_RUN"
SINGLE_LOGIN = "SINGLE_LOGIN"
SINGLE_LOGOUT = "SINGLE_LOGOUT"

HTTP_500_MSG = "Failed to load resource: the server responded with a status of 500 (Internal Server Error)"

TRANS_5C = "".join(chr(x ^ 0x5c) for x in range(256))
TRANS_36 = "".join(chr(x ^ 0x36) for x in range(256))
BLOCKSIZE = md5().block_size

def Initialize():
    os.environ['PATH'] = os.getcwd() + ':' + os.environ['PATH']

class WebCheck:
    def __init__(self):
        self.old_path = ""
        self.driver = None
        self.connected = False
        self.current_url = ""

    def Connect(self, url, auth):
        print("WebCheck Connect")
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--screen-size=1200x600')
        options.set_capability('unhandledPromptBehaviour', 'dismiss')
        options.set_capability('unexpectedAlertBehaviour', 'dismiss')
        self.driver = webdriver.Chrome(options=options)
        self.driver.set_page_load_timeout(60)
        try:
            if ":" in auth:
                index = url.index("://")
                splitIndex = index+3
                head = url[:splitIndex]
                tail = url[splitIndex:]
                print("    - GET", (head + auth + '@' + tail))
                self.driver.get(head + auth + '@' + tail)
            else:
                print("    - GET", url)
                self.driver.get(url)
            time.sleep(5)
            self.connected = True
        except Exception as e:
            print(e)
            self.connected = False

    def HandleAlert(self):
        try:
            alert = self.driver.switch_to_alert()
            if alert:
                print("    - catching and accepting alert")
                alert.accept()
            return alert
        except:
            return None

    def Check(self):
        if self.connected == True:
            page_source = None
            retry = True
            while retry:
                try:
                    page_source = self.driver.page_source
                    self.current_url = self.driver.current_url
                    retry = False

                    print("Check")
                    print("="*50)
                    print("HTML source")
                    print("="*50)
                    if len(page_source) > 200:
                        print(page_source[:200])
                        print("="*50)
                        print("<truncated>")
                    else:
                        print(page_source)
                    print("="*50)
                    if "<html" in page_source or "<script" in page_source:
                        for entry in self.driver.get_log('browser'):
                            if entry["level"] == "SEVERE":
                                if HTTP_500_MSG in entry["message"]:
                                    logmsg = entry["message"]
                                    index = logmsg.find(HTTP_500_MSG)
                                    error_target = logmsg[:index].lower()
                                    isWhitelisted = False
                                    for filetype in WHITELIST:
                                        if filetype in error_target:
                                            isWhitelisted = True
                                            break
                                    if isWhitelisted:
                                        continue
                                    print(entry)
                                    print("="*50)
                                    self.status_code = 500
                                    return False, 500
                        raw_data = lxml.html.fromstring(page_source).text_content()
                        if len(raw_data) <= 0: # check for empty content
                            return False, 204
                        if "GREENHOUSE_WEB_CANARY" in self.driver.page_source:
                            return False, 406 # if we are getting a dir view of the rootfs something is wrong
                        if "401" in raw_data.lower() and "unauthorized" in raw_data.lower():
                            return False, 401
                        if "404" in raw_data.lower() and "not found" in raw_data.lower():
                            return False, 404
                        if "408"  in raw_data.lower() and "request timeout" in raw_data.lower():
                            return False, 408
                        if "500"  in raw_data.lower() and "internal server error" in raw_data.lower():
                            return False, 408
                        return True, 200
                except UnexpectedAlertPresentException as e:
                    self.HandleAlert()
                    retry = True
                except Exception as e: # malformed html
                    print("    - malformed html")
                    print(e)
                    return False, 206
        return False, -1

    def Initialize(self, analysis_path):
        self.old_env = os.environ['PATH']
        os.environ['PATH'] = analysis_path + ':' + os.environ['PATH']

    def Close(self):
        os.environ['PATH'] = self.old_env
        closed = False
        while not closed:
            try:
                self.driver.close()
                closed = True
            except UnexpectedAlertPresentException as e:
                self.HandleAlert()
            except InvalidSessionIdException as e:
                print("    - closing already deleted session [InvalidSessionIdException]")
                closed = True
            except Exception as e:
                print(e)
            time.sleep(3)
            print("    - handled alert, reattempting close...")

        time.sleep(3) # wait a little before quitting
        self.driver.quit()

class Login:
    # shamelessly stolen from FirmAE's login.py script
    # https://github.com/pr0v3rbs/FirmAE/blob/6fd365d838636fd203c07c1b2c7ecf3ad548a6d5/analyses/login
    def hmac_md5(key, msg):
        if len(key) > BLOCKSIZE:
            key = md5(key).digest()
        key = str(key) + '\x00' * (BLOCKSIZE - len(key))

        o_key_pad = key.translate(TRANS_5C).encode()
        i_key_pad = key.translate(TRANS_36).encode()
        return md5(o_key_pad + md5(i_key_pad + msg.encode()).digest())

    def HNAP_AUTH(SOAPAction, privateKey):
        b = math.floor(int(time.time())) % 2000000000;
        b = str(b)[:-2]
        h = Login.hmac_md5(privateKey, b + '"http://purenetworks.com/HNAP1/' + SOAPAction + '"').hexdigest().upper()
        return h + " " + b

    def check_login_type(ip, brand):
        headers = requests.utils.default_headers()
        headers["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko'
        headers["Referer"] = ip
        try:
            r = requests.get(ip, headers=headers)
        except Exception as e:
            print(e)
            return 'connection error'

        if r.status_code == 401:
            if "WWW-Authenticate" in r.headers.keys():
                if "Digest" in r.headers["WWW-Authenticate"]:
                    return 'digest'
            return 'basic'
        elif r.text.find('/info/Login.html') != -1: # dlink hnap
            return 'dlink_hnap'
        elif r.text.find('log_pass') != -1 or r.text.find('login_auth.asp') != -1 or r.text.find('login.cgi') != -1:
            if brand == "dlink":  # dlink normal login
                return 'dlink_asp'
            elif brand == "trendnet":
                if r.text.find('apply_sec.cgi') != -1:
                    return 'trendnet_asp_apply_sec_cgi'
                elif r.text.find('login.cgi') != -1:
                    return 'trendnet_asp_login_cgi'
            else:
                return 'unknown'
        elif r.text.find('setup_top.htm') != -1:
            return 'belkin'
        elif brand == "tenda":
            if r.text.find('/login/Auth') != -1:
                return 'tenda_auth'
            else:        
                try:
                    r = requests.get(ip+"/login/Auth", headers=headers)
                except Exception as e:
                    print(e)
                    return 'connection error'
                if r and r.status_code == 200:
                    return 'tenda_auth'
        elif r.text.find('location.replace(\'login.htm\')') != -1 or r.text.find('login.ccp') != -1:
            return 'trendnet_ccp'
        else:
            return 'unknown'
        return 'unknown'

    def login(session, brand, ip, login_type, username, password):
        reply = None
        headers = None
        payload = ""

        if login_type == 'basic':
            reply = session.get(url=ip, timeout=5, verify=False, auth=(username, password))
            print("    - attempt: ", login_type, ip, username, password, reply)
            return reply.status_code != 401, dict(reply.request.headers), reply.request.body, ip

        elif login_type == 'digest':
            reply = session.get(url=ip, timeout=5, verify=False, auth=HTTPDigestAuth(username, password))
            return reply.status_code != 401, dict(reply.request.headers), reply.request.body, ip
        elif login_type.startswith('trendnet_asp'):
            # username, password = BASIC_CRED[brand]
            login_name = base64.b64encode(username.encode('utf-8'))
            log_pass = base64.b64encode(password.encode('utf-8'))
            if "apply_sec" in login_type:
                login_cgi = "apply_sec.cgi"
            else:
                login_cgi = "login.cgi"
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'html_response_page':'login_fail.asp','login_name':login_name,'login_pass':log_pass,'graph_id':'d360e','log_pass':'','graph_code':'','Login':'Log In'}
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)
        elif login_type == 'dlink_asp':
            # username, password = BASIC_CRED[brand]
            login_name = base64.b64encode(username.encode('utf-8'))
            log_pass = base64.b64encode(password.encode('utf-8'))
            login_cgi = "login.cgi"
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'html_response_page':'login_fail.asp','login_name':login_name,'login_pass':log_pass,'graph_id':'d360e','log_pass':'','graph_code':'','Login':'Log In'}
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)

        elif login_type == 'dlink_hnap':
            # username, password = CRED[brand]
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["SOAPAction"] = '"http://purenetworks.com/HNAP1/Login"'
            headers["Origin"] = ip
            headers["Referer"] = ip + "/info/Login.html"
            headers["Content-Type"] = "text/xml; charset=UTF-8"
            headers["X-Requested-With"] = "XMLHttpRequest"

            payload = """<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                       <soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action>
                       <Username>%s</Username><LoginPassword>%s</LoginPassword><Captcha></Captcha></Login>
                       </soap:Body></soap:Envelope>""" % (username, password)
            r = requests.post(ip+'/HNAP1/', headers=headers, data=payload)
            if r.status_code != 200:
                print(r.status_code)
                return False, None, payload, ip

            data = r.text

            challenge = str(data[data.find("<Challenge>") + 11: data.find("</Challenge>")])
            cookie = str(data[data.find("<Cookie>") + 8: data.find("</Cookie>")])
            publicKey = str(data[data.find("<PublicKey>") + 11: data.find("</PublicKey>")])

            PRIVATE_KEY = Login.hmac_md5(publicKey + password, challenge).hexdigest().upper()
            md5_password = Login.hmac_md5(PRIVATE_KEY, challenge).hexdigest().upper()

            cookies = {"uid": cookie}
            headers["HNAP_AUTH"] = Login.HNAP_AUTH("Login", PRIVATE_KEY)
            payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username>Admin</Username><LoginPassword>'+md5_password+'</LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>'
            reply = requests.post(ip+'/HNAP1/', headers=headers, data=payload, cookies=cookies)
            success = False
            if reply.status_code == 200:
                data = reply.text
                loginresult = str(data[data.find("<LoginResult>") + 13: data.find("<//LoginResult>")])
                success = "success" in loginresult.lower()
            return success, dict(reply.request.headers), reply.request.body, ip+'/HNAP1/'

        elif login_type == 'belkin':
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'totalMSec': '1539994224.535', 'pws': 'd41d8cd98f00b204e9800998ecf8427e', 'arc_action': 'login', 'pws_temp': '', 'action': 'Submit'}
            reply = session.post(ip+'/login.cgi', headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, ip+'/login.cgi'

        elif login_type == 'trendnet_ccp':
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            payload = {'totalMSec': '1539994224.535', 'pws': 'd41d8cd98f00b204e9800998ecf8427e', 'arc_action': 'login', 'pws_temp': '', 'action': 'Submit'}
            payload = {'html_response_page':'login_fail.htm','login_name':'','username': username,'password': password,'curr_language':'','login_n': username,'login_pass': password,'lang_select':'0','login':'Login'}
            reply = session.post(ip + '/login.ccp', headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, ip + '/login.ccp'

        elif login_type == 'tenda_auth':
            log_pass = base64.b64encode(password.encode('utf-8'))
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            payload = {'username':username,'pwd':log_pass}
            login_cgi = "/login/Auth"
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            success = False
            if reply.status_code == 200:
                data = reply.text
                if "<html" in data and "/login/Auth" not in data:
                    success = True
            return success, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)

        else:
            return False, headers, "", ip

class Initializer:
    def __init__(self, brand, ip, port, username, password):
        self.brand = brand
        self.ip = ip
        self.port = port
        self.url = self.build_url(self.ip, self.port)
        self.credentials = dict()
        self.pattern = None
        self.driver = None

        # use defaults if none
        if username is None:
            self.username = DEFAULTS[self.brand][0]
        else:
            self.username = username.strip("\"").strip("\'")

        if password is None:
            self.password = DEFAULTS[self.brand][1]
        else:
            self.password = password.strip("\"").strip("\'")

        self.auth = "%s:%s" % (self.username, self.password)

        # setup re patterns
        if self.brand == "netgear":
            self.pattern = re.compile(r"No[,.]( I want to).+(configur)")
        elif self.brand == "asus":
            self.pattern = re.compile(r"(Quick Internet Setup)")
        elif self.brand == 'dlink':
            self.pattern = re.compile(r'<div id="wizard_title">Welcome</div>')

    def build_url(self, ip, port):
        fields = ip.split("/")
        baseip = ""
        index = 0
        for f in fields:
            f = f.strip()
            if len(f) <= 0 or "http" in f:
                index += 1
                continue
            baseip = f
            break
        if index+1 < len(fields):
            remaining = "/"+"/".join(fields[index+1:])
        else:
            remaining = ""
        url = "http://%s:%s%s" % (baseip, port, remaining)
        return url

    def HandleAlert(self):
        try:
            alert = self.driver.switch_to_alert()
            if alert:
                print("    - catching and accepting alert")
                alert.accept()
            return alert
        except:
            return None

    def GetCredentials(self):
        return self.credentials

    def Login(self):
        print("Login")
        login_type = Login.check_login_type(self.url, self.brand)
        print("    login type", login_type, self.url, self.brand)
        if login_type == 'connection error':
            print("[LOGIN]: CONNECTION ERROR")
        elif login_type == 'unknown':
            print("[LOGIN]: NO LOGIN INTERFACE DETECTED")
        else:
            print("[LOGIN] login type found: ", login_type)
        session = requests.Session()
        logged_in, headers, payload, loginurl = Login.login(session, self.brand, self.url, login_type, self.username, self.password)
        session.close()
        time.sleep(2)

        if not logged_in:
            print("[LOGIN]: UNABLE TO LOGIN")
        else:
            print("[LOGIN]: SUCCESS")
            print("[LOGIN]: username=%s, password=%s, headers=%s, payload=%s, loginurl=%s", (self.username, self.password, headers, payload, loginurl))
        self.credentials["loginheaders"] = headers
        self.credentials["loginpayload"] = payload
        self.credentials["targetip"] = self.url
        self.credentials["loginurl"] = loginurl
        self.credentials["login_type"] = login_type
        self.credentials["loginuser"] = self.username
        self.credentials["loginpassword"] = self.password
        return logged_in, self.credentials

    def Logout(self):
        print("Logout")
        elems = self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Logout')]")
        elems.extend(self.driver.find_elements(By.XPATH, "//*[contains(text(), 'logout')]"))
        for e in elems:
            if e.is_displayed():
                try:
                    print("    - trying logout button", e)
                    e.click()
                except ElementNotInteractableException as e:
                    print("    - elem [%s] not interactable" % e.text)
                except ElementClickInterceptedException as e:
                    print("    - elem [%s] not interactable" % e.text)
                except Exception as e:
                    print("    - error logging out: %s" % e.text)

    def Connect(self):
        print("Connect")
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--screen-size=1200x600')
        options.set_capability('unhandledPromptBehaviour', 'dismiss')
        options.set_capability('unexpectedAlertBehaviour', 'dismiss')
        self.driver = webdriver.Chrome(options=options)
        self.driver.set_page_load_timeout(60)
        try:
            if ":" in self.auth:
                index = self.url.index("://")
                splitIndex = index+3
                head = self.url[:splitIndex]
                tail = self.url[splitIndex:]
                print("    - GET", (head + self.auth + '@' + tail))
                self.driver.get(head + self.auth + '@' + tail)
            else:
                print("    - GET", self.url)
                self.driver.get(self.url)
            time.sleep(5)
            self.connected = True
        except Exception as e:
            print(e)
            self.connected = False
        time.sleep(10)

    def Run(self):
        print("Run")
        run_complete = False
        count = 0
        while not run_complete:
            try:
                if self.SwitchFrame(self.pattern):
                    print("[*] Find menu success!")
                else:
                    print("[-] Couldn't find manual setting information")
                    return

                page_source = self.driver.page_source
                if self.brand == "netgear":
                    idx = self.GetRadioIdx(self.driver.page_source)
                    if idx is not None:
                        self.ClickRadio(idx)
                        self.ClickNext()
                        time.sleep(5)
                elif self.brand == "asus":
                    if "QIS_wizard.htm" in page_source:
                        self.driver.execute_script("location.href = '/QIS_wizard.htm?flag=wireless';")
                        time.sleep(5)
                    if "smartcon_skip" in page_source:
                        self.SwitchFrame(re.compile("smartcon_skip"))
                        self.driver.execute_script("return smartcon_skip();")
                        time.sleep(5)
                elif self.brand == "dlink":
                    # COVR-3902_REVA_ROUTER_FIRMWARE_v1.01B05
                    if "clearCreateRulePOP" in page_source:
                        self.driver.execute_script("clearCreateRulePOP();")
                    time.sleep(5)
                run_complete = True
            except UnexpectedAlertPresentException as e:
                self.HandleAlert()
                print("    - handled alert, reattempting run...")
            except WebDriverException as e:
                print("WebDriverException", e[:100])
                return
            except Exception as e:
                print(e)
                return

            if count > 10:
                print("    - repeated looping alert, exit")
                return
            count += 1


    def GetAlert(self):
        try:
            alert = self.driver.switch_to.alert
            return alert
        except:
            return None

    def Close(self):
        print("Close")
        closed = False
        count = 0

        if self.driver is None:
            return
        while not closed:
            try:
                self.driver.close()
                closed = True
            except UnexpectedAlertPresentException as e:
                self.HandleAlert()
                count += 1
                if count > 10:
                    print("    - repeated looping alert, force exit")
                    return
                print("    - handled alert, reattempting close...")
            except WebDriverException as e:
                print("WebDriverException", e[:100])
                return
            except Exception as e:
                print(e)
                return
            time.sleep(3)

        time.sleep(3) # wait a little before quitting

    def Quit(self):
        print("Quit")
        self.driver.quit()

    def SwitchFrame(self, pattern):
        print("SwitchFrame")
        if pattern is None:
            print("    - no pattern for", self.brand)
            return
        self.driver.switch_to.default_content()
        if pattern.search(self.driver.page_source):
            return True

        for frame_name in ['frame', 'iframe']:
            for frame in self.driver.find_elements(by=By.TAG_NAME, value=frame_name):
                self.driver.switch_to.frame(frame)
                if pattern.search(self.driver.page_source):
                    return True
                self.driver.switch_to.default_content()

        return False

    def GetRadioIdx(self, page):
        return page.count('"radio"', 0, netgear_pattern.search(page).start()) - 1

    def ClickRadio(self, idx):
        self.driver.find_elements(By.XPATH, "//*[@type='radio']")[idx].click()

    def ClickNext(self):
        if self.driver.page_source.find('btnsContainer_div') != -1: # wnr2000v3, WNDR3800, JNR3210, R6200v2
            self.driver.find_elements(By.ID, 'btnsContainer_div').click()
        else: # WNR3500Lv2, WNDR3400v3, R8000
            self.driver.find_elements(By.XPATH, "//*[@type='button']").click()
        alert = self.driver.switch_to.alert
        alert.accept()

    def full_run(brand, target, port, user, passwd, creds_dump_path):
        print("[INFO] Attempting full run of initializer with following params:")
        print("    - brand: ", brand)
        print("    - target: ", target)
        print("    - port: ", port)
        print("    - user: ", user)
        print("    - passwd: ", passwd)

        Initialize()

        initialized = False
        initializer = Initializer(brand, target, port, user, passwd)
        try:
            initializer.Connect()

            initializer.Run()
            success, credentials = initializer.Login()
            if success:
                print("    - successfully logged in with creds :: ", credentials)
                if len(creds_dump_path) > 0:
                    print("    - creating json dump", creds_dump_path)
                    with open(creds_dump_path, "w") as credFile:
                        json.dump(credentials, credFile)
            initializer.Run()

            initializer.Logout()

            initializer.Close()
            initialized = True # as long as we successfully perform a connect and run, we succeeded

            # some netgear firmware redirect to the public page at first time
            initializer.Connect()
            initializer.Close()
            initializer.Quit()

        except Exception as e:
            print(f"[---] {str(e)}")

        print("[INFO] Initialization Complete")
        return initialized

    def single_login(brand, target, port, user, passwd, creds_dump_path, raw_creds_dump_path):
        print("[INFO] Attempting single login with following params:")
        print("    - brand: ", brand)
        print("    - target: ", target)
        print("    - port: ", port)
        print("    - user: ", user)
        print("    - passwd: ", passwd)

        Initialize()

        initializer = Initializer(brand, target, port, user, passwd)
        try:
            success, credentials = initializer.Login()
            if success:
                print("    - successfully logged in with creds :: ", credentials)
                if len(creds_dump_path) > 0:
                    print("    - creating json dump", creds_dump_path)
                    with open(creds_dump_path, "w") as credFile:
                        json.dump(credentials, credFile)
                if len(raw_creds_dump_path) > 0:
                    with open(f"{raw_creds_dump_path}", "w") as rawcredFile:
                        if len(credentials['loginurl']) > len(credentials['targetip']):
                            uri = credentials['loginurl'][len(credentials['targetip']):]
                        elif len(credentials['loginurl']) == len(credentials['targetip']):
                            uri = '/'
                        else:
                            uri = credentials['loginurl']
                        rawcredFile.write(f"GET {uri} HTTP/1.0\r\n")
                        # targetip is of form http://<IP>:<PORT>
                        # Gotta strip it down to <IP>
                        rawcredFile.write(f"Host: {credentials['targetip']}\r\n")
                        for header in credentials['loginheaders']:
                            rawcredFile.write(f"{header}: {credentials['loginheaders'][header]}\r\n")
                        rawcredFile.write("\n\n")
            else:
                print("Login failed")
        except Exception as e:
            print(f"[---] {str(e)}")
        print("[INFO] Login attempt complete")

    def single_logout(brand, target, port, user, passwd, creds_dump_path):
        print("[INFO] Attempting a simple logout")

        Initialize()

        initializer = Initializer(brand, target, port, user, passwd)
        try:
            initializer.Connect()

            initializer.Logout()

            initializer.Close()
            initializer.Quit()

        except Exception as e:
            print(f"[---] {str(e)}")
        print("[INFO] Logout attempt complete")

if __name__ == "__main__":
    parser = ArgumentParser(description='Use RSF to run a module')
    parser.add_argument('-m', metavar='MODE', type=str, help='The mode to use', required=True)
    parser.add_argument('-b', metavar='BRAND', type=str, help='brand of target', required=False)
    parser.add_argument('-t', metavar='TARGETIP', type=str, help='The target IP', required=False, default="")
    parser.add_argument('-p', metavar='PORT', type=int, help='Port number', required=False, default=-1)
    parser.add_argument('-u', metavar='USERNAME', type=str, help='default username to try', required=False, default="")
    parser.add_argument('-w', metavar='PASSWORD', type=str, help='default password to try', required=False, default="")
    parser.add_argument('-c', metavar='CONFIGFILE', type=str, help='config file to source from', required=False, default="")
    parser.add_argument('-d', metavar='CREDSDUMP', type=str, help='path to json file to dump credentials to', required=False, default="")
    parser.add_argument('-r', metavar='RAWCREDSDUMP', type=str, help='path to file to dump raw packet with credentials to', required=False, default="")

    args = parser.parse_args()

    mode = args.m
    brand = args.b
    target = args.t
    port = args.p
    user = args.u
    passwd = args.w
    configpath = args.c
    creds_dump_path = args.d
    raw_creds_dump_path = args.r

    if len(configpath) > 0:
        if os.path.exists(configpath):
            configs = None
            with open(configpath, "r") as configFile:
                configs = json.load(configFile)
                if "brand" in configs.keys():
                    brand = configs["brand"]
                if "targetip" in configs.keys():
                    target = configs["targetip"]
                elif "ip" in configs.keys():
                    target = configs["ip"]
                if "targetport" in configs.keys():
                    port = configs["targetport"]
                elif "port" in configs.keys():
                    port = configs["port"]
                if "loginuser" in configs.keys():
                    user = configs["loginuser"]
                elif "user" in configs.keys():
                    user = configs["user"]
                if "loginpassword" in configs.keys():
                    passwd = configs["loginpassword"]
                elif "password" in configs.keys():
                    passwd = configs["password"]
                    passwd = configs["loginpassword"]
        else:
            print("configfile %s does not exist" % configpath)
            exit(1)

    # use cmd line args
    if brand == "":
        print("need to have valid [brand] argument")
        exit(1)
    elif target == "":
        print("need to have valid [target] argument")
        exit(1)
    elif port == -1:
        print("need to have valid [port] argument")
        exit(1)

    if user == "":
        print("[INFO] - username empty, will use empty string \"\" for login attempts")
    if passwd == "":
        print("[INFO] - passwd empty, will use empty string \"\" for login attempts")

    if mode == FULL_RUN:
        Initializer.full_run(brand, target, port, user, passwd, creds_dump_path)
    elif mode == SINGLE_LOGIN:
        Initializer.single_login(brand, target, port, user, passwd, creds_dump_path, raw_creds_dump_path)
    elif mode == SINGLE_LOGOUT:
        Initializer.single_logout(brand, target, port, user, passwd, creds_dump_path)
    else:
        print("[ERROR] mode <%s> is not recognized. Valid modes are: [%s, %s, %s]" % (mode, FULL_RUN, SINGLE_LOGIN, SINGLE_LOGOUT))
        exit(1)
