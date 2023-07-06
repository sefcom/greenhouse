import sys
import time
import requests
import xmltodict
from selenium import webdriver


def login_1():
    try:
        cd = "/home/sefcom/projects/greenhouse/routersploit_ghpatched/routersploit_ghpatched/chromedriver"
        op = webdriver.ChromeOptions()
        op.add_argument('--headless')
        driver = webdriver.Chrome(cd, options=op)
        URL = f"http://{sys.argv[2]}"
        time.sleep(1)
        driver.get(f"{URL}/info/Login.html")
        time.sleep(1)
        driver.execute_script("OnClickLogin()")
        time.sleep(1)
        driver.get(f"{URL}/Home.html")
        
        if driver.current_url == f"{URL}/Home.html":
            return True
        else:
            print(f"{driver.current_url}")
            return False
    except:
        return False

def login_2():
    try:
        cd = "/home/sefcom/projects/greenhouse/routersploit_ghpatched/routersploit_ghpatched/chromedriver"
        op = webdriver.ChromeOptions()
        op.add_argument('--headless')
        driver = webdriver.Chrome(cd, options=op)
        URL = f"http://{sys.argv[2]}"
        time.sleep(1)
        driver.get(f"{URL}/info/Login.html")
        time.sleep(1)
        driver.execute_script("SetXML()")
        time.sleep(1)
        driver.get(f"{URL}/Home.html")
        
        if driver.current_url == f"{URL}/Home.html":
            return True
        else:
            print(f"{driver.current_url}")
            return False
    except:
        return False

def login_3():
    try:
        cookies = {
            'uid': 'cZIKlLdrta',
        }
        
        data = {
            'REPORT_METHOD': 'xml',
            'ACTION': 'login_plaintext',
            'USER': sys.argv[1],
            'PASSWD': '',
            'CAPTCHA': '',
        }
    
        resp = requests.post(f'http://{sys.argv[2]}/session.cgi', cookies=cookies, data=data)
        msg = xmltodict.parse(resp.text)['report']["RESULT"]
        return msg == "SUCCESS"
    except:
        return False


if __name__ == "__main__":
    assert len(sys.argv) == 3, f"Usage {sys.argv[0]} <username> <ip addr>"
    if login_1() is True:
        print("ok")
    elif login_2() is True:
        print("ok")
    elif login_3() is True:
        print("ok")
    else:
        sys.exit()
