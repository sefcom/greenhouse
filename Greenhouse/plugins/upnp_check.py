import os
import re
from telnetlib import IP
import socket

UDP_SOCKET_TIMEOUT = 8.0

# take from routersploit
# https://github.com/threat9/routersploit/blob/85f4bf2301e9d082985c0973d2b6bc42e01fbe09/routersploit/core/udp/udp_client.py
class UDPCli():
    """ UDP Client provides methods to handle communication with UDP server """

    def __init__(self, udp_target: str, udp_port: int, verbosity: bool = False) -> None:
        """ UDP client constructor
        :param str udp_target: target UDP server ip address
        :param int udp_port: target UDP server port
        :param bool verbosity: display verbose output
        :return None:
        """

        self.udp_target = udp_target
        self.udp_port = udp_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.udp_target, self.udp_port)

        if self.is_ipv4(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.is_ipv6(self.udp_target):
            self.udp_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            print("Target address is not valid IPv4 nor IPv6 address")
            return None

        self.udp_client.settimeout(UDP_SOCKET_TIMEOUT)

    def is_ipv4(self, address: str) -> bool:
        """ Checks if given address is valid IPv4 address
        :param str address: IP address to check
        :return bool: True if address is valid IPv4 address, False otherwise
        """

        regexp = "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        if re.match(regexp, address):
            return True

        return False


    def is_ipv6(self, address: str) -> bool:
        """ Checks if given address is valid IPv6 address
        :param str address: IP address to check
        :return bool: True if address is valid IPv6 address, False otherwise
        """

        regexp = "^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%.*$"

        if re.match(regexp, address):
            return True

        return False
    
    def send(self, data: bytes) -> bool:
        """ Send UDP data
        :param bytes data: data that should be sent to the server
        :return bool: True if data was sent, False otherwise
        """

        try:
            self.udp_client.sendto(data, (self.udp_target, self.udp_port))
            return True
        except Exception as err:
            print("Error while sending data", err)

        return False

    def recv(self, num: int) -> bytes:
        """ Receive UDP data
        :param int num: number of bytes that should received from the server
        :return bytes: bytes received from the server
        """

        try:
            response = self.udp_client.recv(num)
            return response
        except Exception as err:
            print("Error while receiving data", err)

        return None

    def close(self) -> bool:
        """ Close UDP connection
        :return bool: True if connection was closed successful, False otherwise
        """

        try:
            self.udp_client.close()
            return True
        except Exception as err:
            print("Error while closing udp socket", err)

        return False

class UPNPCheck:
    def __init__(self, ip, port):
        # uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data
        self.connected = False
        self.wellformed = False
        self.ip = ip
        self.port = port
        self.user = ""
        self.password = ""
        self.headers = ""
        self.data = ""
        self.loginurl = ip
        self.login_type = ""

    def udp_create(self, target: str = None, port: int = None) -> UDPCli:
        """ Create UDP client
        :param str target: target UDP server ip address
        :param int port: target UDP server port
        :return UDPCli: UDP client object
        """

        udp_target = target if target else self.target
        udp_port = port if port else self.port

        udp_client = UDPCli(udp_target, udp_port)
        return udp_client
    
    def connection_check(self):
        ip = bytes(self.ip, "utf-8")
        port = bytes(self.port, "utf-8")
        print("    - sending upnp discover check @ %s:%s" % (self.ip, self.port))
        request = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"Host:%s:%s\r\n"
            b"ST:upnp:rootdevice\r\n"
            b"Man:\"ssdp:discover\"\r\n"
            b"MX:2\r\n\r\n" % (ip, port)
        )
        response = None

        udp_client = self.udp_create(self.ip, int(self.port))

        if udp_client:
            print("     [>] ", request)
            udp_client.send(request)
            response = udp_client.recv(65535)
            udp_client.close()
            print("-"*50)
            print("     [<]", response)
            print("-"*50)
        return response

    def is_connected(self):
        return self.connected

    def is_wellformed(self):
        return self.wellformed
    
    def probe(self):
        response = self.connection_check()
        if response:
            self.connected = True
            if b"upnp" in response.lower():
                self.wellformed = True
                return True
        return False
    
class UPNPInteractionCheck:
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
                uc = UPNPCheck(ip, port)
                success = uc.probe()
                if success:
                    self.urlchecks.append(uc)
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