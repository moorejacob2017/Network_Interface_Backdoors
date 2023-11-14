# BASIC CLIENT
from scapy.all import Ether, IP, TCP, send, Raw
from random import randint
# --------------------------------------------------------------------
def send_tcp_frame(destination_ip, destination_port, payload, seq, ack, flags):
    ip_packet = IP(dst=destination_ip)
    tcp_frame = TCP(
        dport=destination_port,
        sport=randint(10000,60000), # Source Port does not matter for our case
        seq=seq,
        ack=ack,
        flags=flags,
        options=[("NOP", None)] # "No Operation"
    )
    # Build out the packet
    special_packet = ip_packet / tcp_frame / Raw(load=payload)
    send(special_packet, verbose=0)
# --------------------------------------------------------------------
# Basic Driver, Send a packet down range
send_tcp_frame(
    destination_ip='127.0.0.1', # Will be delivered on Loopback (lo)
    destination_port=12345,
    payload=b'Hello, World',
    seq=1234,
    ack=5678,
    flags='PA' # PSH/ACK
)