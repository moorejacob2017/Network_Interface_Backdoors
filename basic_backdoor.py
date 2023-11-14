# BASIC SERVER
import socket
from scapy.all import Ether, IP, TCP
# --------------------------------------------------------------------
def capture_tcp_frame(interface, port):
    # Create a raw socket to capture packets/frames
    sniffer = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(3)
    )
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
                    return tcp_frame # Return the caught packet

    except KeyboardInterrupt: # Close the sniffer on ^C
        sniffer.close()
        raise KeyboardInterrupt
# --------------------------------------------------------------------
# Basic Driver, Continuously listen for packets
#   to port 12345 on the Loopback interface (lo)
while True: 
    p = capture_tcp_frame('lo', 12345)
    print(p.show()) # Print out frame info