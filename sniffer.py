#!/usr/bin/env python3

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

def packet_callback(packet):
    # Check for Ethernet layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"\nEthernet Frame:")
        print(f"    Source MAC: {eth.src}")
        print(f"    Destination MAC: {eth.dst}")
        print(f"    Type: {eth.type}")
        print(f"    Length: {len(packet)}")
    # Check for IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"\nIP Packet:")
        print(f"    Version: {ip.version}")
        print(f"    Header Length: {ip.ihl * 4} bytes")
        print(f"    Total Length: {ip.len} bytes")
        print(f"    TTL: {ip.ttl}")
        print(f"    Protocol: {ip.proto}")
        print(f"    Source IP: {ip.src}")
        print(f"    Destination IP: {ip.dst}")

        # Check for TCP layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"\nTCP Segment:")
            print(f"    Source Port: {tcp.sport}")
            print(f"    Destination Port: {tcp.dport}")
            print(f"    Sequence Number: {tcp.seq}")
            print(f"    Acknowledgment Number: {tcp.ack}")
            print(f"    Data Offset: {tcp.dataofs * 4} bytes")
            print(f"    Flags: {tcp.flags}")
            print(f"    Window Size: {tcp.window}")
            print(f"    Checksum: {tcp.chksum}")

        # Check for UDP layer
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"\nUDP Datagram:")
            print(f"    Source Port: {udp.sport}")
            print(f"    Destination Port: {udp.dport}")
            print(f"    Length: {udp.len}")
            print(f"    Checksum: {udp.chksum}")

        # Check for ICMP layer
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print(f"\nICMP Packet:")
            print(f"    Type: {icmp.type}")
            print(f"    Code: {icmp.code}")
            print(f"    Checksum: {icmp.chksum}")
            print(f"    Identifier: {icmp.id}")
            print(f"    Sequence Number: {icmp.seq}")

def main():
    # Sniff packets
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()

