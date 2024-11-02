# import scapy

# Implement your ICMP receiver here

from scapy.all import sniff, IP, ICMP

# Define a callback function for processing captured packets
def packet_callback(packet):
    # Check if the packet is an ICMP request and has TTL = 1
    if IP in packet and ICMP in packet and packet[IP].ttl == 1:
        packet.show()  # Display packet details

# Sniff for ICMP packets with TTL = 1
sniff(filter="icmp", prn=packet_callback)
