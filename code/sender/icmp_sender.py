# import scapy

# Implement your ICMP sender here

from scapy.all import IP, ICMP, send

# Specify the destination IP address of the receiver container
destination_ip = "172.18.0.2"  # Replace with the actual IP of the receiver container

# Create an IP packet with a TTL of 1
ip = IP(dst=destination_ip, ttl=1)
icmp = ICMP()  # Create an ICMP packet

# Combine IP and ICMP packets
packet = ip / icmp

# Send the packet
send(packet)
