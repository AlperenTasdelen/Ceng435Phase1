"""
Covert Timing Channel that exploits Idle Period Between Packet Bursts using DNS
"""

from CovertChannelBase import CovertChannelBase
import time
import random
from scapy.all import IP, UDP, DNS, DNSQR, sniff

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        super().__init__()

    def send(self, log_file_name, target_ip, domain, short_idle, long_idle, burst_size):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.

        Parameters:
        - log_file_name: Name of the log file to store the sent message.
        - target_ip: Target IP for DNS queries.
        - domain: Target domain for DNS queries.
        - short_idle: Short idle period (seconds) representing binary '1'.
        - long_idle: Long idle period (seconds) representing binary '0'.
        - burst_size: Number of packets in each burst.        
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        for bit in binary_message:

            for _ in range(burst_size):
                dns_packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A'))
                CovertChannelBase.send(self, dns_packet)

            if bit == '1':
                time.sleep(short_idle)
            elif bit == '0':
                time.sleep(long_idle)
        
        stop_packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A')) #?
        CovertChannelBase.send(self, stop_packet) 

    def receive(self, target_ip, short_idle, long_idle, tolerance, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.

        Parameters:
        - target_ip: Target IP for DNS queries.
        - short_idle: Short idle period (seconds) representing binary '1'.
        - long_idle: Long idle period (seconds) representing binary '0'.
        - tolerance: Tolerance for the idle periods.
        - log_file_name: Name of the log file to store the received message.
        """
        
        received_message = ""
        last_packet_time = None

        def packet_handler(packet):
            nonlocal received_message, last_packet_time

            # Ignore packets not from the target IP
            if packet[IP].src != target_ip or not packet.haslayer(DNS):
                return

            if packet.haslayer(DNS):
                if last_packet_time is not None:
                    time_diff = time.time() - last_packet_time
                    if abs(time_diff - short_idle) < tolerance:
                        received_message += '1'
                    elif abs(time_diff - long_idle) < tolerance:
                        received_message += '0'
                    else:
                        received_message += '.'
                last_packet_time = time.time()
            
        sniff(prn=packet_handler, filter=f"src host {target_ip}", store=0, timeout=10)
        self.log_message(received_message, log_file_name)

