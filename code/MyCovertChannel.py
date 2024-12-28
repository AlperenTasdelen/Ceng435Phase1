"""
Covert Timing Channel that exploits Idle Period Between Packet Bursts using DNS
"""

from CovertChannelBase import CovertChannelBase
import time
import random
from scapy.all import IP, UDP, DNS, DNSQR, sniff

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, target_ip, domain, short_idle, long_idle, burst_size):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        binary_message += '.' # Stop packet
        start_time = time.time()

        # Send the encoded message
        for bit in binary_message:
            for _ in range(burst_size):
                dns_packet = (
                    IP(dst=target_ip) /
                    UDP(dport=53) /
                    DNS(
                        rd=1,
                        qd=DNSQR(qname=domain, qtype='A')
                    )
                )
                CovertChannelBase.send(self, dns_packet)
                
            if bit == '1':
                time.sleep(short_idle)
            elif bit == '0':
                time.sleep(long_idle)

        end_time = time.time()
        print("Bits per second: ", 128 / (end_time - start_time))
        print("Message sent successfully.")
        

    def receive(self, target_ip, short_idle, long_idle, tolerance, log_file_name):
        received_message = ""
        received_bytes = ""
        last_packet_time = None

        def packet_handler(packet):
            nonlocal received_message, last_packet_time, received_bytes

            # Ignore packets not from the target IP
            if not packet.haslayer(IP) or packet[IP].src != target_ip or not packet.haslayer(DNS):
                return

            # Decode the time-based bit
            if last_packet_time is not None:
                time_diff = time.time() - last_packet_time
                
                if abs(time_diff - short_idle) < tolerance:
                    received_bytes += '1'
                elif abs(time_diff - long_idle) < tolerance:
                    received_bytes += '0'

            # Convert bits to bytes
            if len(received_bytes) >= 8:
                decoded_byte = chr(int(received_bytes, 2))
                received_message += decoded_byte
                if (decoded_byte == '.'):
                    print("Stop packet received. Ending reception.")
                    self.log_message(received_message, log_file_name)
                    exit()
                    return
                print(f"Received byte: {received_bytes} -> {decoded_byte}")
            
                received_bytes = ""

            last_packet_time = time.time()

        sniff(prn=packet_handler, filter=f"src host {target_ip} and dst port 53", store=0)

        # Log the decoded message
        self.log_message(received_message, log_file_name)

