import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            print("Protocol: TCP")
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"TCP Payload: {decoded_payload}")
                except (IndexError, UnicodeDecodeError):
                    print("Unable to decode TCP payload.")

        elif packet.haslayer(scapy.UDP):
            print("Protocol: UDP")
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"UDP Payload: {decoded_payload}")
                except (IndexError, UnicodeDecodeError):
                    print("Unable to decode UDP payload.")

def start_sniffing(interface=None):
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

# Example usage: start_sniffing("eth0") or start_sniffing("wlan0")
start_sniffing()
