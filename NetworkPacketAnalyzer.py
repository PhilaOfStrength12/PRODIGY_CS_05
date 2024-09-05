import scapy.all as scapy

def packet_callback(packet):

    # Check if the packet contains an IP layer
    if packet.haslayer(scapy.IP):

        # Extract source and destination IP addresses and protocol
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Print source IP, destination IP, and protocol information
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check if the packet contains a TCP layer
        if packet.haslayer(scapy.TCP):
            print("Protocol: TCP")

            # Check if the packet contains a Raw layer (payload)
            if packet.haslayer(scapy.Raw):
                try:
                    # Extract and decode TCP payload
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"TCP Payload: {decoded_payload}")
                except (IndexError, UnicodeDecodeError):
                    # Handle exceptions if decoding fails
                    print("Unable to decode TCP payload.")

        # Check if the packet contains a UDP layer
        elif packet.haslayer(scapy.UDP):
            print("Protocol: UDP")

            # Check if the packet contains a Raw layer (payload)
            if packet.haslayer(scapy.Raw):
                try:
                    # Extract and decode UDP payload
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"UDP Payload: {decoded_payload}")
                except (IndexError, UnicodeDecodeError):
                    # Handle exceptions if decoding fails
                    print("Unable to decode UDP payload.")

def start_sniffing(interface=None):
    
    """
    Start sniffing packets on a specified network interface.
    
    Args:
        interface: The network interface to sniff on (e.g., "eth0" or "wlan0").
    """
    # Start packet sniffing
    scapy.sniff(iface=interface, store=False, prn=packet_callback)


start_sniffing()
