from scapy.all import sniff, IP, TCP, UDP, ICMP

# Callback function to process packets
def packet_callback(packet):
    print("\n=== New Packet Captured ===")
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")
    
    # Check for TCP, UDP, ICMP
    if packet.haslayer(TCP):
        print(f"TCP Packet - Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"UDP Packet - Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        print("ICMP Packet Detected")

    # Print raw payload (if any)
    if packet.haslayer(Raw):
        print(f"Payload: {packet[Raw].load}")

# Start sniffing (Change 'iface' to the correct interface if needed)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
