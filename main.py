from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

# Define the number of packets to capture
PACKET_LIMIT = 20  # Stop after capturing 20 packets
TIMEOUT = 30  # Stop sniffing after 30 seconds

# Callback function to process packets
def packet_callback(packet):
    print("\n=== New Packet Captured ===")

    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    if packet.haslayer(TCP):
        print(f"TCP Packet - Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"UDP Packet - Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        print("ICMP Packet Detected")

    if packet.haslayer(Raw):
        print(f"Payload: {packet[Raw].load}")

# Function to stop sniffing after TIMEOUT seconds
def stop_sniffing():
    print("\n[INFO] Time limit reached. Stopping packet sniffing...\n")
    global stop_sniff
    stop_sniff = True

# Start the sniffer
print("Starting packet sniffer... It will stop after 20 packets or 30 seconds.")
stop_sniff = False
sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False, count=PACKET_LIMIT, stop_filter=lambda x: stop_sniff))
sniff_thread.start()

# Start the timer for automatic stop
timer = threading.Timer(TIMEOUT, stop_sniffing)
timer.start()

sniff_thread.join()  # Wait for sniffing to finish
