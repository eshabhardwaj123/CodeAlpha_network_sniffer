import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

# Default settings
PACKET_LIMIT = 20  # Number of packets to capture
TIMEOUT = 30  # Stop sniffing after 30 seconds
stop_sniffing = False

# Function to process packets
def packet_callback(packet):
    if packet.haslayer(IP):
        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        result = f"Source: {packet[IP].src} → Dest: {packet[IP].dst} | Protocol: {protocol}\n"
        text_output.insert(tk.END, result)
        text_output.yview(tk.END)

# Function to start sniffing
def start_sniffing():
    global stop_sniffing
    stop_sniffing = False
    status_label.config(text="Status: Sniffing...", fg="green")

    # Get selected protocol
    selected_protocol = protocol_var.get()
    
    def sniff_packets():
        sniff(
            prn=packet_callback,
            store=False,
            count=PACKET_LIMIT,
            timeout=TIMEOUT,
            filter=selected_protocol.lower() if selected_protocol != "All" else None
        )
        status_label.config(text="Status: Stopped", fg="red")

    # Run in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

# Function to stop sniffing manually
def stop_sniffing():
    global stop_sniffing
    stop_sniffing = True
    status_label.config(text="Status: Stopped", fg="red")

# GUI Setup
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("500x400")

# Title
title_label = tk.Label(root, text="Network Packet Sniffer", font=("Arial", 14, "bold"))
title_label.pack(pady=5)

# Status Label
status_label = tk.Label(root, text="Status: Idle", fg="black", font=("Arial", 10))
status_label.pack()

# Protocol Selection
protocol_var = tk.StringVar(value="All")
protocol_label = tk.Label(root, text="Select Protocol:")
protocol_label.pack()
protocol_dropdown = ttk.Combobox(root, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP"])
protocol_dropdown.pack()

# Start/Stop Buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=15)
start_btn.grid(row=0, column=0, padx=5)

stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15)
stop_btn.grid(row=0, column=1, padx=5)

# Output Display
text_output = scrolledtext.ScrolledText(root, height=15, width=60)
text_output.pack(pady=5)

# Run the GUI
root.mainloop()
