import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import sniff
import os
import threading
from PIL import Image, ImageTk

# Load memes
meme_folder = "./memes/"
meme_files = {
    "welcome": os.path.join(meme_folder, "meme1.jpeg")
}

capturing = False
packet_count = 0  # Counter for packets
selected_protocol = "ALL"
filter_ip = ""
filter_port = ""
log_file = "packet_log.txt"

# Function to switch UI from Welcome to Sniffer
def start_sniffing_ui():
    welcome_frame.pack_forget()
    sniffer_frame.pack()
    start_sniffing()

# Function to show a welcome screen
def show_welcome():
    img = Image.open(meme_files["welcome"])
    img = img.resize((250, 250))
    img = ImageTk.PhotoImage(img)
    
    meme_label = tk.Label(welcome_frame, image=img, bg="black")
    meme_label.image = img
    meme_label.pack()
    
    start_button = tk.Button(welcome_frame, text="Start Sniffer", command=start_sniffing_ui, bg="green", fg="white", 
                             font=("Courier", 10, "bold"), relief="raised", bd=5, width=14, height=3)
    start_button.pack(pady=10)

# Function to process captured packets
def packet_callback(packet):
    global packet_count
    if not capturing:
        return
    
    # Apply filters
    if selected_protocol != "ALL" and selected_protocol.lower() not in packet.summary().lower():
        return
    if filter_ip and filter_ip not in packet.summary():
        return
    if filter_port and filter_port not in packet.summary():
        return
    
    packet_count += 1
    info = f"[+] Packet {packet_count}: {packet.summary()}\n"
    packet_text.insert(tk.END, info)
    packet_text.see(tk.END)
    packet_counter_label.config(text=f"Packets Captured: {packet_count}")
    
    with open(log_file, "a") as f:
        f.write(f"Packet {packet_count}: {packet.summary()}\n")

# Function to start packet sniffing in a separate thread
def start_sniffing():
    global capturing, packet_count
    capturing = True
    packet_count = 0
    packet_text.insert(tk.END, "\n[+] Sniffing Started...\n")
    packet_counter_label.config(text=f"Packets Captured: {packet_count}")
    
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False, stop_filter=lambda x: not capturing))
    sniff_thread.daemon = True
    sniff_thread.start()

# Function to stop packet sniffing
def stop_sniffing():
    global capturing
    capturing = False
    packet_text.insert(tk.END, "\n[-] Sniffing Stopped.\n")

# Function to view logs
def view_logs():
    log_window = tk.Toplevel(root)
    log_window.title("Packet Logs")
    log_window.geometry("600x400")
    
    log_text = scrolledtext.ScrolledText(log_window, width=70, height=20, bg="black", fg="green", font=("Courier", 10))
    log_text.pack()
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            log_text.insert(tk.END, f.read())

# Function to apply filters
def apply_filters():
    global selected_protocol, filter_ip, filter_port
    selected_protocol = protocol_var.get()
    filter_ip = ip_entry.get()
    filter_port = port_entry.get()

# GUI Setup
root = tk.Tk()
root.title("Interactive Packet Sniffer")
root.geometry("700x600")
root.configure(bg="black")

# Welcome Frame
welcome_frame = tk.Frame(root, bg="black")
welcome_frame.pack()
show_welcome()

# Sniffer Frame (Hidden initially)
sniffer_frame = tk.Frame(root, bg="black")

# Packet Display Area
packet_text = scrolledtext.ScrolledText(sniffer_frame, width=85, height=15, bg="black", fg="green", font=("Courier", 10))
packet_text.pack()

# Packet Counter
packet_counter_label = tk.Label(sniffer_frame, text="Packets Captured: 0", bg="black", fg="white", font=("Courier", 12, "bold"))
packet_counter_label.pack()

# Filtering Options
filter_frame = tk.Frame(sniffer_frame, bg="black")
filter_frame.pack(pady=5)
protocol_var = tk.StringVar(value="ALL")
tk.Label(filter_frame, text="Protocol:", fg="white", bg="black").pack(side=tk.LEFT)
protocol_menu = ttk.Combobox(filter_frame, textvariable=protocol_var, values=["ALL", "TCP", "UDP", "HTTP"])
protocol_menu.pack(side=tk.LEFT, padx=5)
tk.Label(filter_frame, text="IP:", fg="white", bg="black").pack(side=tk.LEFT)
ip_entry = tk.Entry(filter_frame, width=15)
ip_entry.pack(side=tk.LEFT, padx=5)
tk.Label(filter_frame, text="Port:", fg="white", bg="black").pack(side=tk.LEFT)
port_entry = tk.Entry(filter_frame, width=10)
port_entry.pack(side=tk.LEFT, padx=5)
tk.Label(filter_frame, text="Port:", fg="white", bg="black").pack(side=tk.LEFT)
apply_button = tk.Button(filter_frame, text="Apply", command=apply_filters, bg="gray", fg="white")
apply_button.pack(side=tk.LEFT, padx=5)

# View Logs Button
log_button = tk.Button(sniffer_frame, text="View Logs", command=view_logs, bg="blue", fg="white", 
                       font=("Courier", 12, "bold"), relief="raised", bd=5, width=10, height=2)
log_button.pack(pady=5)

# Start/Stop Buttons
button_frame = tk.Frame(sniffer_frame, bg="black")
button_frame.pack()

start_button = tk.Button(button_frame, text="Start", command=start_sniffing, bg="green", fg="white", 
                         font=("Courier", 12, "bold"), relief="raised", bd=5, width=10, height=2)
start_button.pack(side=tk.LEFT, padx=10, pady=5)

stop_button = tk.Button(button_frame, text="Stop", command=stop_sniffing, bg="red", fg="white", 
                        font=("Courier", 12, "bold"), relief="raised", bd=5, width=10, height=2)
stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

root.mainloop()
