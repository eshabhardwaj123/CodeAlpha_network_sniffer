import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import random
import os
import threading
from PIL import Image, ImageTk

# Load memes
meme_folder = "./memes/"
meme_files = {
    "welcome": os.path.join(meme_folder, "meme1.jpeg"),
    "sniffing": [os.path.join(meme_folder, "meme3.jpeg")]
}

capturing = False
packet_count = 0  # Counter for packets

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

# Function to update the meme while sniffing
def update_meme():
    if meme_files["sniffing"]:
        random_meme = random.choice(meme_files["sniffing"])
        img = Image.open(random_meme)
        img = img.resize((150, 150))
        img = ImageTk.PhotoImage(img)
        meme_label.configure(image=img)
        meme_label.image = img

# Function to process captured packets
def packet_callback(packet):
    global packet_count
    if not capturing:
        return
    
    packet_count += 1
    info = f"\033[92m[+] Packet {packet_count}: {packet.summary()}\033[0m\n"
    packet_text.insert(tk.END, info)
    packet_text.see(tk.END)
    update_meme()
    packet_counter_label.config(text=f"Packets Captured: {packet_count}")

# Function to start packet sniffing in a separate thread
def start_sniffing():
    global capturing, packet_count
    capturing = True
    packet_count = 0
    packet_text.insert(tk.END, "\033[92m\n[+] Sniffing Started...\033[0m\n")
    packet_counter_label.config(text=f"Packets Captured: {packet_count}")
    
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False, stop_filter=lambda x: not capturing))
    sniff_thread.daemon = True
    sniff_thread.start()

# Function to stop packet sniffing
def stop_sniffing():
    global capturing
    capturing = False
    packet_text.insert(tk.END, "\033[91m\n[-] Sniffing Stopped.\033[0m\n")

# GUI Setup
root = tk.Tk()
root.title("Interactive Packet Sniffer")
root.geometry("600x400")
root.configure(bg="black")

# Welcome Frame
welcome_frame = tk.Frame(root, bg="black")
welcome_frame.pack()
show_welcome()

# Sniffer Frame (Hidden initially)
sniffer_frame = tk.Frame(root, bg="black")

# Packet Display Area
packet_text = scrolledtext.ScrolledText(sniffer_frame, width=70, height=15, bg="black", fg="green", font=("Courier", 10))
packet_text.pack()

# Packet Counter
packet_counter_label = tk.Label(sniffer_frame, text="Packets Captured: 0", bg="black", fg="white", font=("Courier", 12, "bold"))
packet_counter_label.pack()

# Start/Stop Buttons
button_frame = tk.Frame(sniffer_frame, bg="black")
button_frame.pack()

start_button = tk.Button(button_frame, text="Start", command=start_sniffing, bg="green", fg="white", 
                         font=("Courier", 12, "bold"), relief="raised", bd=5, width=10, height=2)
start_button.pack(side=tk.LEFT, padx=10, pady=5)

stop_button = tk.Button(button_frame, text="Stop", command=stop_sniffing, bg="red", fg="white", 
                        font=("Courier", 12, "bold"), relief="raised", bd=5, width=10, height=2)
stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

# Meme Display
meme_label = tk.Label(sniffer_frame, bg="black")
meme_label.pack()

root.mainloop()
