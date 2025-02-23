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
    "sniffing": [os.path.join(meme_folder, "meme2.jpeg"), os.path.join(meme_folder, "meme3.jpeg")],
    "stop": os.path.join(meme_folder, "meme4.jpeg")
}

capturing = False

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
    
    start_button = tk.Button(welcome_frame, text="Start Sniffing", command=start_sniffing_ui, bg="green", fg="white")
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
    if not capturing:
        return
    
    info = f"[+] Packet: {packet.summary()}\n"
    packet_text.insert(tk.END, info)
    packet_text.see(tk.END)
    update_meme()

# Function to start packet sniffing in a separate thread
def start_sniffing():
    global capturing
    capturing = True
    packet_text.insert(tk.END, "\n[+] Sniffing Started...\n")
    
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False, stop_filter=lambda x: not capturing))
    sniff_thread.daemon = True
    sniff_thread.start()

# Function to stop packet sniffing
def stop_sniffing():
    global capturing
    capturing = False
    packet_text.insert(tk.END, "\n[-] Sniffing Stopped.\n")

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
packet_text = scrolledtext.ScrolledText(sniffer_frame, width=70, height=15, bg="black", fg="white")
packet_text.pack()

# Start/Stop Buttons
button_frame = tk.Frame(sniffer_frame, bg="black")
button_frame.pack()

stop_img = Image.open(meme_files["stop"])
stop_img = stop_img.resize((50, 50))
stop_img = ImageTk.PhotoImage(stop_img)

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_button.pack(side=tk.LEFT, padx=10, pady=5)
stop_button = tk.Button(button_frame, image=stop_img, command=stop_sniffing, bg="red")
stop_button.image = stop_img
stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

# Meme Display
meme_label = tk.Label(sniffer_frame, bg="black")
meme_label.pack()

root.mainloop()
