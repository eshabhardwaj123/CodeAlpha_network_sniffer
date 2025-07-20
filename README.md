
#  Interactive Packet Sniffer with Meme UI

This is a graphical Python-based **Packet Sniffer** built using `Tkinter` and `Scapy`, designed to provide a fun and functional interface for monitoring network traffic in real-time.



## Features

- ✅ **Welcome Screen with Meme** — Adds a fun touch before you start sniffing.
- ✅ **Real-time Packet Capture** — Displays packet summaries live in the GUI.
- ✅ **Protocol, IP, and Port Filtering** — Focus on the packets you care about.
- ✅ **Start / Stop Controls** — Safe and smooth packet sniffing control.
- ✅ **Logs** — Saves all captured packets to a log file (`packet_log.txt`).
- ✅ **Threaded Sniffing** — Keeps the UI responsive while sniffing.
- ✅ **View Logs Button** — Easily review all captured traffic.



## GUI Overview

- **Welcome Screen:** Meme + "Start Sniffer" button  
- **Sniffer Screen:**  
  - Live packet display (scrollable)  
  - Packet counter  
  - Filter inputs (Protocol, IP, Port)  
  - Start / Stop buttons  
  - View Logs option



##  How to Run

1. **Install Dependencies**  
   Ensure you have Python installed (preferably 3.6+), then install the required modules:
   
   pip install scapy pillow


2. **Run the Program**

   python sniffer_gui.py
  

3. **Start Sniffing!**
   Click on **"Start Sniffer"** to begin capturing packets.


##  Project Structure

```
.
├── sniffer_gui.py         # Main application
├── packet_log.txt         # Auto-created log file
└── memes/
    └── meme1.jpeg         # Welcome screen meme
```


## 🔐 Requirements

* **Admin / Root Privileges**
  Packet sniffing requires elevated permissions. Run the script with `sudo` on Linux/Mac or as Administrator on Windows.

* **Python Libraries**:

  * `scapy`
  * `tkinter` (usually preinstalled)
  * `PIL` / `Pillow`


## Disclaimer

This tool is for **educational and ethical use only**. Do not use it on networks you do not own or have permission to monitor.


##  Credits

Created with ❤️ using Python, Scapy, and Tkinter.
Meme included just for some laughs 😄.


