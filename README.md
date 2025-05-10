# 🛠️ Packet Analyzer 🚀  

Packet Analyzer is a command-line tool designed to analyze `.pcap` and `.pcapng` files, filter specific protocols, and highlight specific keywords within packet content. It provides a simple and efficient way to inspect network traffic and extract meaningful information with custom keyword highlighting.

---

## 🌟 Features

- 🌐 **Protocol Filtering:** Supports HTTP, DNS, ICMP, TCP, and UDP.
- 🔍 **Keyword Highlighting:** Detects and highlights specified keywords in packet data.
- 📊 **Packet Summaries:** Provides packet summaries for quick analysis.

---

## 🚀 Installation

1. **Clone the repository:**  
```bash
git clone https://github.com/yourusername/PacketAnalyzer.git
cd PacketAnalyzer
```

2. **Install the required packages:**  
```bash
pip install -r requirements.txt
```

## 🛠️ Usage
Run the tool using the command below:
```bash
python analyzer.py <file_path> -p <protocol> -k <keyword1> <keyword2>
```

Parameters:

- <file_path> : Path to the .pcap or .pcapng file.
- -p / --protocol : Protocol to filter (http, dns, icmp, tcp, udp).
- -k / --keywords : Space-separated list of keywords to highlight.

## 📦 Examples
1. Filter HTTP packets and search for keywords:
```bash
python analyzer.py data/sample.pcapng -p http -k admin login
```
2. Analyze all packets without filtering and search for keywords:
```bash
python analyzer.py data/sample.pcapng -k password session
```
3. Only display TCP packets without keyword search:
```bash
python analyzer.py data/sample.pcapng -p tcp
```

## 📢 Contact
For any questions or feedback, feel free to reach out:

- Email: icmustafa1@gmail.com

- LinkedIn: https://www.linkedin.com/in/mustafa-tayyip-i%C3%A7-a0b474287/
