
# 🛡️ CRUS SCANNER

**CRUS SCANNER** is a fast and flexible TCP port scanner built with Python, using **Scapy**, **Socket**, and a touch of interactivity via an in-terminal command shell. It can also attempt to grab banners from open ports.

> ⚡ Powered by multi-threading and stylish output via Rich and PyFiglet.

---

## 🚀 Features

- TCP SYN port scanning using raw packets (`Scapy`)
- Banner grabbing (optional)
- CIDR range support (e.g., `192.168.1.0/24`)
- Interactive command-line shell
- Colorful, readable output with `rich`
- Fast scanning using `ThreadPoolExecutor`

---

## 📦 Dependencies

Install dependencies via pip:

```bash
pip install -r requirements.txt
````

**Required libraries:**

* `scapy`
* `rich`
* `pyfiglet`

You can also install them manually:

```bash
pip install scapy rich pyfiglet
```

> ⚠️ Run with `sudo` or admin permissions (Scapy requires raw socket access).

---

## 🧪 Usage

Run the scanner interactively:

```bash
python3 crus_scanner.py
```

You’ll enter an interactive shell like this:

```
CRUS SCANNER
============

Enter commands like:
  scan 192.168.1.1 -p 80,443 -b
  exit or quit to leave.

crus>
```

### 🔧 Commands

| Command Example                 | Description                     |
| ------------------------------- | ------------------------------- |
| `scan 192.168.1.1`              | Scan default ports (1-1024)     |
| `scan 10.0.0.0/24 -p 22,80,443` | Scan ports on entire subnet     |
| `scan 127.0.0.1 -p 21-25 -b`    | Scan ports with banner grabbing |
| `help` or `?`                   | Show available commands         |
| `exit` or `quit`                | Exit the scanner                |

---

## 📌 Notes

* Scapy may trigger firewall alerts. Use responsibly on machines you own or have permission to scan.
* Banner grabbing is TCP-based (basic socket request) and may fail if services don’t send banners.
* Scanning high port ranges or many IPs might take time.

---

## 📁 Example Output

```
crus> scan 127.0.0.1 -p 22,80,443 -b

🔍 Scanning Host: 127.0.0.1
  ✅ Port 22 OPEN (ssh) | Banner: OpenSSH_8.9p1 Ubuntu
  ❌ No open ports found.
```

---

## 🔒 Disclaimer

This tool is meant for **educational** and **authorized penetration testing** use only. Do **not** use it on networks you don’t own or have written permission to scan.

---

## 📜 License

MIT License — feel free to use, modify, and contribute!

---

## 👤 Author

Made with 💻 by **Crusveder**
GitHub: [@crusveder](https://github.com/crusveder)







