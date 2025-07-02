

````
# 🔍 ScanForge: Advanced TCP Port Scanner

ScanForge is a high-speed, feature-rich TCP port scanner built with Python and Scapy. It allows you to scan individual IP addresses or full subnets for open ports using TCP SYN scanning. With support for multithreading and optional banner grabbing, it's a powerful tool for network reconnaissance, penetration testing, and forensic analysis.

---

## 🚀 Features

- ⚡ **Multithreaded TCP SYN scanning**
- 🧠 **CIDR/IP range support**
- 🎯 **Custom port selection** (single, list, range)
- 🛡️ **Banner grabbing** to identify services
- 🧩 **Scapy-powered raw packet crafting**
- 🎛️ **Command-line interface with argparse**

---

## 🛠️ Requirements

- Python 3.6+
- `scapy`
- Root/Administrator privileges (for raw packet sending)

### 🔧 Install dependencies:

```bash
pip install scapy
````

---

## 📦 Usage

```bash
python scanner.py <target> [options]
```

### 📘 Examples

* **Basic Scan on single IP (ports 1-1024)**

  ```bash
  python scanner.py 192.168.1.10
  ```

* **Scan a subnet with specific ports**

  ```bash
  python scanner.py 192.168.1.0/30 -p 22,80,443,8000-8100
  ```

* **Scan with banner grabbing**

  ```bash
  python scanner.py 10.0.0.1 -p 21-25 -b
  ```

---

## 🧪 Output Example

```
🔍 Scanning Host: 192.168.1.10
  ✅ Port 22 OPEN (ssh)
  ✅ Port 80 OPEN (http)
  ✅ Port 21 OPEN (ftp) | Banner: 220 Welcome to FTP service
```

---

## ⚠️ Disclaimer

> This tool is intended for **educational and authorized penetration testing purposes only**.
> Unauthorized scanning of networks may be illegal. Always ensure you have permission.

---

## 📄 Project Summary

ScanForge is an advanced TCP scanner using Scapy for efficient SYN scanning of networks.
It supports multithreaded execution, IP/CIDR targeting, and banner grabbing for service detection.
Ideal for forensic analysts, security researchers, and ethical hackers.
Simple to use, yet powerful for network auditing tasks.

---

## 👨‍💻 Author

**CRUSVEDER**
Python | Cybersecurity | Network Tools

---

## 📜 License

MIT License – free to use, modify, and distribute.

```


