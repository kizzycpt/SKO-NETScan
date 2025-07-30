# Sko_NetScan 🔍

Created By Samuel Quarm
A fast, multi-threaded network scanner built in Python. It identifies devices on your local network, scans for open ports with protocol labels, performs OS fingerprinting via Nmap, and summarizes the results — all while saving logs to an organized folder.

---

## 📌 Features

- ✅ ARP scan to detect active devices on a subnet  
- ✅ TCP port scanning with protocol name display (e.g., HTTPS, FTP)  
- ✅ OS detection using Nmap  
- ✅ Summary report showing:
  - Total hosts found
  - Subnet scanned
  - Local and public IP addresses  
- ✅ Auto-saves results in `Sko_NetScan/logs/scan_log.txt`

---

## 🛠️ Requirements

Install the dependencies using:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

To run the scanner:

```bash
python scanner.py -s <subnet>
```

Example:

```bash
python scanner.py -s 192.168.1.0/24
```

If no `-s` (subnet) is provided, it defaults to `192.168.1.0/24`.

---

## 📁 Output

All scan results are saved in:

```
Sko_NetScan/logs/scan_log.txt
```

---

## 🧪 Example Output

```
Port 22 (SSH): OPEN
Port 80 (HTTP): CLOSED/FILTERED
Port 443 (HTTPS): OPEN

========= SCAN SUMMARY =========
Total Hosts Found: 4
Subnet Scanned: 192.168.1.0/24
Local IP: 192.168.1.15
Public IP: 8.23.5.88
================================
```

---

## ⚠️ Disclaimer

This tool is for **educational and authorized use only**.  
Do **NOT** scan networks that you do not own or lack permission to analyze.  
Use responsibly.

---

## 📄 License

MIT License
