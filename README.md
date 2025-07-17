# 🕵️‍♂️ ARP Spoofer – Man-in-the-Middle Python Tool

Welcome to **Cybernerddd’s ARP Spoofing Tool** – a Python script that enables Man-in-the-Middle `(MITM)` attacks by poisoning the `ARP` tables of devices on a local network.

---

## Features

- ⚡ ARP Spoofing between a victim and a gateway
- 🔁 Continuous packet poisoning
- 💥 Auto ARP table restoration on exit
- 🔧 Interface with command-line arguments
- 💻 Built with `Python 3` and `Scapy`

---

## ⚙️ Requirements

> - Python 3
> - `scapy` library

Install it with:

```bash
pip install scapy
```

## Usage
```bash
sudo python3 arp_spoofer.py -t <target_ip> -g <gateway_ip>
```
**EXAMPLE**
```bash
sudo python3 arp_spoofer.py -t 192.168.1.147 -g 192.168.1.1
```
> Requires root privileges

## Sample Output
[*] Enabling IP Forwarding...
[*] Starting ARP spoofing on `192.168.1.147` <-> `192.168.1.1`
[+] Sent Packets: 10
...
[-] CTRL+C detected. Restoring ARP tables...
[+] ARP spoofing stopped and targets restored.

## ⚠️ Legal Disclaimer
This tool is for educational and authorized penetration testing only.
Do NOT use it on networks you don’t own or have permission to test.


## 🙌 Author
- Created by `Cybernerddd`
- GitHub: `github.com/Cybernerddd`
