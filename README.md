# ARP Spoofer & Man-in-the-Middle (MITM) Tool

**Author:** [cybernerddd](https://github.com/cybernerddd)  
**Repository:** [Arp-spoofer](https://github.com/cybernerddd/Arp-spoofer)

---

## 🛡️ Overview

This project is a professional-grade ARP spoofing and Man-in-the-Middle (MITM) attack tool built using Python and Scapy.  
It enables users (with proper authorization) to perform ARP poisoning, place themselves between a target (victim) and the network gateway, and optionally sniff unencrypted traffic for security auditing and educational purposes.

> **Warning:**  
> This tool is intended strictly for use in authorized penetration testing, ethical hacking training, and cybersecurity research on networks you own or have explicit, legal permission to assess.

---

## ✨ Features

- **ARP Spoofing:** Redirects network traffic between victim and gateway.
- **Automatic ARP Table Restoration:** Cleans up on exit or interruption.
- **Packet Sniffing:** Optionally sniffs packets for HTTP credentials and data (unencrypted only).
- **Customizable Interface & Timing:** Choose network interface and spoofing frequency.
- **Professional Logging:** Informative, user-friendly output.
- **Extensible Design:** Ready for integration with SSL stripping or advanced packet analysis tools.

---

## 🚀 Usage

### **Prerequisites**

- Python 3.x
- [Scapy](https://scapy.net/) (`pip install scapy`)
- Root privileges (required for network operations)

### **Enable IP Forwarding and NAT (Linux):**

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables --flush
sudo iptables -t nat --flush
sudo iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE
```
Replace `<interface>` with your actual network adapter (e.g., `eth0`, `wlan0`).

### **Run the Tool**

```sh
sudo python3 modern_arp_spoofer.py -t <victim_ip> -g <gateway_ip> -i <interface> [--sniff] [--interval N]
```

**Arguments:**
- `-t, --target`    Target/victim IP address
- `-g, --gateway`   Gateway/router IP address
- `-i, --interface` Network interface to use (e.g., eth0, wlan0)
- `--sniff`         (Optional) Enable packet sniffing for HTTP credentials
- `--interval`      (Optional) Spoofing packet interval in seconds (default: 2)

**Example:**
```sh
sudo python3 modern_arp_spoofer.py -t 192.168.1.10 -g 192.168.1.1 -i eth0 --sniff
```

---

## 🔍 How It Works

1. **ARP Spoofing:** Forges ARP replies to trick the victim and gateway into sending their traffic through your machine.
2. **MITM:** Intercepts and forwards packets, allowing traffic analysis or credential sniffing (HTTP only).
3. **Restoration:** Restores ARP tables to their legitimate state on exit.

---

## ⚠️ Legal & Ethical Notice

- **For educational and authorized testing only.**
- Do **not** use this tool on public or unauthorized networks.
- Unauthorized interception of data is illegal and unethical.
- The author assumes **no liability** for any misuse or damage.

---

## 🤝 Contributing

Improvements, feature suggestions, and pull requests are welcome!  
Please open issues for bugs, feature requests, or questions.

---

## 📚 References

- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
- [ARP Poisoning – Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing)
- [Ethical Hacking Guidelines](https://www.eccouncil.org/ethical-hacking/)

---

**Happy (ethical) hacking!**
