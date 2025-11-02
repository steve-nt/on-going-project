#!/usr/bin/env python3
"""
Fake SMTP Server for demonstration
Accepts mail and shows it was intercepted
"""

import socket
import threading

HOST = '0.0.0.0'
PORT = 25

def handle_client(client_socket, address):
    print(f"\n[+] Connection from {address}")
    
    try:
        client_socket.send(b"220 fake-mail.attacker.local ESMTP\r\n")
        
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            
            message = data.decode('utf-8', errors='ignore').strip()
            print(f"[RECV] {message}")
            
            if message.startswith("HELO") or message.startswith("EHLO"):
                client_socket.send(b"250 Hello, pleased to meet you\r\n")
            elif message.startswith("MAIL FROM"):
                print(f"[!] INTERCEPTED MAIL FROM: {message}")
                client_socket.send(b"250 OK\r\n")
            elif message.startswith("RCPT TO"):
                print(f"[!] INTERCEPTED RCPT TO: {message}")
                client_socket.send(b"250 OK\r\n")
            elif message.startswith("DATA"):
                client_socket.send(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            elif message == ".":
                print("[!] EMAIL INTERCEPTED SUCCESSFULLY!")
                client_socket.send(b"250 OK: Message accepted for delivery\r\n")
            elif message.startswith("QUIT"):
                client_socket.send(b"221 Bye\r\n")
                break
            else:
                client_socket.send(b"250 OK\r\n")
                
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection from {address} closed")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[*] Fake SMTP server listening on {HOST}:{PORT}")
    print("[*] Waiting for connections...")
    
    while True:
        client_sock, address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_sock, address))
        client_handler.start()

if __name__ == "__main__":
    main()
