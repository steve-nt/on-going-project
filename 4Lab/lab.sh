#!/bin/bash

# Lab 4 Helper Scripts

case "$1" in
    start)
        echo "Starting Lab 4 environment..."
        docker-compose up -d
        echo "Waiting for services to initialize..."
        sleep 5
        docker-compose ps
        ;;
    
    stop)
        echo "Stopping Lab 4 environment..."
        docker-compose down
        ;;
    
    reset)
        echo "Resetting Lab 4 environment..."
        docker-compose down -v
        docker-compose up -d
        ;;
    
    test-dns)
        echo "Testing DNS resolution..."
        docker exec -it client dig @172.20.0.10 mail.example.com
        docker exec -it client dig @172.20.0.10 example.com MX
        ;;
    
    test-mail)
        echo "Testing mail delivery..."
        docker exec -it client swaks --to test@example.com --from user@client.example.com --server mail.example.com --header "Subject: Test Email"
        ;;
    
    attack-dns)
        echo "Starting DNS spoofing attack..."
        echo "Run this in a separate terminal:"
        echo "  docker exec -it attacker python3 /root/fake_mail_server.py"
        echo ""
        docker exec -it attacker python3 /root/dns_spoof.py
        ;;
    
    attack-fake-mail)
        echo "Starting fake mail server..."
        docker exec -it attacker python3 /root/fake_mail_server.py
        ;;
    
    show-dkim)
        echo "DKIM public key:"
        docker exec -it mail-server cat /etc/opendkim/keys/example.com/default.txt 2>/dev/null || echo "DKIM keys not generated yet. Start mail-server first."
        ;;
    
    logs)
        docker-compose logs -f
        ;;
    
    logs-mail)
        docker exec -it mail-server tail -f /var/log/mail.log
        ;;
    
    shell-client)
        docker exec -it client bash
        ;;
    
    shell-attacker)
        docker exec -it attacker bash
        ;;
    
    shell-mail)
        docker exec -it mail-server bash
        ;;
    
    shell-dns)
        docker exec -it dns-server bash
        ;;
    
    *)
        echo "Lab 4: Secure E-Mail and DNS"
        echo ""
        echo "Usage: $0 {command}"
        echo ""
        echo "Commands:"
        echo "  start           - Start all containers"
        echo "  stop            - Stop all containers"
        echo "  reset           - Reset environment (removes volumes)"
        echo "  test-dns        - Test DNS resolution"
        echo "  test-mail       - Send test email"
        echo "  attack-dns      - Launch DNS spoofing attack"
        echo "  attack-fake-mail - Start fake mail server"
        echo "  show-dkim       - Display DKIM public key"
        echo "  logs            - Show all logs"
        echo "  logs-mail       - Show mail server logs"
        echo "  shell-client    - Open shell in client"
        echo "  shell-attacker  - Open shell in attacker"
        echo "  shell-mail      - Open shell in mail server"
        echo "  shell-dns       - Open shell in DNS server"
        echo ""
        exit 1
        ;;
esac
