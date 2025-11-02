
# Lab 4: Secure E-Mail and DNS - Docker Implementation

This lab demonstrates email security using DNS, SPF, DKIM, DMARC, and DNSSEC in a containerized environment.

## Architecture

- **DNS Server** (172.20.0.10): BIND9 with DNSSEC capability
- **Mail Server** (172.20.0.20): Postfix with OpenDKIM
- **Client** (172.20.0.30): Testing client with mail utilities
- **Attacker** (172.20.0.40): For simulating DNS spoofing attacks

## Quick Start

```bash
# Build and start all containers
docker-compose up -d

# View logs
docker-compose logs -f

# Access client
docker exec -it client bash

# Access attacker
docker exec -it attacker bash

# Access mail server
docker exec -it mail-server bash

# Access DNS server
docker exec -it dns-server bash
```

## Lab Tasks

### Task 1: Basic Setup and Testing

1. Start the environment:
```bash
docker-compose up -d
```

2. Test DNS resolution from client:
```bash
docker exec -it client bash
dig @172.20.0.10 mail.example.com
dig @172.20.0.10 example.com MX
```

3. Send test email:
```bash
docker exec -it client bash
swaks --to user@example.com --from test@client.example.com --server mail.example.com
```

### Task 2: DNS Spoofing Attack (Before DNSSEC)

1. Start fake mail server on attacker:
```bash
docker exec -it attacker bash
python3 /root/fake_mail_server.py
```

2. In another terminal, run DNS spoof:
```bash
docker exec -it attacker bash
python3 /root/dns_spoof.py
```

3. From client, try sending email while attack is active
4. Observe email being intercepted by fake server

### Task 3: Email Header Forgery

Test forged headers from client:
```bash
docker exec -it client bash
swaks --to victim@example.com \
      --from ceo@example.com \
      --header "From: CEO <ceo@example.com>" \
      --body "Please transfer funds immediately" \
      --server mail.example.com
```

### Task 4: Enable SPF

1. Edit DNS zone to add SPF:
```bash
docker exec -it dns-server bash
# Uncomment SPF line in /etc/bind/zones/db.example.com
# Increment serial number
rndc reload
```

2. Configure Postfix to check SPF (requires additional setup)

### Task 5: Enable DKIM

1. DKIM keys are auto-generated on mail server startup
2. Get public key:
```bash
docker exec -it mail-server cat /etc/opendkim/keys/example.com/default.txt
```

3. Add DKIM record to DNS zone
4. Enable DKIM in Postfix by uncommenting milter lines in main.cf
5. Restart mail server:
```bash
docker exec -it mail-server service postfix restart
```

### Task 6: Enable DNSSEC

1. Generate DNSSEC keys on DNS server:
```bash
docker exec -it dns-server bash
cd /etc/bind/zones
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com
dnssec-keygen -f KSK -a RSASHA256 -b 4096 -n ZONE example.com
dnssec-signzone -o example.com db.example.com
```

2. Update named.conf.local to use signed zone
3. Configure client to validate DNSSEC

### Task 7: Enable DMARC

Add DMARC record to DNS:
```
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Testing and Verification

### Check DNS responses:
```bash
dig @172.20.0.10 example.com MX
dig @172.20.0.10 example.com TXT
dig @172.20.0.10 default._domainkey.example.com TXT
```

### Test email delivery:
```bash
swaks --to test@example.com \
      --from sender@example.com \
      --server mail.example.com \
      --header "Subject: Test Email"
```

### Monitor traffic:
```bash
docker exec -it client tcpdump -i any port 53 -n
docker exec -it client tcpdump -i any port 25 -n
```

### Check mail logs:
```bash
docker exec -it mail-server tail -f /var/log/mail.log
```

## Cleanup

```bash
docker-compose down
docker-compose down -v  # Also remove volumes
```

## Report Requirements

Document the following:
1. Initial setup and DNS/mail server configuration
2. Successful DNS spoofing attack demonstration
3. Email forgery demonstration
4. SPF implementation and testing
5. DKIM key generation and verification
6. DNSSEC setup and validation
7. DMARC policy configuration
8. Comparison of before/after security measures
9. Traffic captures showing differences
10. Attack attempts before and after hardening

## Troubleshooting

### DNS not resolving:
```bash
docker exec -it dns-server named-checkconf
docker exec -it dns-server named-checkzone example.com /etc/bind/zones/db.example.com
```

### Mail not delivering:
```bash
docker exec -it mail-server postfix check
docker exec -it mail-server tail -f /var/log/mail.log
```

### Container networking issues:
```bash
docker network inspect 4lab_labnet
docker exec -it client ping mail.example.com
```
