$TTL    604800
@       IN      SOA     dns.example.com. admin.example.com. (
                              2023110201         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

; Name servers
@       IN      NS      dns.example.com.

; A records
dns             IN      A       172.20.0.10
mail            IN      A       172.20.0.20
client          IN      A       172.20.0.30

; MX records
@       IN      MX      10      mail.example.com.

; SPF record (to be enabled later)
; @       IN      TXT     "v=spf1 ip4:172.20.0.20 -all"

; DKIM record (to be added after key generation)
; default._domainkey  IN  TXT  "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"

; DMARC record (to be enabled later)
; _dmarc  IN      TXT     "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
