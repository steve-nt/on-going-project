$TTL    604800
@       IN      SOA     dns.example.com. admin.example.com. (
                              2023110204         ; Serial
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

; SPF record (enabled for email authentication)
@       IN      TXT     "v=spf1 ip4:172.20.0.20 -all"

; DKIM record (enabled for email authentication)
default._domainkey  IN  TXT  ( "v=DKIM1; h=sha256; k=rsa; "
        "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh7Td7VIuQwb7tkA9hNzgrvt43iwCwHp+6eoWAEbW2KlBJPTxhH10c8BbB32Uz/zofcezgaimrTyW/GUf2So6DyumVlEJwjubtZifsEjwu22lAbdrWh5pEvigk9VWkzguq2PVF4jCggyFYCkWTKuljmjn/g17oCkXyWIkZ8Ew3+QC21IUhoPENwfobtC/fQZMd5xgWe3yJupxp+"
        "Wna5S/iMD4wdXjf24aYpoY53nR9fCAPXwgYwnRs5OFIfK7wnkd0SIyaEPjqob1nMZQTQMUlX7FdznxyDEFqvXCg//csVyp1xD+AmGLOn8A75QU9K6Re0xUEbK+Ubd25nU3EUizzQIDAQAB" )

; DMARC record (enabled for email policy enforcement)
_dmarc  IN      TXT     "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
