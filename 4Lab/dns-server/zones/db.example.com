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
; This is a zone-signing key, keyid 34576, for example.com.
; Created: 20251102160237 (Sun Nov  2 16:02:37 2025)
; Publish: 20251102160237 (Sun Nov  2 16:02:37 2025)
; Activate: 20251102160237 (Sun Nov  2 16:02:37 2025)
example.com. IN DNSKEY 256 3 8 AwEAAaGo7X6iI45c76eIHvdi5HlARb/4kkaQ7BeDZ9xgpojUcdoaLioA HK1P1RXaXRiG4wo1cLUty8RzY1Tok0VWd2MA0Bg1A2YLL6QocnvHFOh/ y9ipWZzwzo3aa2g20cRIioBJ/vidzx19UNZax/B+F9CoreTqP3Mbvz/k LcvFRvFKeyhuf3iYcuxyEJbFph0T3LO9KA8X7LlJEtiziJQpr6SbmujP IR3UBu9Gem2X5JjD57eJGyYtiCHdfbcCnsNVw0MGKUM6YVgodGJyPm0b Pvynd9+QZr1aX5K0pcsmeRAbaNqruB+py63564T014VcILBcro1grpwE 9UyJtDCRFZ0=
; This is a key-signing key, keyid 4856, for example.com.
; Created: 20251102160244 (Sun Nov  2 16:02:44 2025)
; Publish: 20251102160244 (Sun Nov  2 16:02:44 2025)
; Activate: 20251102160244 (Sun Nov  2 16:02:44 2025)
example.com. IN DNSKEY 257 3 8 AwEAAaNRySTJhrpb8FulPwdgCBnMkaNHT0eejnoT/Wgf7R6DxLIwzzvk b3KG1gq5EN0jfACgnYn1kRO25cq0zuhP0ypMjEh5s87e1CT0WnkAL2LZ jDGk19JEGpNOT84L99M7/5YidYQUMuwZPNOg4nJ7Tv+k+cOOYJMXC5ok 22xJic3/YcbEsxs/7VbDz8xqcWhs5W2Uu0lWmhyH2rFjRhTWqXuppcSY S7dKN20RvVzpW0ehAiefF9IwyokOkPF6SVKBc7ec1Ok7lHH1aQh6woVT krPOACj4Y3Bh7B/V1bQMXDtQzbrl+Ztf9HBdKPZcDyFWzsWuWjDL9AR/ 7eIySTmExVGeOC30kiwJ73f/IrRalBVkrVrmURtLlzEmMfPG8S284OPt BQa6i8cR82b5sSJvNIX49yLxRa/vaOJLSZ9pwplHZ+O46CUvEQs3noM3 tjhX2NgFtPxojUTWQI7PN+cDpQxj0xiEAlMnCPiCgPE+qx3O6V1z/Bde D9FNEeu5+310yIeJK0iZMZiwcyxwz2eHdngrAw3djX5kELF+ZmgqWDSO UFny9kPjOIEU52jM4KOF7KTE+8kKHFpbq4VqzIc/ZNxJmJRfrqvGU8P3 2llwkXd/kfeFlte/BlMd1SKejY+OcZ2aM3bp97fIpVNT9DLX2Hh+/mZi hznATdkdPWMnP0QN
