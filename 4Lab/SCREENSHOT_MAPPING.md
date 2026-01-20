# Screenshot Mapping: LAB_STEPS.txt → report1.tex

This document maps screenshots from LAB_STEPS.txt to their placement in report1.tex

## Section 1: Traffic and Log Analysis - Before vs After Security Implementation

### Subsection 1.1: DNS Traffic Comparison

#### 1.1.1 DNS Query Traffic - Without DNSSEC
**Screenshot to use:**
- **Step 4** from LAB_STEPS.txt: "Test DNS Resolution from Client"
  - Command: `dig @172.20.0.10 mail.example.com`
  - Shows: Basic DNS query without DNSSEC (simple A record response)
  - Place after line 91 in report1.tex (after DNS Response Structure listing)

**Alternative:**
- **Step 34** from LAB_STEPS.txt: "Capture DNS Traffic (without DNSSEC)"
  - Command: `tcpdump -i any port 53 -n -v`
  - Shows: Raw packet capture of DNS query/response
  - Can be used alongside Step 4 screenshot

#### 1.1.2 DNS Query Traffic - With DNSSEC
**Screenshot to use:**
- **Step 40** from LAB_STEPS.txt: "Verify DNSSEC"
  - Command: `dig @172.20.0.10 example.com +dnssec`
  - Shows: DNS response with RRSIG records, DNSKEY records, NSEC3
  - Place after line 145 in report1.tex (after DNS Response Structure with DNSSEC)

**Additional screenshot:**
- **Step 37** from LAB_STEPS.txt: "Sign the Zone"
  - Shows: Zone signing output with file sizes (2.9KB → 13KB)
  - Can illustrate the overhead of DNSSEC
  - Place in the DNS Traffic Comparison Table section

### Subsection 1.2: SMTP Traffic Comparison

#### 1.2.1 SMTP Traffic - Without DKIM
**Screenshot to use:**
- **Step 8** from LAB_STEPS.txt: "Send First Test Email"
  - Command: `swaks --to user@example.com --from testuser@client.example.com...`
  - Shows: SMTP conversation WITHOUT DKIM signature
  - Place after line 228 in report1.tex (after Email Header Analysis - No Security)

**Additional screenshot:**
- **Step 9** from LAB_STEPS.txt: "Verify Email in Mail Server Logs"
  - Command: `docker exec -it mail-server tail -n 50 /var/log/mail.log`
  - Shows: Simple log entries without DKIM processing
  - Can be used in the log comparison section

#### 1.2.2 SMTP Traffic - With DKIM
**Screenshot to use:**
- **Step 26** from LAB_STEPS.txt: "Verify DKIM Signature"
  - Command: `docker exec mail-server cat /var/spool/mail/user`
  - Shows: Email headers WITH DKIM-Signature
  - Place after line 287 in report1.tex (after Email Header Analysis - With DKIM)

**Alternative:**
- **Step 35** from LAB_STEPS.txt: "Capture SMTP Traffic with DKIM"
  - Command: `tcpdump -i any port 25 -n -A`
  - Shows: SMTP conversation with DKIM signature in transit
  - Very useful for traffic analysis section

### Subsection 1.3: Mail Server Log Comparison

#### 1.3.1 Logs Without Security Mechanisms
**Screenshot to use:**
- **Step 9** from LAB_STEPS.txt: "Verify Email in Mail Server Logs"
  - Shows: Simple Postfix logs (6 entries, no security processing)
  - Place after line 383 in report1.tex (after Log Analysis - No Security)

#### 1.3.2 Logs With DKIM Enabled
**Screenshot to use:**
- **Step 27** from LAB_STEPS.txt: "Check DKIM in Logs"
  - Command: `docker exec -it mail-server tail -50 /var/log/mail.log | grep -i dkim`
  - Shows: OpenDKIM milter processing, signature addition
  - Place after line 432 in report1.tex (after Log Analysis - With DKIM)

**Additional screenshot:**
- **Step 3** from LAB_STEPS.txt: "Check Container Logs"
  - Shows: DKIM key generation on startup
  - Can supplement the DKIM logging section

---

## Section 2: Attack Documentation - Success in Insecure Setup vs Failure with Security

### Attack 1: Email Header Forgery

#### Attack Execution - INSECURE Setup (NO SPF/DKIM/DMARC)

**Screenshot 1 - Attack Command & Success:**
- **Step 10** from LAB_STEPS.txt: "Test Email Header Forgery"
  - Command: `swaks --to victim@example.com --from ceo@example.com...`
  - Shows: "250 2.0.0 Ok: queued" - Email accepted WITHOUT validation
  - Place after line 502 in report1.tex (after SMTP Conversation - Attack Succeeds)

**Screenshot 2 - Mail Server Logs (No Warnings):**
- **Step 11** from LAB_STEPS.txt: "Verify Forged Email Delivered"
  - Command: `docker exec mail-server cat /var/spool/mail/victim`
  - Shows: Forged email delivered to victim's mailbox
  - Place after line 520 in report1.tex (after Mail Server Logs section)

**Screenshot 3 - Email Headers:**
- **Step 12** from LAB_STEPS.txt: "Inspect Forged Email Headers"
  - Shows: Email headers with forged "From: CEO <ceo@example.com>"
  - No security indicators present
  - Place after line 539 in report1.tex (after Delivered Email Headers)

#### Attack Execution - SECURE Setup (WITH SPF/DKIM/DMARC)

**Screenshot 1 - Email with DKIM Signature:**
- **Step 31** from LAB_STEPS.txt: "Retry Email Forgery (Should Be Harder)"
  - Same forgery attempt but email now has DKIM signature
  - Shows: Email accepted but signed (different security context)
  - Place after line 623 in report1.tex (after Delivered Email Headers WITH DKIM)

**Screenshot 2 - SPF Record:**
- **Step 19** from LAB_STEPS.txt: "Verify SPF Record"
  - Command: `dig @172.20.0.10 example.com TXT`
  - Shows: "v=spf1 ip4:172.20.0.20 -all"
  - Illustrates SPF check that would FAIL for unauthorized IPs
  - Place in the SPF Check section (around line 638)

**Screenshot 3 - DMARC Policy:**
- **Step 30** from LAB_STEPS.txt: "Verify DMARC Record"
  - Command: `dig @172.20.0.10 _dmarc.example.com TXT`
  - Shows: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
  - Illustrates policy enforcement
  - Place in the DMARC Check section (around line 650)

### Attack 2: DNS Spoofing / Cache Poisoning

#### Attack Execution - INSECURE Setup (NO DNSSEC)

**Screenshot 1 - Fake Mail Server Running:**
- **Step 13** from LAB_STEPS.txt: "Start Fake Mail Server"
  - Command: `python3 /root/fake_mail_server.py`
  - Shows: "[*] Fake SMTP server listening on 0.0.0.0:25"
  - Place after line 807 in report1.tex (after Fake Mail Server code)

**Screenshot 2 - DNS Spoofing Attack Active:**
- **Step 14** from LAB_STEPS.txt: "Start DNS Spoofing Attack"
  - Command: `python3 /root/dns_spoof.py`
  - Shows: "[*] Starting DNS Spoofer..."
  - Place after line 768 in report1.tex (after DNS spoofer code)

**Screenshot 3 - Email Intercepted:**
- **Step 15** from LAB_STEPS.txt: "Send Email During Attack"
  - Shows: Client connects to 172.20.0.40 (fake server)
  - Email intercepted: "This should be intercepted"
  - Place after line 859 in report1.tex (after SMTP Connection to Fake Server)

**Screenshot 4 - Attacker Logs:**
- Same as Step 15 but from attacker's perspective
  - Shows: "[+] EMAIL INTERCEPTED from ('172.20.0.30', 45678)"
  - Full email content exposed to attacker
  - Place after line 877 in report1.tex (after Attacker's Fake Server Logs)

#### Attack Execution - SECURE Setup (WITH DNSSEC)

**Screenshot 1 - DNSSEC Zone Signing:**
- **Step 37** from LAB_STEPS.txt: "Sign the Zone"
  - Shows: Zone signing output
  - "db.example.com.signed created"
  - "19 RRSIG records created"
  - Place after line 920 in report1.tex (after DNSSEC Zone Signing section)

**Screenshot 2 - DNSSEC Validation:**
- **Step 40** from LAB_STEPS.txt: "Verify DNSSEC"
  - Command: `dig @172.20.0.10 example.com +dnssec`
  - Shows: RRSIG records, DNSKEY records, "ad" flag (authenticated data)
  - Place after line 949 in report1.tex (after Client DNS Query with DNSSEC Validation)

**Screenshot 3 - DNS Server Logs (Validation Success):**
- Can create this by running dig with +dnssec and checking DNS logs
  - Shows: "validating mail.example.com/A: verify rdataset: success"
  - "marking as secure"
  - Place after line 1001 in report1.tex (after DNS Server Logs section)

**Screenshot 4 - Connection to Legitimate Server:**
- Can use Step 15 output but with DNS resolving correctly
  - Shows: Client connects to 172.20.0.20 (legitimate server)
  - Email delivered securely
  - Place after line 989 in report1.tex (after SMTP Connection to Legitimate Server)

---

## Additional Supporting Screenshots

### For DNS Traffic Comparison Table (line 177)
**Use:**
- **Step 4** (without DNSSEC) + **Step 40** (with DNSSEC) side-by-side
- Annotate to highlight the size difference: 51 bytes vs 847 bytes

### For SMTP Traffic Comparison Table (line 337)
**Use:**
- **Step 8** (without DKIM) + **Step 26** (with DKIM) side-by-side
- Annotate to highlight header size: 350 bytes vs 862 bytes

### For Mail Server Log Comparison Table (line 457)
**Use:**
- **Step 9** (no security) + **Step 27** (with DKIM) side-by-side
- Annotate to highlight: 6 log entries vs 8 log entries

### For Email Forgery Attack Comparison Table (line 714)
**Use:**
- **Step 10** (forgery succeeds) + **Step 31** (forgery detected) side-by-side
- Annotate the differences: "Accepted" vs "Quarantined/Flagged"

### For DNS Spoofing Attack Comparison Table (line 1037)
**Use:**
- **Step 15** (attack succeeds) + **Step 40** (attack prevented) side-by-side
- Annotate: "Connected to 172.20.0.40 (fake)" vs "Connected to 172.20.0.20 (legitimate)"

---

## Summary of Screenshots Needed for report1.tex

### Priority 1 (Essential):
1. **Step 4** - DNS without DNSSEC
2. **Step 40** - DNS with DNSSEC
3. **Step 8** - Email without DKIM
4. **Step 26** - Email with DKIM
5. **Step 10** - Email forgery succeeds
6. **Step 15** - DNS spoofing succeeds
7. **Step 37** - DNSSEC zone signing

### Priority 2 (Highly Recommended):
8. **Step 9** - Logs without security
9. **Step 27** - Logs with DKIM
10. **Step 19** - SPF record
11. **Step 30** - DMARC record
12. **Step 31** - Retry forgery with security
13. **Step 13** - Fake mail server
14. **Step 14** - DNS spoofer

### Priority 3 (Supplementary):
15. **Step 3** - DKIM key generation
16. **Step 34** - DNS traffic capture
17. **Step 35** - SMTP traffic capture
18. **Step 11** - Forged email delivered
19. **Step 12** - Forged email headers

---

## LaTeX Insert Points Summary

| report1.tex Location | LAB_STEPS Screenshot | Purpose |
|---------------------|---------------------|---------|
| After line 91 | Step 4 | DNS query without DNSSEC |
| After line 145 | Step 40 | DNS query with DNSSEC |
| After line 177 | Steps 4+40 | DNS traffic comparison table |
| After line 228 | Step 8 | SMTP without DKIM |
| After line 287 | Step 26 | SMTP with DKIM |
| After line 337 | Steps 8+26 | SMTP traffic comparison table |
| After line 383 | Step 9 | Logs without security |
| After line 432 | Step 27 | Logs with DKIM |
| After line 457 | Steps 9+27 | Log comparison table |
| After line 502 | Step 10 | Email forgery - attack succeeds |
| After line 520 | Step 11 | Forged email delivered |
| After line 539 | Step 12 | Forged email headers |
| After line 623 | Step 31 | Email with DKIM (retry forgery) |
| After line 638 | Step 19 | SPF record verification |
| After line 650 | Step 30 | DMARC record verification |
| After line 714 | Steps 10+31 | Email forgery comparison table |
| After line 768 | Step 14 | DNS spoofer running |
| After line 807 | Step 13 | Fake mail server running |
| After line 859 | Step 15 | Email intercepted (attack) |
| After line 877 | Step 15 | Attacker logs (email captured) |
| After line 920 | Step 37 | DNSSEC zone signing |
| After line 949 | Step 40 | DNSSEC validation query |
| After line 989 | Modified Step 15 | Connection to legitimate server |
| After line 1001 | DNS logs | DNSSEC validation logs |
| After line 1037 | Steps 15+40 | DNS spoofing comparison table |

---

## How to Insert Screenshots in LaTeX

For each screenshot location, add this code in report1.tex:

```latex
\begin{figure}[H]
    \centering
    \includegraphics[width=\textwidth]{screenshots/step_XX_description.png}
    \caption{Description of what the screenshot shows}
    \label{fig:stepXX}
\end{figure}
```

**Example for Step 4 (after line 91):**
```latex
\begin{figure}[H]
    \centering
    \includegraphics[width=0.9\textwidth]{screenshots/step04_dns_without_dnssec.png}
    \caption{DNS A record query without DNSSEC - Response size: 51 bytes}
    \label{fig:dns_no_dnssec}
\end{figure}
```

**Example for Step 40 (after line 145):**
```latex
\begin{figure}[H]
    \centering
    \includegraphics[width=0.9\textwidth]{screenshots/step40_dns_with_dnssec.png}
    \caption{DNS query with DNSSEC validation - Response size: 847 bytes with RRSIG, DNSKEY, and NSEC3 records}
    \label{fig:dns_with_dnssec}
\end{figure}
```

---

## Notes for Taking Screenshots

1. **Use consistent terminal dimensions** - Set all terminals to the same size for uniform screenshots

2. **Highlight important sections** - Consider using colored boxes or arrows to point out:
   - DKIM-Signature headers
   - RRSIG records in DNS responses
   - "250 Ok" vs "FAIL" messages
   - File size differences (2.9KB vs 13KB)

3. **Clean up output** - Remove unnecessary terminal clutter, focus on relevant command output

4. **Side-by-side comparisons** - For comparison tables, create composite images showing before/after

5. **Annotation suggestions**:
   - Step 4: Circle "MSG SIZE rcvd: 51"
   - Step 40: Circle "MSG SIZE rcvd: 847" and "ad" flag
   - Step 10: Circle "250 2.0.0 Ok: queued"
   - Step 15: Circle "Connected to mail.example.com [Actually 172.20.0.40]"
   - Step 37: Circle "db.example.com.signed - 13KB"

---

## Final Checklist

Before submitting report1.tex with screenshots:

- [ ] All Priority 1 screenshots included (7 screenshots)
- [ ] All Priority 2 screenshots included (7 screenshots)
- [ ] Comparison tables have side-by-side screenshots
- [ ] Each screenshot has descriptive caption
- [ ] File paths in \includegraphics match actual file locations
- [ ] All screenshots are readable (font size, resolution)
- [ ] Important details are highlighted/annotated
- [ ] Screenshot numbers/labels match LAB_STEPS references
- [ ] PDF compiles without errors
- [ ] All figures referenced in text with \ref{fig:label}

---

End of Screenshot Mapping Document
