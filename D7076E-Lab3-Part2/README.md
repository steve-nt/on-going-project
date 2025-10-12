# Lab 3 - Person B Implementation
## Secure Authentication & Attack Demonstrations

**Author:** Person B
**Course:** D7076E - Security in Computer Systems
**Focus:** MFA, FIDO2/WebAuthn, Attack Scripts, and Security Mitigations

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Project Structure](#project-structure)
4. [Running the Demonstrations](#running-the-demonstrations)
5. [Implementation Details](#implementation-details)
6. [Expected Outputs](#expected-outputs)
7. [Troubleshooting](#troubleshooting)
8. [Security Notes](#security-notes)

---

## Overview

This project implements **Person B's tasks** from Lab 3, focusing on:

### Multi-Factor Authentication (MFA)
- **TOTP (Time-based One-Time Password)**: QR code enrollment, verification, time window configuration
- **HOTP (HMAC-based One-Time Password)**: Counter-based authentication, desync demonstration
- **Statistical logging**: Success/failure rates, timing data

### FIDO2 / WebAuthn
- Server-side implementation using `python-fido2`
- Client-side browser flows (HTML/JavaScript demo)
- Demonstration of MITM resistance (origin binding)

### Attack Scripts & Demonstrations
- **Password Cracking**: Dictionary and brute-force attacks
- **Timing Attacks**: Naive vs constant-time comparisons
- **MITM Relay**: Proxy demonstrating OTP relay vs WebAuthn protection

### Key Learning Objectives
- Understanding MFA mechanisms and their vulnerabilities
- Implementing cryptographically secure authentication
- Demonstrating real-world attack vectors
- Learning proper security mitigations

---

## Installation

### Prerequisites

- **Python 3.8+** (recommended: Python 3.10+)
- **pip** (Python package manager)
- **Modern web browser** (Chrome, Firefox, Edge, or Safari) for WebAuthn demos

### Step 1: Clone/Navigate to Project Directory

```bash
cd D7076E-Lab3-Part2
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip

# Install required packages
pip install pyotp qrcode pillow bcrypt argon2-cffi fido2 matplotlib
```

### Dependency List

| Package | Version | Purpose |
|---------|---------|---------|
| `pyotp` | ≥2.8.0 | TOTP/HOTP implementation |
| `qrcode` | ≥7.4.0 | QR code generation |
| `pillow` | ≥10.0.0 | Image processing for QR codes |
| `bcrypt` | ≥4.0.0 | Password hashing |
| `argon2-cffi` | ≥23.0.0 | Argon2 password hashing |
| `fido2` | ≥1.1.0 | FIDO2/WebAuthn implementation |
| `matplotlib` | ≥3.5.0 | Visualization for timing attacks |

### Step 4: Verify Installation

```bash
python3 -c "import pyotp, qrcode, bcrypt, argon2, fido2; print('✓ All dependencies installed successfully!')"
```

---

## Project Structure

```
D7076E-Lab3-Part2/
├── Lab3.txt                     # Original lab requirements
├── README.md                    # This file - run instructions
├── report.txt                   # Theory and experiment report
├── sources.txt                  # References and sources
│
├── mfa_implementation.py        # TOTP & HOTP implementation
├── fido2_webauthn.py           # WebAuthn server & client demo
├── password_cracking.py        # Dictionary & brute-force attacks
├── timing_attack.py            # Timing side-channel demonstration
├── mitm_relay_proxy.py         # MITM relay attack demo
│
└── Output Files (generated):
    ├── totp_qr_*.png           # TOTP QR codes
    ├── webauthn_demo.html      # WebAuthn browser demo
    ├── mfa_stats.json          # MFA statistics
    ├── webauthn_credentials.json
    ├── cracking_results.json
    ├── mitm_relay_stats.json
    └── timing_attack_visualization.png
```

---

## Running the Demonstrations

### 1. MFA Implementation (TOTP & HOTP)

#### Run the complete MFA demo:

```bash
python3 mfa_implementation.py
```

**What it does:**
- Enrolls users for TOTP and HOTP
- Generates QR codes for TOTP (scan with Google Authenticator/Authy)
- Demonstrates token verification
- Shows time window configuration for TOTP
- Demonstrates counter desynchronization for HOTP
- Logs statistics to `mfa_stats.json`

**Expected Output:**
```
====================================================================
MULTI-FACTOR AUTHENTICATION (MFA) DEMONSTRATION
====================================================================

PART 1: TOTP (Time-based One-Time Password)
--------------------------------------------------------------------
[TOTP] Generated secret for user: alice
[TOTP] QR code saved to totp_qr_alice.png
...
```

**QR Code Usage:**
1. Open Google Authenticator or Authy on your phone
2. Scan the generated `totp_qr_alice.png`
3. App will show 6-digit codes that change every 30 seconds

---

### 2. FIDO2 / WebAuthn Implementation

#### Run the WebAuthn server demo:

```bash
python3 fido2_webauthn.py
```

**What it does:**
- Demonstrates WebAuthn server-side operations
- Generates `webauthn_demo.html` for browser testing
- Shows registration and authentication flows
- Explains origin binding and MITM resistance

#### Interactive Browser Demo:

```bash
# Start a local web server
python3 -m http.server 8000

# Open browser to:
# http://localhost:8000/webauthn_demo.html
```

**Browser Requirements:**
- Must use HTTPS or localhost (WebAuthn security requirement)
- Browser must support WebAuthn API (Chrome, Firefox, Edge, Safari)
- May need a security key (YubiKey) or platform authenticator (Touch ID, Windows Hello)

**Expected Output:**
```
====================================================================
FIDO2 / WEBAUTHN DEMONSTRATION
====================================================================

SERVER-SIDE OPERATIONS
--------------------------------------------------------------------
[WebAuthn] Initialized Relying Party: Lab3 Secure App (localhost)
...
```

---

### 3. Password Cracking Scripts

#### Run password cracking demonstration:

```bash
python3 password_cracking.py
```

**What it does:**
- Creates test passwords with different hash algorithms
- Performs dictionary attacks on SHA-256 and bcrypt
- Performs brute-force attacks (limited length for demo)
- Compares cracking times across algorithms
- Generates `cracking_results.json`

**Expected Output:**
```
====================================================================
PASSWORD CRACKING DEMONSTRATION
====================================================================

SETUP: Creating test password hashes
--------------------------------------------------------------------
WEAK: 'password'
  SHA-256: 5e884898da28047151d0e56f8dc629...

PART 1: DICTIONARY ATTACK
--------------------------------------------------------------------
[Dictionary] Starting SHA-256 attack...
[Dictionary] Testing 48 passwords...
[Dictionary] ✓ PASSWORD CRACKED!
[Dictionary] Password: password
[Dictionary] Attempts: 1
[Dictionary] Time: 0.0023 seconds
...
```

**⚠️ Note:** Brute-force demonstrations are limited to short passwords (4-6 characters) for reasonable runtime. Real attacks with GPUs are much faster.

---

### 4. Timing Attack Demonstration

#### Run timing attack demo:

```bash
python3 timing_attack.py
```

**What it does:**
- Demonstrates timing side-channel vulnerabilities
- Shows naive vs constant-time string comparison
- Simulates timing attack to extract secret token
- Demonstrates hmac.compare_digest() protection
- Generates visualization: `timing_attack_visualization.png`

**Expected Output:**
```
====================================================================
TIMING ATTACK DEMONSTRATION
====================================================================

TIMING DIFFERENCE DEMONSTRATION
--------------------------------------------------------------------
Secret token: abc123...

NAIVE COMPARISON (Vulnerable)
--------------------------------------------------------------------
No match              :   245.32 ns
1 char match          :   267.45 ns
4 chars match         :   312.67 ns
8 chars match         :   378.89 ns
...
```

**⚠️ Warning:** The timing attack simulation takes several minutes due to statistical measurements (1000+ iterations per character).

---

### 5. MITM Relay Proxy

#### Run MITM demonstration (text-based):

```bash
python3 mitm_relay_proxy.py
```

**What it does:**
- Explains MITM relay attacks
- Compares OTP vs WebAuthn security
- Shows why WebAuthn origin binding prevents relay

**Expected Output:**
```
====================================================================
MITM RELAY ATTACK COMPARISON
====================================================================

SCENARIO 1: MITM RELAY WITH TOTP/HOTP (VULNERABLE)
--------------------------------------------------------------------
Attack Flow:
  1. Victim visits: http://evil-phishing-site.com
  ...
  6. ✗ ATTACK SUCCESSFUL!
     - Attacker gains access to victim's account
...
```

#### Run interactive MITM proxy server:

```bash
python3 mitm_relay_proxy.py server
```

Then open browser to: `http://localhost:9999`

**What it does:**
- Starts a phishing site on port 9999
- Captures credentials and relays to fake server
- Demonstrates successful OTP relay
- Demonstrates failed WebAuthn relay
- Logs statistics to `mitm_relay_stats.json`

**Test Credentials:**
- Username: `alice`
- Password: `password123`
- OTP: Check console output for current code

---

## Implementation Details

### MFA Implementation

**File:** `mfa_implementation.py`

**Key Classes:**
- `MFAStats`: Tracks authentication statistics
- `TOTPManager`: Manages TOTP enrollment and verification
- `HOTPManager`: Manages HOTP with counter resync

**Key Features:**
- Per-user secret generation
- QR code generation for authenticator apps
- Configurable time windows (TOTP)
- Look-ahead windows for desync recovery (HOTP)
- Comprehensive logging

**Code Highlights:**
```python
# TOTP with time window
totp.verify(token, valid_window=1)  # ±30 seconds

# HOTP with look-ahead
hotp.verify(token, look_ahead_window=3)  # Check next 3 counters
```

---

### FIDO2 / WebAuthn

**File:** `fido2_webauthn.py`

**Key Classes:**
- `WebAuthnManager`: Server-side Relying Party implementation
- Generates HTML client for browser testing

**Security Features:**
- Public key cryptography (asymmetric)
- Origin binding (prevents phishing/MITM)
- Challenge-response (prevents replay)
- Attestation support

**Origin Binding Example:**
```python
# Server verifies origin matches expected RP ID
if origin != expected_origin:
    return False, "Origin mismatch - MITM detected!"
```

---

### Password Cracking

**File:** `password_cracking.py`

**Key Classes:**
- `PasswordHasher`: Multi-algorithm hashing utility
- `DictionaryAttack`: Wordlist-based cracking
- `BruteForceAttack`: Exhaustive search
- `CrackingBenchmark`: Algorithm comparison

**Algorithms Tested:**
- SHA-256: ~100,000+ hashes/second
- SHA-3: ~80,000+ hashes/second
- bcrypt (rounds=12): ~10-50 hashes/second
- Argon2: ~5-20 hashes/second

**Key Finding:** Slow hashing algorithms (bcrypt, Argon2) dramatically increase cracking time.

---

### Timing Attacks

**File:** `timing_attack.py`

**Key Classes:**
- `TimingAttackDemo`: Demonstrates timing vulnerabilities

**Attack Process:**
1. Measure comparison time for each character guess
2. Character with longest time likely matches more positions
3. Extract secret character-by-character

**Mitigation:**
```python
# VULNERABLE
if input_token[i] != secret_token[i]:
    return False  # Early exit leaks timing!

# SECURE
return hmac.compare_digest(input_token, secret_token)
```

---

### MITM Relay

**File:** `mitm_relay_proxy.py`

**Key Classes:**
- `MITMProxyHandler`: HTTP proxy that captures and relays
- `FakeAuthServer`: Simulates target server
- `RelayStats`: Tracks attack success/failure

**Attack Scenarios:**

| Auth Method | Relay Success | Reason |
|-------------|---------------|--------|
| TOTP/HOTP | ✓ Vulnerable | Code is portable, no origin binding |
| WebAuthn | ✗ Protected | Signature includes origin, server rejects |

---

## Expected Outputs

### Generated Files

#### MFA Statistics (`mfa_stats.json`):
```json
{
  "totp": {
    "total_attempts": 5,
    "successful": 4,
    "failed": 1,
    "avg_verification_time": 0.000234
  },
  "hotp": {
    "total_attempts": 8,
    "successful": 7,
    "failed": 1,
    "desync_events": 2,
    "counter_adjustments": 2
  }
}
```

#### QR Codes:
- `totp_qr_alice.png`: Scannable QR code for TOTP enrollment
- Contains: `otpauth://totp/Lab3-SecureApp:alice?secret=...&issuer=Lab3-SecureApp`

#### WebAuthn Demo:
- `webauthn_demo.html`: Interactive browser-based demo
- `webauthn_credentials.json`: Stored credential metadata

#### Cracking Results (`cracking_results.json`):
- Time-to-crack for different algorithms
- Comparison data

#### MITM Statistics (`mitm_relay_stats.json`):
- OTP relay attempts and success rate
- WebAuthn relay attempts (should all fail)
- Timing data

#### Timing Attack Visualization:
- `timing_attack_visualization.png`: Shows timing differences per character position

---

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Error:** `ModuleNotFoundError: No module named 'pyotp'`

**Solution:**
```bash
pip install pyotp qrcode pillow bcrypt argon2-cffi fido2 matplotlib
```

---

#### 2. QR Code Generation Fails

**Error:** `ImportError: No module named 'PIL'`

**Solution:**
```bash
pip install pillow
```

---

#### 3. WebAuthn Not Working in Browser

**Error:** `WebAuthn is not supported in this browser`

**Solutions:**
- Use modern browser (Chrome 67+, Firefox 60+, Edge 18+, Safari 14+)
- Must be on HTTPS or localhost (http://localhost:8000 is OK)
- May need security key or platform authenticator

---

#### 4. MITM Proxy Port Already in Use

**Error:** `OSError: [Errno 98] Address already in use`

**Solution:**
```bash
# Find process using port
lsof -i :9999

# Kill process
kill -9 <PID>

# Or use different port
python3 mitm_relay_proxy.py server --port 10000
```

---

#### 5. Timing Attack Takes Too Long

**Note:** This is normal! Timing attacks require statistical measurements.

**To Speed Up (for testing):**
Edit `timing_attack.py` and reduce iterations:
```python
# Change from:
iterations=5000

# To:
iterations=100
```

**Warning:** Fewer iterations = less accurate results.

---

#### 6. Permission Denied on Linux

**Error:** `Permission denied: './mfa_implementation.py'`

**Solution:**
```bash
chmod +x *.py
python3 mfa_implementation.py
```

---

## Security Notes

### ⚠️ IMPORTANT DISCLAIMERS

1. **Educational Purpose Only**
   - All code is for learning and demonstration
   - Do NOT use attack scripts for malicious purposes
   - Legal and ethical use only

2. **Local Testing Only**
   - MITM proxy is for localhost demonstration
   - Never deploy on public networks
   - Could be illegal if used to intercept real traffic

3. **Production Considerations**
   - This code prioritizes education over production security
   - Real implementations need additional hardening:
     - Rate limiting
     - Account lockout policies
     - Secure key storage (HSM, key vaults)
     - Proper error handling
     - Logging and monitoring
     - Regular security audits

4. **Password Storage**
   - Never store plaintext passwords
   - Always use proper hashing (bcrypt, Argon2)
   - Use unique salts per user
   - Consider system-wide pepper
   - Implement password policies

5. **MFA Best Practices**
   - WebAuthn > TOTP > HOTP > SMS
   - Provide backup codes
   - Support multiple authenticators
   - Monitor for suspicious activity

---

## Testing Checklist

Use this checklist to verify all components work:

- [ ] MFA demo runs without errors
- [ ] QR codes are generated and scannable
- [ ] TOTP codes verify correctly
- [ ] HOTP counter desync is demonstrated
- [ ] WebAuthn server demo runs
- [ ] WebAuthn HTML file is created
- [ ] Password cracking finds weak passwords
- [ ] Algorithm comparison shows bcrypt is slower
- [ ] Timing attack demo shows timing differences
- [ ] Constant-time comparison prevents attack
- [ ] MITM text demo explains vulnerability
- [ ] MITM proxy server starts (optional)
- [ ] All JSON output files are created
- [ ] Timing visualization PNG is created

---

## Additional Resources

### For Users

- **Google Authenticator:** [iOS](https://apps.apple.com/app/google-authenticator/id388497605) | [Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
- **Authy:** [authy.com](https://authy.com/)
- **YubiKey:** [yubico.com](https://www.yubico.com/)

### For Developers

- **TOTP RFC:** [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
- **HOTP RFC:** [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)
- **WebAuthn Spec:** [w3.org/TR/webauthn](https://www.w3.org/TR/webauthn/)
- **FIDO2:** [fidoalliance.org](https://fidoalliance.org/)
- **OWASP Auth Guide:** [owasp.org](https://owasp.org/www-project-authentication-cheat-sheet/)

---

## Contact

For questions about this implementation:
- **Course:** D7076E - Security in Computer Systems
- **Lab:** Lab 3 - Person B Tasks
- **Implementation:** MFA, FIDO2, Attack Demonstrations

---

## License

This code is provided for educational purposes as part of Lab 3.
See course materials for usage guidelines.

---

**Last Updated:** 2025-10-12
**Version:** 1.0
**Author:** Person B
