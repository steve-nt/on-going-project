# Lab 3: Authentication Security - From Password Storage to FIDO2/WebAuthn

## Project Overview

This project implements a comprehensive authentication security system demonstrating various password hashing schemes, multi-factor authentication (MFA) methods, and security attack/defense mechanisms. The project showcases the evolution from basic password storage to modern FIDO2/WebAuthn authentication, along with practical demonstrations of common security vulnerabilities and their mitigations.

## Authors

- Person A: Password hashing implementation (SHA-256, SHA-3, bcrypt, Argon2)
- Person B: MFA implementation (TOTP, HOTP, FIDO2/WebAuthn) and attack demonstrations

## Table of Contents

1. [Quick Start](#quick-start)
2. [Project Structure](#project-structure)
3. [Features](#features)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Components](#components)
7. [API Endpoints](#api-endpoints)
8. [Security Demonstrations](#security-demonstrations)
9. [Artifacts](#artifacts)
10. [Dependencies](#dependencies)
11. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Automated Launcher (Recommended)

The easiest way to run this project:

```bash
cd "Deliverables/Code"
python3 launcher.py
```

The launcher provides:
- ✅ Automatic dependency checking and installation
- ✅ Interactive menu with guided execution
- ✅ Process management for background servers
- ✅ Step-by-step demonstrations
- ✅ Automatic cleanup on exit

See [QUICKSTART.md](QUICKSTART.md) for detailed launcher usage.

### Manual Quick Start

If you prefer manual execution:

```bash
# 1. Install dependencies
pip3 install --user flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests

# 2. Start the authentication server
cd "Core Application Files"
python3 integrated_app.py

# 3. In another terminal, run demonstrations
cd "../MFA Implementation"
python3 mfa_totp.py
```

---

## Project Structure

```
Deliverables/
├── Code/
│   ├── launcher.py                    # Automated project launcher
│   ├── QUICKSTART.md                  # Quick reference guide
│   ├── README.md                      # This file
│   │
│   ├── Core Application Files/
│   │   ├── app.py                     # Basic authentication API
│   │   ├── integrated_app.py          # Full API with MFA support
│   │   └── users.db                   # SQLite database
│   │
│   ├── MFA Implementation/
│   │   ├── mfa_totp.py               # TOTP implementation
│   │   ├── mfa_hotp.py               # HOTP implementation
│   │   ├── fido2_webauthn.py         # WebAuthn/FIDO2 implementation
│   │   └── mitm_proxy.py             # MITM relay demonstration
│   │
│   └── Attack & Testing Scripts/
│       ├── dictionary_attack.py       # Password cracking
│       ├── crack_passwords.py         # Brute-force cracking
│       ├── timing_attack.py           # Timing attack demo
│       ├── mitm_proxy.py             # MITM relay proxy
│       └── testing.py                 # API testing utilities
│
├── Artifacts/
│   ├── qr_*.png                       # TOTP QR codes
│   ├── *_stats.json                   # MFA statistics
│   ├── webauthn_logs.json            # WebAuthn traces
│   ├── mitm_logs.json                # MITM attack logs
│   ├── timing_attack_results.txt     # Timing measurements
│   ├── dictionary_attack_report.txt  # Cracking results
│   └── *.jpg                         # Screenshots of demonstrations
│
├── Report/
│   └── Lab3_Report.tex               # Comprehensive report (LaTeX)
│
└── Lab3.txt                          # Lab requirements
```

---

## Features

### Password Hashing Implementations

- **SHA-256**: Iterative hashing with salt and pepper (100 rounds default)
- **SHA-3**: Modern SHA-3-256 with salt and pepper (100 rounds)
- **bcrypt**: Industry-standard with configurable work factor (cost=8)
- **Argon2**: Memory-hard hashing resistant to GPU attacks (time_cost=1, memory_cost=8192)

All implementations use:
- Per-user random salts (32 bytes)
- System-wide pepper for additional security
- Secure random generation (`secrets` module)

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)
- RFC 6238 compliant implementation
- 30-second time windows
- Configurable time drift tolerance (±0, ±1 windows)
- QR code generation for authenticator apps
- Statistics tracking (success/failure rates)

#### HOTP (HMAC-based One-Time Password)
- RFC 4226 compliant implementation
- Counter-based OTP generation
- Counter desynchronization demonstration
- Look-ahead window for counter recovery
- Statistics and event logging

#### FIDO2/WebAuthn
- Public key cryptography-based authentication
- Origin/RP-ID binding for phishing protection
- Browser-native credentials.create/get() flows
- Credential storage and management
- MITM attack protection demonstration

### Security Features

- **HMAC Integrity**: Response tampering protection
- **Constant-time Comparison**: Timing attack mitigation (`hmac.compare_digest()`)
- **Salt & Pepper**: Defense against rainbow table attacks
- **Secure Random**: Cryptographically secure random generation
- **Input Validation**: SQL injection and input sanitization

### Attack Demonstrations

#### 1. Password Cracking
- Dictionary attacks on common passwords
- Brute-force attacks with configurable length
- Performance comparison across hash algorithms
- Time-to-crack measurements

#### 2. Timing Attacks
- Naive string comparison demonstration
- Constant-time comparison using `hmac.compare_digest()`
- Micro-benchmark measurements showing timing differences
- Statistical analysis of timing leakage

#### 3. MITM Relay Attacks
- Local proxy capturing credentials and OTP
- Real-time relay to legitimate server
- Latency measurements
- Success rate tracking
- Demonstration of TOTP vulnerability vs WebAuthn protection

---

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- SQLite3 (usually included with Python)

### Automatic Installation

Use the launcher for automatic dependency installation:

```bash
python3 launcher.py
# Select option to install missing packages when prompted
```

### Manual Installation

```bash
# Install all required packages
pip3 install --user flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests

# Or install from requirements file (if provided)
pip3 install --user -r requirements.txt
```

### Verify Installation

```bash
python3 -c "import flask, bcrypt, argon2, pyotp, qrcode, fido2, requests; print('All dependencies installed!')"
```

---

## Usage

### Option 1: Automated Launcher (Recommended)

```bash
cd "Deliverables/Code"
python3 launcher.py
```

**Menu Options:**
1. **Quick Demo** - Automated full demonstration
2. **Step-by-Step Tour** - Interactive walkthrough with descriptions
3. **Individual Components** - Run specific parts on demand
4. **Tests & Attacks** - Run all security demonstrations
5. **System Status** - Check installation and processes

### Option 2: Manual Execution

#### Start Core Authentication Server

```bash
cd "Core Application Files"
python3 integrated_app.py
# Server runs on http://localhost:5000
```

#### Run MFA Demonstrations

```bash
cd "MFA Implementation"

# TOTP Demo
python3 mfa_totp.py

# HOTP Demo
python3 mfa_hotp.py

# WebAuthn Demo
python3 fido2_webauthn.py
```

#### Run Attack Demonstrations

```bash
cd "Attack & Testing Scripts"

# Timing Attack
python3 timing_attack.py

# Password Cracking
python3 dictionary_attack.py
```

#### MITM Relay Attack Demonstration

This requires multiple terminals:

**Terminal 1 - Real Server:**
```bash
cd "Core Application Files"
python3 integrated_app.py
# Runs on port 5000
```

**Terminal 2 - MITM Proxy:**
```bash
cd "Attack & Testing Scripts"
python3 mitm_proxy.py
# Runs on port 8080
```

**Terminal 3 - Interactive Demo:**
```bash
cd "MFA Implementation"
python3 fido2_webauthn.py relay-demo
# Demonstrates TOTP relay success and WebAuthn protection
```

---

## Components

### 1. Core Authentication API

**File:** `Core Application Files/integrated_app.py`

Flask REST API providing:
- User registration with multiple hash algorithms
- Password authentication
- MFA enrollment (TOTP/HOTP)
- MFA verification
- HMAC-protected responses
- Statistics and logging

### 2. TOTP Implementation

**File:** `MFA Implementation/mfa_totp.py`

Features:
- Secret generation
- QR code creation for authenticator apps
- Time-based token verification
- Configurable time windows (±0, ±1 intervals)
- Success/failure statistics
- Time window usage tracking

### 3. HOTP Implementation

**File:** `MFA Implementation/mfa_hotp.py`

Features:
- Counter-based OTP generation
- Counter synchronization
- Desynchronization demonstration
- Look-ahead window for recovery
- Event logging

### 4. WebAuthn/FIDO2 Implementation

**File:** `MFA Implementation/fido2_webauthn.py`

Features:
- Registration flow (credentials.create)
- Authentication flow (credentials.get)
- Origin/RP-ID binding
- Credential storage
- Interactive relay attack demonstration
- Origin mismatch detection

### 5. Password Cracking Suite

**File:** `Attack & Testing Scripts/dictionary_attack.py`

Features:
- Dictionary attack with common passwords
- Brute-force attack with character sets
- Multi-algorithm support
- Performance metrics
- Time-to-crack analysis
- Detailed reporting

### 6. Timing Attack Demonstration

**File:** `Attack & Testing Scripts/timing_attack.py`

Demonstrates:
- Naive string comparison (vulnerable)
- Constant-time comparison (secure)
- Statistical timing measurements
- Micro-benchmarks
- Results exported to file

### 7. MITM Relay Proxy

**Files:** 
- `Attack & Testing Scripts/mitm_proxy.py`
- `MFA Implementation/mitm_proxy.py`

Features:
- Intercepts HTTP requests
- Captures credentials and OTP
- Forwards to real server
- Measures relay latency
- Logs all activities
- Demonstrates OTP vulnerability

---

## API Endpoints

### Base URL
```
http://localhost:5000
```

### Endpoints

#### POST /register
Register a new user.

**Request:**
```json
{
  "username": "alice",
  "password": "SecurePass123!",
  "hash_type": "bcrypt"
}
```

**Hash Types:** `sha256`, `sha3`, `bcrypt`, `argon2`

**Response:**
```json
{
  "status": "success",
  "username": "alice",
  "hash_type": "bcrypt",
  "mac": "hmac_signature"
}
```

#### POST /login
Authenticate a user.

**Request:**
```json
{
  "username": "alice",
  "password": "SecurePass123!"
}
```

**Response (no MFA):**
```json
{
  "status": "success",
  "message": "Login successful",
  "username": "alice",
  "mac": "hmac_signature"
}
```

**Response (MFA required):**
```json
{
  "status": "mfa_required",
  "mfa_type": "totp",
  "session_token": "token_here",
  "mac": "hmac_signature"
}
```

#### POST /mfa/enroll/totp
Enroll user for TOTP.

**Request:**
```json
{
  "username": "alice"
}
```

**Response:**
```json
{
  "status": "success",
  "secret": "BASE32SECRET",
  "qr_code": "data:image/png;base64,...",
  "mac": "hmac_signature"
}
```

#### POST /mfa/verify
Verify MFA token.

**Request:**
```json
{
  "username": "alice",
  "token": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "TOTP verified",
  "mac": "hmac_signature"
}
```

#### GET /mfa/stats
Get MFA statistics.

**Response:**
```json
{
  "total_attempts": 100,
  "successful": 95,
  "failed": 5,
  "success_rate": "95.00%",
  "mac": "hmac_signature"
}
```

---

## Security Demonstrations

### 1. Password Strength Comparison

Run cracking demonstrations to see relative strength:

```bash
cd "Attack & Testing Scripts"
python3 dictionary_attack.py
```

**Observed Results:**
- SHA-256 (100 rounds): Fast cracking (~11,000 attempts/sec)
- bcrypt (cost 8): Slower cracking (~10 attempts/sec)
- Argon2: Slowest cracking (memory-hard, GPU-resistant)

### 2. Timing Attack Vulnerability

```bash
cd "Attack & Testing Scripts"
python3 timing_attack.py
```

Demonstrates:
- Early termination in naive comparison leaks timing information
- `hmac.compare_digest()` provides constant-time comparison
- Statistical measurements show timing differences

### 3. TOTP Relay Success vs WebAuthn Protection

```bash
# Method 1: Automated demo
cd "MFA Implementation"
python3 fido2_webauthn.py relay-demo

# Method 2: Manual testing with real proxy
# Terminal 1:
cd "Core Application Files"
python3 integrated_app.py

# Terminal 2:
cd "Attack & Testing Scripts"
python3 mitm_proxy.py

# Terminal 3:
cd "MFA Implementation"
python3 fido2_webauthn.py relay-demo
```

**Key Findings:**
- **TOTP**: Vulnerable to relay attacks (OTP is just a number)
- **WebAuthn**: Protected by origin binding (cryptographic proof of domain)

### 4. Salt & Pepper Analysis

Same password with different salts produces different hashes, preventing:
- Rainbow table attacks
- Hash correlation across users
- Pre-computed attack tables

System pepper adds additional layer requiring:
- Knowledge of pepper value
- Access to application code

---

## Artifacts

All generated artifacts are stored in `../Artifacts/`:

### MFA Artifacts
- `qr_*.png` - QR codes for TOTP enrollment
- `totp_stats.json` - TOTP verification statistics
- `hotp_stats.json` - HOTP verification statistics
- `webauthn_logs.json` - WebAuthn registration and authentication logs

### Attack Results
- `dictionary_attack_report.txt` - Password cracking analysis
- `timing_attack_results.txt` - Timing measurements
- `mitm_logs.json` - MITM relay attack logs

### Database
- `artifacts_users.db` - SQLite database with test users

### Screenshots
- Various `.jpg` files demonstrating features and attacks

---

## Dependencies

### Required Python Packages

| Package | Version | Purpose |
|---------|---------|---------|
| flask | Latest | Web framework for REST API |
| bcrypt | Latest | bcrypt password hashing |
| argon2-cffi | Latest | Argon2 password hashing |
| pyotp | Latest | TOTP/HOTP implementation |
| qrcode | Latest | QR code generation |
| pillow | Latest | Image processing for QR codes |
| fido2 | 2.0+ | WebAuthn/FIDO2 support |
| requests | Latest | HTTP client for testing |

### Standard Library Dependencies
- sqlite3 (database)
- hashlib (SHA-256, SHA-3)
- hmac (integrity checks)
- secrets (secure random)
- time, datetime (timing)
- json (data serialization)

---

## Troubleshooting

### Port Already in Use

If you see "Address already in use" error:

```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use a different port
FLASK_RUN_PORT=5001 python3 integrated_app.py
```

### Import Errors

If you get import errors:

```bash
# Reinstall all dependencies
pip3 install --user --force-reinstall flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests

# Check Python version
python3 --version  # Should be 3.7+
```

### Database Locked

If you see "database is locked":

```bash
# Close all connections and restart
rm users.db
python3 integrated_app.py
```

### MITM Demo Not Working

Ensure both servers are running:
1. Real server on port 5000
2. MITM proxy on port 8080

Check with:
```bash
curl http://localhost:5000
curl http://localhost:8080/proxy/stats
```

### QR Codes Not Generating

Install Pillow if missing:
```bash
pip3 install --user pillow
```

---

## Testing

### Manual API Testing

```bash
# Register user
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test", "password":"pass123", "hash_type":"bcrypt"}'

# Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test", "password":"pass123"}'

# Enroll TOTP
curl -X POST http://localhost:5000/mfa/enroll/totp \
  -H "Content-Type: application/json" \
  -d '{"username":"test"}'
```

### Automated Testing

```bash
cd "Attack & Testing Scripts"
python3 testing.py
```

---

## Performance Notes

### Hash Algorithm Benchmarks (Approximate)

Based on dictionary attack results:

| Algorithm | Hashes/sec | Notes |
|-----------|------------|-------|
| SHA-256 (100 rounds) | ~11,000 | Fast but vulnerable |
| SHA-3 (100 rounds) | ~10,000 | Similar to SHA-256 |
| bcrypt (cost 8) | ~10 | Good balance |
| Argon2 (default) | ~5 | Best security |

**Recommendation:** Use Argon2 for new systems, bcrypt for compatibility.

---

## Security Recommendations

### For Developers

1. **Use Argon2 or bcrypt** - Avoid fast hashes like SHA-256 alone
2. **Implement MFA** - Preferably WebAuthn/FIDO2
3. **Use constant-time comparison** - Prevent timing attacks
4. **Generate secure random** - Use `secrets` module
5. **Apply salt and pepper** - Unique salts per user, system pepper
6. **Use HMAC for integrity** - Protect API responses
7. **Validate all inputs** - Prevent injection attacks

### For Users

1. **Enable MFA** - Use WebAuthn when available
2. **Use unique passwords** - Password managers help
3. **Verify URLs** - Check domain before entering credentials
4. **Use hardware keys** - YubiKey, TouchID for WebAuthn
5. **Watch for phishing** - TOTP can be relayed, WebAuthn cannot

### Deployment Considerations

- **HTTPS only** - Required for WebAuthn
- **Rate limiting** - Prevent brute-force attacks
- **Account lockout** - After failed attempts
- **Logging and monitoring** - Detect attack patterns
- **Regular updates** - Keep dependencies current

---

## Known Limitations

1. **Local-only MITM demo** - For educational purposes only
2. **Simplified WebAuthn** - Production needs more error handling
3. **No rate limiting** - Should be added for production
4. **SQLite database** - Use PostgreSQL/MySQL for production
5. **No account lockout** - Should implement after N failed attempts
6. **Hardcoded secrets** - Use environment variables in production

---

## Future Enhancements

- [ ] Add HOTP to integrated_app.py endpoints
- [ ] Implement rate limiting and account lockout
- [ ] Add WebAuthn registration/authentication endpoints to API
- [ ] Support multiple authenticators per user
- [ ] Add password strength requirements
- [ ] Implement session management
- [ ] Add audit logging
- [ ] Support for hardware security keys (YubiKey)
- [ ] Add biometric authentication support
- [ ] Implement password reset flows

---

## References

### RFCs and Standards
- RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
- RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm
- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
- W3C WebAuthn Specification
- FIDO2/CTAP2 Specifications

### Libraries Used
- [Flask Documentation](https://flask.palletsprojects.com/)
- [pyotp Documentation](https://pyauth.github.io/pyotp/)
- [python-fido2 Documentation](https://github.com/Yubico/python-fido2)
- [Argon2 Documentation](https://argon2-cffi.readthedocs.io/)

### Learning Resources
- OWASP Password Storage Cheat Sheet
- NIST Special Publication 800-63B (Digital Identity Guidelines)
- OWASP Authentication Cheat Sheet

---

## License

This project is for educational purposes as part of Lab 3: Authentication Security.

---

## Contact

For questions or issues related to this project:
- Check the troubleshooting section above
- Review the QUICKSTART.md guide
- Consult the comprehensive report in `../Report/Lab3_Report.tex`

---

## Acknowledgments

This project demonstrates authentication security concepts from basic password hashing to modern FIDO2/WebAuthn. It is designed for educational purposes to understand both attack vectors and defense mechanisms in authentication systems.

**Last Updated:** 2025-10-19
