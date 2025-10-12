# Lab 3: Secure Password Storage and Authentication

**Course:** D7076E Security
**Topic:** Password hashing, MFA, and authentication security

## Overview

This lab implements and demonstrates secure password storage, multi-factor authentication (MFA), and various security concepts including:

- Multiple password hashing algorithms (SHA-256, SHA-3, bcrypt, Argon2)
- Salt and pepper for password security
- HMAC-based integrity protection
- Multi-factor authentication (TOTP, HOTP, WebAuthn/FIDO2)
- Password cracking demonstrations
- Timing attack demonstrations and mitigations
- MITM relay attack demonstrations

## Project Structure

```
├── app.py                    # Main Flask API server
├── password_cracker.py       # Password cracking demonstrations
├── timing_attack_demo.py     # Timing attack demonstrations
├── mitm_relay.py            # MITM relay proxy demonstration
├── test_api.py              # API testing suite
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── LAB_REPORT.txt          # Comprehensive lab report
├── auth.db                 # SQLite database (created on first run)
└── *.png                   # Generated QR codes and plots
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

### Setup

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Lab

### 1. Start the Main API Server

```bash
python app.py
```

The API will be available at `http://localhost:5000`

### 2. Run the Test Suite

In a new terminal:

```bash
python test_api.py
```

This will run all automated tests including:
- User registration with different algorithms
- Login and password verification
- TOTP enrollment and verification
- HOTP enrollment and verification
- MFA logs retrieval
- Algorithm performance comparison
- Salt vs pepper comparison

### 3. Run Password Cracking Demonstrations

```bash
python password_cracker.py
```

This demonstrates:
- Benchmarking of hashing algorithms
- Salt vs pepper comparison
- Dictionary attacks
- Brute-force attacks
- Cracking time differences between algorithms

### 4. Run Timing Attack Demonstrations

```bash
python timing_attack_demo.py
```

This demonstrates:
- Timing leakage in vulnerable comparisons
- Constant-time comparison security
- Remote timing attack simulation
- Secure MAC comparison

### 5. Run MITM Relay Demonstration

Start the MITM proxy in a new terminal:

```bash
python mitm_relay.py
```

The proxy will be available at `http://localhost:5001`

Visit `http://localhost:5001/mitm/demo` for information about the demonstration.

## API Endpoints

### Authentication

- `POST /register` - Register a new user
  - Parameters: `username`, `password`, `algorithm`, `use_pepper`
  - Algorithms: `sha256`, `sha3`, `bcrypt`, `argon2`

- `POST /login` - Login with username and password
  - Parameters: `username`, `password`, `timing_vulnerable` (optional)

### MFA - TOTP

- `POST /mfa/totp/enroll` - Enroll in TOTP
  - Parameters: `username`
  - Returns: Secret and QR code

- `POST /mfa/totp/verify` - Verify TOTP code
  - Parameters: `username`, `code`, `window` (±0, ±1, etc.)

### MFA - HOTP

- `POST /mfa/hotp/enroll` - Enroll in HOTP
  - Parameters: `username`
  - Returns: Secret and QR code

- `POST /mfa/hotp/verify` - Verify HOTP code
  - Parameters: `username`, `code`, `look_ahead`

### MFA - WebAuthn

- `POST /mfa/webauthn/register/begin` - Begin WebAuthn registration
- `POST /mfa/webauthn/register/complete` - Complete WebAuthn registration
- `POST /mfa/webauthn/authenticate/begin` - Begin WebAuthn authentication
- `POST /mfa/webauthn/authenticate/complete` - Complete WebAuthn authentication

### Monitoring

- `GET /mfa/logs` - Get MFA authentication logs
  - Optional parameter: `username`

- `GET /status` - Check API status

## Usage Examples

### Register a user with Argon2

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secure_password",
    "algorithm": "argon2",
    "use_pepper": true
  }'
```

### Login

```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secure_password"
  }'
```

### Enroll in TOTP

```bash
curl -X POST http://localhost:5000/mfa/totp/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice"
  }'
```

The response will include a QR code file that can be scanned with an authenticator app.

### Verify TOTP

```bash
curl -X POST http://localhost:5000/mfa/totp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "code": "123456",
    "window": 1
  }'
```

## Security Features

### Password Hashing

1. **SHA-256**: Fast but not recommended for passwords (demonstration only)
2. **SHA-3**: Newer hash function, still too fast for passwords
3. **bcrypt**: Industry standard, adaptive cost factor
4. **Argon2**: Modern winner of Password Hashing Competition

### Salt and Pepper

- **Salt**: Random per-user value stored in database
  - Prevents rainbow table attacks
  - Makes identical passwords have different hashes

- **Pepper**: System-wide secret NOT stored in database
  - Defense-in-depth measure
  - Protects against database compromise

### HMAC Integrity

All API responses include HMAC for integrity protection:
- Prevents tampering with responses
- Uses `hmac.compare_digest()` for constant-time verification
- Demonstrates defense against length-extension attacks

### Multi-Factor Authentication

1. **TOTP** (Time-based One-Time Password)
   - 30-second time windows
   - Configurable ±N window tolerance
   - Vulnerable to MITM relay attacks

2. **HOTP** (HMAC-based One-Time Password)
   - Counter-based
   - Demonstrates counter desynchronization
   - Look-ahead window for counter drift
   - Vulnerable to MITM relay attacks

3. **WebAuthn/FIDO2**
   - Public key cryptography
   - Origin binding prevents MITM attacks
   - Phishing-resistant
   - Hardware security key support

## Attack Demonstrations

### Password Cracking

The `password_cracker.py` script demonstrates:
- Dictionary attacks against weak passwords
- Brute-force attacks against short passwords
- Time-to-crack differences between algorithms
- Impact of cost parameters

**Key Finding:** bcrypt and Argon2 are orders of magnitude slower to crack than SHA-256/SHA-3

### Timing Attacks

The `timing_attack_demo.py` script demonstrates:
- Byte-by-byte timing leakage in vulnerable comparisons
- Statistical analysis of timing differences
- Constant-time comparison mitigation
- Remote timing attack simulation

**Key Finding:** Use `hmac.compare_digest()` for all security-sensitive comparisons

### MITM Relay Attacks

The `mitm_relay.py` proxy demonstrates:
- Capturing credentials and OTP codes
- Successful relay of TOTP/HOTP codes
- Failed relay of WebAuthn authentication
- Latency measurements

**Key Finding:** WebAuthn's origin binding prevents MITM attacks, while OTP codes can be relayed

## Generated Artifacts

After running the demonstrations, you'll find:

- `qr_*_totp.png` - TOTP QR codes for authenticator apps
- `qr_*_hotp.png` - HOTP QR codes for authenticator apps
- `timing_attack_results.png` - Timing attack visualization
- `common_passwords.txt` - Dictionary for password cracking
- `auth.db` - SQLite database with user data

## Test Coverage

The `test_api.py` script provides comprehensive testing:
- API connectivity and status
- User registration with all algorithms
- Login and password verification
- TOTP enrollment and verification
- HOTP enrollment and verification
- MFA logs retrieval
- Algorithm performance comparison
- Salt vs pepper comparison

## Security Considerations

### For Educational Use Only

⚠️ **WARNING**: This code is for educational purposes in controlled environments.

- The MITM proxy should only be used in isolated lab environments
- Do not use against systems you don't own
- Do not deploy this code in production without security review
- Some features (like timing_vulnerable mode) are intentionally insecure for demonstration

### Production Recommendations

If adapting this code for production:

1. Use Argon2 or bcrypt for password hashing
2. Always use pepper in addition to salt
3. Implement rate limiting on authentication endpoints
4. Use HTTPS for all connections
5. Prefer WebAuthn over OTP for MFA
6. Add CSRF protection
7. Implement proper session management
8. Add comprehensive logging and monitoring
9. Regular security audits
10. Keep dependencies updated

## Troubleshooting

### API won't start

- Check if port 5000 is already in use
- Verify all dependencies are installed
- Check Python version (3.8+ required)

### TOTP codes not working

- Ensure system time is synchronized
- Try increasing the time window parameter
- Verify the secret was correctly enrolled

### HOTP counter desync

- Use the `look_ahead` parameter to account for drift
- Check the current counter value in the database
- Re-enroll if necessary

### WebAuthn not working

- WebAuthn requires HTTPS or localhost
- Some browsers have better WebAuthn support than others
- Check browser console for errors
- Verify RP ID matches the domain

## Database Schema

The SQLite database (`auth.db`) contains:

### Users Table
- `id` - Primary key
- `username` - Unique username
- `salt` - Random salt (binary)
- `hash` - Password hash (binary)
- `hash_algorithm` - Algorithm used
- `pepper_used` - Boolean flag
- `totp_secret` - TOTP secret key
- `hotp_secret` - HOTP secret key
- `hotp_counter` - Current HOTP counter
- `webauthn_credential_id` - FIDO2 credential ID
- `webauthn_public_key` - FIDO2 public key
- `created_at` - Timestamp

### MFA Logs Table
- `id` - Primary key
- `username` - Username
- `mfa_type` - TOTP/HOTP/WebAuthn
- `success` - Boolean
- `timestamp` - When attempt occurred
- `details` - Additional information

## Performance Benchmarks

Expected performance on modern hardware:

- SHA-256: ~50,000 hashes/sec
- SHA-3: ~40,000 hashes/sec
- bcrypt (cost=12): ~10 hashes/sec
- Argon2 (default): ~5 hashes/sec

This demonstrates why bcrypt/Argon2 are preferred - they're intentionally slow to resist brute-force attacks.

## Further Reading

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)

## License

Educational use only - D7076E Security Lab

## Author

Security Lab Assignment - D7076E
