================================================================================
                    v1-D7076E-Lab3 - PROJECT OVERVIEW
              Secure Authentication API with MFA and Attack Analysis
================================================================================

This project implements a comprehensive authentication security system
demonstrating password hashing, multi-factor authentication, attack vectors,
and defense mechanisms.


================================================================================
PROJECT STRUCTURE
================================================================================

Assignment Document:
  Assigment-PersonA-PersonB.txt     - Original assignment and task division

Person A Files (Core API & Security Foundations):
  PersonA-app.py                     - Flask REST API with password hashing
  PersonA-crack_passwords.py         - Password cracking demonstration
  PersonA-timing_attack.py           - Timing attack vulnerability demo
  PersonA-testing.py                 - API testing script
  PersonA.txt                        - Person A documentation (7 KB)
  PersonA-Task-Completion-Report.txt - Complete analysis report (19 KB)

Person B Files (MFA, Attacks & Mitigations):
  PersonB-mfa_totp.py                - TOTP implementation
  PersonB-mfa_hotp.py                - HOTP implementation
  PersonB-fido2_webauthn.py          - WebAuthn/FIDO2 implementation
  PersonB-dictionary_attack.py       - Dictionary/brute-force attacks
  PersonB-mitm_proxy.py              - MITM relay proxy
  PersonB-integrated_app.py          - Integrated Flask app with MFA
  PersonB-Report.txt                 - Comprehensive theory report (40 KB)
  PersonB-Task-Completion-Summary.txt - Task completion summary (12 KB)

Total: 15 files (168 KB)


================================================================================
QUICK START
================================================================================

1. Install Dependencies:
   pip install flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests

2. Run Person A's API:
   python PersonA-app.py
   # Server runs on http://localhost:5000

3. Test Person A's API:
   python PersonA-testing.py

4. Run Person B's Integrated API:
   python PersonB-integrated_app.py
   # Server runs on http://localhost:5000 with MFA support

5. Run Individual Demonstrations:
   python PersonB-mfa_totp.py          # TOTP demo
   python PersonB-mfa_hotp.py          # HOTP demo
   python PersonB-fido2_webauthn.py    # WebAuthn demo
   python PersonB-dictionary_attack.py # Password cracking
   python PersonB-mitm_proxy.py        # MITM proxy (needs target server)


================================================================================
FEATURES IMPLEMENTED
================================================================================

Password Storage & Hashing (Person A):
  ✓ SHA-256 with configurable iterations
  ✓ SHA-3 (SHA3-256)
  ✓ bcrypt with cost factor
  ✓ Argon2 (memory-hard)
  ✓ Per-user salts (32 bytes)
  ✓ System-wide pepper
  ✓ HMAC integrity on API responses

Multi-Factor Authentication (Person B):
  ✓ TOTP (Time-based One-Time Password)
    - QR code enrollment
    - Configurable time windows (±0, ±1, ±2)
    - Statistics tracking
  
  ✓ HOTP (HMAC-based One-Time Password)
    - Counter management
    - Desync detection and resync
    - Look-ahead window (10 counters)
  
  ✓ WebAuthn/FIDO2
    - Registration and authentication flows
    - Origin binding (MITM protection)
    - Credential storage

Attack Demonstrations (Person B):
  ✓ Dictionary attacks
  ✓ Brute-force attacks
  ✓ Hash algorithm benchmarking
  ✓ Timing attack demonstrations
  ✓ MITM relay attacks
  ✓ OTP relay (succeeds)
  ✓ WebAuthn relay (fails - protected)

Security Analysis:
  ✓ Algorithm performance comparison
  ✓ Time-to-crack measurements
  ✓ Success rate statistics
  ✓ Latency analysis
  ✓ Security recommendations


================================================================================
API ENDPOINTS
================================================================================

Core Authentication:
  POST /register              - User registration
    Body: {username, password, hash_type}
  
  POST /login                 - User login
    Body: {username, password}

MFA Enrollment:
  POST /mfa/enroll/totp       - Enroll TOTP
    Body: {username}
    Returns: secret, QR code provisioning URI
  
  POST /mfa/enroll/hotp       - Enroll HOTP
    Body: {username}
    Returns: secret, counter

MFA Verification:
  POST /mfa/verify            - Verify TOTP/HOTP token
    Body: {username, token, time_window}
  
  GET /mfa/stats              - Get MFA statistics
    Query: ?username=<username> (optional)

Proxy Endpoints (MITM Demo):
  All endpoints mirrored on port 5001
  GET /proxy/stats            - Proxy statistics
  GET /proxy/captured         - Captured credentials/OTP


================================================================================
KEY CONCEPTS DEMONSTRATED
================================================================================

1. Password Security:
   - Strong hashing algorithms (bcrypt, Argon2)
   - Per-user salts prevent rainbow tables
   - System pepper adds defense-in-depth
   - Iteration counts slow down cracking

2. Multi-Factor Authentication:
   - TOTP: Time-synchronized, widely supported
   - HOTP: Counter-based, offline support
   - WebAuthn: Cryptographic, phishing-resistant

3. Attack Vectors:
   - Dictionary attacks exploit common passwords
   - Brute-force systematically tries all combinations
   - Timing attacks leak information through execution time
   - MITM relays capture and forward credentials/OTP

4. Defense Mechanisms:
   - Constant-time comparisons prevent timing attacks
   - HMAC ensures message integrity
   - Origin binding prevents MITM (WebAuthn)
   - Strong hash algorithms resist cracking

5. Security Trade-offs:
   - Usability vs Security (time windows)
   - Performance vs Protection (hash iterations)
   - Complexity vs Adoption (WebAuthn vs OTP)


================================================================================
EXPERIMENTAL RESULTS HIGHLIGHTS
================================================================================

Password Cracking (Person A):
  - 3-char password "abc" cracked in ~126 seconds
  - SHA-256 (100 rounds): ~11 attempts/second
  - Demonstrates vulnerability of fast hashes

Timing Attacks (Person A):
  - Naive comparison: 616-706 nanoseconds (varies)
  - Secure comparison: 739-834 nanoseconds (consistent)
  - Measurable timing differences detected

Hash Algorithm Comparison (Person B):
  - SHA-256 (100): 0.05ms per hash (baseline)
  - SHA-256 (10k): 5ms per hash (100x slower)
  - bcrypt (cost=8): 30ms per hash (600x slower)
  - Argon2: 50ms per hash (1000x slower)

TOTP Time Windows (Person B):
  - Window ±0: 85% success, high security
  - Window ±1: 98% success, balanced (RECOMMENDED)
  - Window ±2: 99.5% success, lower security

MITM Relay Performance (Person B):
  - OTP relay latency: ~75ms average
  - OTP relay success: >95%
  - WebAuthn relay: 0% success (origin binding)


================================================================================
DOCUMENTATION
================================================================================

Read these reports for complete details:

1. PersonA-Task-Completion-Report.txt (19 KB)
   - Person A task analysis
   - Implementation details
   - Code architecture
   - Experimental results

2. PersonB-Report.txt (40 KB)
   - Complete theoretical foundations
   - MFA algorithms (TOTP, HOTP, WebAuthn)
   - Attack methodologies
   - Security analysis
   - Experimental results
   - Industry standards
   - Security recommendations

3. PersonB-Task-Completion-Summary.txt (12 KB)
   - Quick overview of Person B deliverables
   - File descriptions
   - Execution instructions


================================================================================
ARTIFACTS GENERATED AT RUNTIME
================================================================================

When running the applications, these files are created:

Database:
  users.db                    - SQLite database with users and MFA data

QR Codes:
  qr_<username>_totp.png      - TOTP enrollment QR codes

Statistics:
  totp_stats.json             - TOTP verification statistics
  hotp_stats.json             - HOTP verification statistics
  cracking_report.txt         - Password cracking analysis
  mitm_logs.json              - MITM proxy capture logs
  webauthn_logs.json          - WebAuthn registration/auth logs


================================================================================
SECURITY RECOMMENDATIONS
================================================================================

For Production Deployment:

1. Password Storage:
   ✓ Use Argon2 (best) or bcrypt (good)
   ✓ Minimum bcrypt cost: 12
   ✓ Minimum Argon2: time_cost=3, memory_cost=65536
   ✓ Store pepper in secure key management system
   ✓ Encrypt database at rest

2. MFA Selection:
   ✓ WebAuthn for high-security users
   ✓ TOTP for standard users (with education)
   ✓ Avoid SMS OTP (SIM swapping vulnerability)
   ✓ Provide backup codes for recovery

3. API Security:
   ✓ Use HTTPS (TLS 1.3)
   ✓ Implement rate limiting
   ✓ Add CSRF protection
   ✓ Use secure session management
   ✓ Implement proper error handling
   ✓ Log security events

4. Monitoring:
   ✓ Track failed authentication attempts
   ✓ Detect anomalous patterns (IP, location, device)
   ✓ Alert on suspicious activity
   ✓ Regular security audits

5. User Education:
   ✓ Phishing awareness training
   ✓ Strong password guidelines
   ✓ MFA enrollment instructions
   ✓ Security best practices


================================================================================
LEARNING OBJECTIVES ACHIEVED
================================================================================

✓ Understanding of secure password storage
✓ Implementation of multiple hashing algorithms
✓ Salt and pepper security techniques
✓ HMAC and message integrity
✓ Constant-time comparisons
✓ TOTP/HOTP one-time password systems
✓ WebAuthn/FIDO2 cryptographic authentication
✓ Origin binding and MITM protection
✓ Password cracking techniques
✓ Attack and defense demonstrations
✓ Performance benchmarking
✓ Security analysis and recommendations
✓ Industry standards compliance (NIST SP 800-63B)


================================================================================
NIST AAL COMPLIANCE
================================================================================

Authenticator Assurance Level 1 (AAL1):
  ✓ Memorized secret with strong hashing

Authenticator Assurance Level 2 (AAL2):
  ✓ Two-factor: Password + TOTP/HOTP
  ⚠ Note: OTP is phishing-vulnerable

Authenticator Assurance Level 3 (AAL3):
  ✓ Hardware authenticator (WebAuthn)
  ✓ Phishing-resistant
  ✓ Fully compliant


================================================================================
TESTING SCENARIOS
================================================================================

1. Basic Authentication:
   - Register user with different hash types
   - Login with correct/incorrect password
   - Verify HMAC integrity

2. TOTP Enrollment and Verification:
   - Enroll user for TOTP
   - Generate QR code
   - Verify token with different time windows
   - Test expired tokens

3. HOTP Enrollment and Verification:
   - Enroll user for HOTP
   - Generate tokens sequentially
   - Test counter desynchronization
   - Verify resynchronization

4. WebAuthn:
   - Register authenticator
   - Authenticate with challenge-response
   - Test origin binding
   - Attempt MITM relay (should fail)

5. Attack Demonstrations:
   - Dictionary attack on common password
   - Brute-force attack on short password
   - Timing attack comparison
   - MITM relay on OTP (succeeds)
   - MITM relay on WebAuthn (fails)


================================================================================
TROUBLESHOOTING
================================================================================

Common Issues:

1. "Module not found" errors:
   Solution: pip install <module_name>
   Install all: pip install flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests

2. "Address already in use" (port 5000):
   Solution: Kill existing process or use different port
   Find process: lsof -i :5000
   Kill: kill -9 <PID>

3. Database errors:
   Solution: Delete users.db and restart
   rm users.db && python PersonB-integrated_app.py

4. QR code not generating:
   Solution: Install Pillow (PIL)
   pip install pillow

5. MITM proxy connection refused:
   Solution: Ensure target server is running first
   Terminal 1: python PersonB-integrated_app.py
   Terminal 2: python PersonB-mitm_proxy.py


================================================================================
FUTURE ENHANCEMENTS
================================================================================

Potential improvements:

1. Additional MFA Methods:
   - Push notifications
   - Biometric authentication
   - Risk-based authentication

2. Advanced Security:
   - Device fingerprinting
   - Behavioral biometrics
   - Machine learning anomaly detection

3. User Experience:
   - Progressive enrollment
   - Passwordless flows
   - Social login integration

4. Enterprise Features:
   - SSO (SAML, OAuth, OIDC)
   - Centralized policy management
   - Compliance reporting
   - Audit logging

5. Performance:
   - Database connection pooling
   - Caching layer (Redis)
   - Load balancing
   - Horizontal scaling


================================================================================
CONTACT & SUPPORT
================================================================================

For questions or issues:
1. Review the comprehensive reports in this directory
2. Check inline code documentation (docstrings)
3. Examine test output and logs
4. Refer to assignment document for requirements


================================================================================
ACKNOWLEDGMENTS
================================================================================

Standards and Specifications:
- RFC 6238: TOTP
- RFC 4226: HOTP
- W3C WebAuthn Specification
- FIDO2 CTAP2 Specification
- NIST SP 800-63B: Digital Identity Guidelines

Libraries Used:
- Flask: Web framework
- pyotp: TOTP/HOTP implementation
- python-fido2: WebAuthn/FIDO2
- bcrypt: bcrypt hashing
- argon2-cffi: Argon2 hashing
- qrcode: QR code generation


================================================================================
LICENSE
================================================================================

Educational project for security demonstration purposes.
Code provided for learning and research.
Use responsibly and ethically.


================================================================================
END OF README
================================================================================

Last Updated: October 18, 2025
Project Status: COMPLETE
