# Lab 3 Quick Start Guide

## Automated Launcher

The easiest way to run this project is using the automated launcher:

```bash
cd "Deliverables/Code"
python3 launcher.py
```

The launcher will:
- ✓ Check Python version (requires 3.7+)
- ✓ Check and optionally install missing dependencies
- ✓ Provide an interactive menu to run components
- ✓ Manage background processes automatically
- ✓ Clean up when you exit

## Launcher Menu Options

### 1. Quick Demo
Runs a complete automated demonstration:
- Starts the authentication server
- Shows TOTP, HOTP, and WebAuthn demos
- Demonstrates timing attacks
- Demonstrates password cracking

### 2. Step-by-Step Guided Tour
Walks you through each component with descriptions:
- Core Authentication Server
- TOTP Demonstration
- HOTP Demonstration
- WebAuthn/FIDO2 Demonstration
- Timing Attack
- Password Cracking
- MITM Relay Proxy (optional)

### 3. Individual Component Selection
Run specific components on demand:
- Core servers (integrated or basic)
- Individual MFA demos
- Attack demonstrations
- MITM proxy

### 4. Run Tests & Attack Demonstrations
Runs all security testing and attack demonstrations

### 5. Check System Status
Shows:
- Python version
- Installed dependencies
- Running processes
- Project structure

## Manual Execution

If you prefer to run components manually:

### Core Application
```bash
cd "Core Application Files"
python3 integrated_app.py
# Server runs on http://localhost:5000
```

### MFA Demonstrations
```bash
cd "MFA Implementation"

# TOTP Demo
python3 mfa_totp.py

# HOTP Demo
python3 mfa_hotp.py

# WebAuthn Demo
python3 fido2_webauthn.py

# Interactive Relay Attack Demo (requires servers running)
python3 fido2_webauthn.py relay-demo
```

### Attack Scripts
```bash
cd "Attack & Testing Scripts"

# Timing Attack
python3 timing_attack.py

# Password Cracking
python3 dictionary_attack.py

# MITM Proxy (requires server running)
python3 mitm_proxy.py
```

## Dependencies

Required Python packages:
- flask
- bcrypt
- argon2-cffi
- pyotp
- qrcode
- pillow
- fido2
- requests

Install manually if needed:
```bash
pip3 install --user flask bcrypt argon2-cffi pyotp qrcode pillow fido2 requests
```

## Output Files

Check the `../Artifacts/` directory for:
- QR codes (`qr_*.png`)
- Statistics logs (`*_stats.json`)
- Attack results (`*_report.txt`)
- WebAuthn traces (`webauthn_logs.json`)
- MITM logs (`mitm_logs.json`)

## Tips

- The launcher automatically manages background processes
- Press `Ctrl+C` to safely exit and cleanup
- Screenshots can be taken during any demonstration
- Check system status if something doesn't work
- All demonstrations are safe to run locally

## Need Help?

The launcher is self-explanatory with descriptions for each option.
For more details, see the full README.md file.
