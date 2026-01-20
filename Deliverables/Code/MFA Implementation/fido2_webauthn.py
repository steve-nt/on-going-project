"""
FIDO2/WebAuthn Implementation
"""

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.client import CollectedClientData
from fido2 import cbor
import secrets
import json
import os
from datetime import datetime
import requests
import pyotp
import time

class WebAuthnManager:
    def __init__(self, rp_id="localhost", rp_name="SecureAuthApp"):
        """
        Initialize WebAuthn server
        
        Args:
            rp_id: Relying Party ID (domain)
            rp_name: Relying Party name
        """
        self.rp = PublicKeyCredentialRpEntity(name=rp_name, id=rp_id)
        self.server = Fido2Server(self.rp)
        
        # Storage for registered credentials
        self.credentials_db = {}  # username -> list of credentials
        self.registration_logs = []
        self.authentication_logs = []
    
    def register_begin(self, username, user_id=None):
        """
        Begin WebAuthn registration process
        
        Returns:
            dict with registration options for client
        """
        if user_id is None:
            user_id = secrets.token_bytes(32)
        
        user = PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username
        )
        
        # Generate registration challenge
        registration_data, state = self.server.register_begin(
            user,
            credentials=self.credentials_db.get(username, []),
            user_verification="discouraged"
        )
        
        # Store state for verification
        self.registration_state = state
        
        # Log registration attempt
        self.registration_logs.append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'event': 'registration_begin',
            'challenge': registration_data.public_key.challenge.hex()
        })
        
        return {
            'username': username,
            'user_id': user_id.hex(),
            'registration_options': self._serialize_registration_data(registration_data.public_key),
            'state': state
        }
    
    def register_complete(self, username, client_data, attestation_object):
        """
        Complete WebAuthn registration
        
        Args:
            username: Username
            client_data: ClientData from authenticator
            attestation_object: AttestationObject from authenticator
        
        Returns:
            dict with credential info
        """
        try:
            # Verify and complete registration
            auth_data = self.server.register_complete(
                self.registration_state,
                client_data,
                attestation_object
            )
            
            # Store credential
            if username not in self.credentials_db:
                self.credentials_db[username] = []
            
            credential = {
                'credential_id': auth_data.credential_data.credential_id.hex(),
                'public_key': cbor.encode(auth_data.credential_data.public_key).hex(),
                'sign_count': auth_data.counter,
                'registered_at': datetime.now().isoformat()
            }
            
            self.credentials_db[username].append(auth_data.credential_data)
            
            # Log successful registration
            self.registration_logs.append({
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'event': 'registration_complete',
                'credential_id': credential['credential_id'],
                'status': 'success'
            })
            
            return {
                'success': True,
                'credential': credential
            }
        
        except Exception as e:
            # Log failed registration
            self.registration_logs.append({
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'event': 'registration_complete',
                'status': 'failed',
                'error': str(e)
            })
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def authenticate_begin(self, username):
        """
        Begin WebAuthn authentication
        
        Returns:
            dict with authentication options
        """
        credentials = self.credentials_db.get(username, [])
        
        if not credentials:
            return {
                'success': False,
                'error': 'No credentials registered for user'
            }
        
        # Generate authentication challenge
        auth_data, state = self.server.authenticate_begin(credentials)
        
        # Store state for verification
        self.authentication_state = state
        
        # Log authentication attempt
        self.authentication_logs.append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'event': 'authentication_begin',
            'challenge': auth_data['challenge'].hex()
        })
        
        return {
            'username': username,
            'authentication_options': self._serialize_authentication_data(auth_data),
            'state': state
        }
    
    def authenticate_complete(self, username, credential_id, client_data, authenticator_data, signature):
        """
        Complete WebAuthn authentication
        
        Args:
            username: Username
            credential_id: Credential ID from authenticator
            client_data: ClientData from authenticator
            authenticator_data: AuthenticatorData from authenticator
            signature: Signature from authenticator
        
        Returns:
            dict with authentication result
        """
        try:
            credentials = self.credentials_db.get(username, [])
            
            # Find the credential
            credential = None
            for cred in credentials:
                if cred.credential_id == bytes.fromhex(credential_id):
                    credential = cred
                    break
            
            if not credential:
                raise Exception("Credential not found")
            
            # Verify authentication
            self.server.authenticate_complete(
                self.authentication_state,
                credentials,
                credential_id,
                client_data,
                authenticator_data,
                signature
            )
            
            # Log successful authentication
            self.authentication_logs.append({
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'event': 'authentication_complete',
                'credential_id': credential_id,
                'status': 'success'
            })
            
            return {
                'success': True,
                'username': username
            }
        
        except Exception as e:
            # Log failed authentication
            self.authentication_logs.append({
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'event': 'authentication_complete',
                'status': 'failed',
                'error': str(e)
            })
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def demonstrate_origin_binding(self):
        """
        Demonstrate how WebAuthn origin binding prevents MITM attacks
        """
        print("\n=== WebAuthn Origin Binding Demonstration ===\n")
        
        print("Key Concept: WebAuthn binds authentication to the origin")
        print("- ClientData includes origin (e.g., https://example.com)")
        print("- Authenticator signs the ClientData with origin")
        print("- Server verifies origin matches RP ID")
        print("- MITM proxy at different origin will be detected\n")
        
        print("Scenario 1: Legitimate Authentication")
        print("-" * 50)
        print("User -> https://example.com (legitimate site)")
        print("Origin in ClientData: https://example.com")
        print("RP ID: example.com")
        print("Result: Origin matches RP ID → Authentication succeeds ✓\n")
        
        print("Scenario 2: MITM Attack")
        print("-" * 50)
        print("User -> https://evil-proxy.com (MITM proxy)")
        print("Proxy -> https://example.com (legitimate site)")
        print("Origin in ClientData: https://evil-proxy.com")
        print("RP ID: example.com")
        print("Result: Origin doesn't match RP ID → Authentication fails ✗\n")
        
        print("Scenario 3: OTP vs WebAuthn under MITM")
        print("-" * 50)
        print("OTP (TOTP/HOTP):")
        print("  - User generates: 123456")
        print("  - MITM captures: 123456")
        print("  - MITM forwards: 123456 to real site")
        print("  - Result: MITM attack succeeds ✗\n")
        
        print("WebAuthn:")
        print("  - Authenticator signs with origin: evil-proxy.com")
        print("  - MITM forwards signed data to: example.com")
        print("  - Server checks origin: evil-proxy.com != example.com")
        print("  - Result: MITM attack fails ✓\n")
    
    def _serialize_registration_data(self, data):
        """Convert registration data to serializable format"""
        return {
            'challenge': data.challenge.hex(),
            'rp': {'id': data.rp.id, 'name': data.rp.name},
            'user': {
                'id': data.user.id.hex(),
                'name': data.user.name,
                'displayName': data.user.display_name
            },
            'pubKeyCredParams': [
                {'type': str(p.type.value), 'alg': p.alg}
                for p in data.pub_key_cred_params
            ],
            'timeout': data.timeout if data.timeout else 60000
        }
    
    def _serialize_authentication_data(self, data):
        """Convert authentication data to serializable format"""
        return {
            'challenge': data['challenge'].hex(),
            'timeout': data.get('timeout', 60000),
            'rpId': data.get('rpId'),
            'allowCredentials': [
                {'type': 'public-key', 'id': cred['id'].hex()}
                for cred in data.get('allowCredentials', [])
            ]
        }
    
    def get_registration_logs(self):
        """Get all registration logs"""
        return self.registration_logs
    
    def get_authentication_logs(self):
        """Get all authentication logs"""
        return self.authentication_logs
    
    def save_logs(self, filename='webauthn_logs.json'):
        """Save logs to file"""
        logs = {
            'registration': self.registration_logs,
            'authentication': self.authentication_logs
        }
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2)


def interactive_relay_attack_demo():
    """
    Interactive demonstration of TOTP relay attack vs WebAuthn protection
    Requires integrated_app.py (port 5000) and mitm_proxy.py (port 8080) running
    """
    print("\n" + "="*80)
    print("INTERACTIVE RELAY ATTACK DEMONSTRATION")
    print("="*80)
    print("\nThis demonstration will:")
    print("1. Register a test user with TOTP MFA on the real server")
    print("2. Attempt TOTP login through MITM proxy → Should SUCCEED (vulnerable)")
    print("3. Show that WebAuthn would FAIL due to origin binding")
    print("\nPrerequisites:")
    print("  - integrated_app.py running on http://localhost:5000")
    print("  - mitm_proxy.py running on http://localhost:8080")
    print("="*80 + "\n")
    
    # Check if servers are running
    try:
        requests.get("http://localhost:5000", timeout=2)
        print("✓ Real server detected on port 5000")
    except:
        print("✗ ERROR: Real server not running on port 5000")
        print("  Please start: python3 integrated_app.py")
        return False
    
    try:
        requests.get("http://localhost:8080/proxy/stats", timeout=2)
        print("✓ MITM proxy detected on port 8080")
    except:
        print("✗ ERROR: MITM proxy not running on port 8080")
        print("  Please start: python3 mitm_proxy.py")
        return False
    
    print("\n" + "="*80)
    print("PHASE 1: SETUP - Register User with TOTP")
    print("="*80)
    
    test_user = "relay_test_user"
    test_pass = "SecurePass123!"
    
    # Register user on real server
    print(f"\n[1.1] Registering user '{test_user}' on real server (port 5000)...")
    try:
        response = requests.post(
            "http://localhost:5000/register",
            json={"username": test_user, "password": test_pass, "hash_type": "bcrypt"}
        )
        if response.status_code == 200:
            print(f"     ✓ User registered successfully")
        else:
            print(f"     Note: User may already exist (continuing...)")
    except Exception as e:
        print(f"     ✗ Registration failed: {e}")
        return False
    
    # Enroll TOTP
    print(f"\n[1.2] Enrolling TOTP for user '{test_user}'...")
    try:
        response = requests.post(
            "http://localhost:5000/mfa/enroll/totp",
            json={"username": test_user}
        )
        data = response.json()
        if 'secret' in data:
            totp_secret = data['secret']
            print(f"     ✓ TOTP enrolled successfully")
            print(f"     Secret: {totp_secret}")
        else:
            print(f"     Note: TOTP may already be enrolled")
            # Try to use a default secret or continue
            totp_secret = pyotp.random_base32()
    except Exception as e:
        print(f"     ✗ TOTP enrollment failed: {e}")
        return False
    
    time.sleep(1)
    
    print("\n" + "="*80)
    print("PHASE 2: TOTP RELAY ATTACK (Through MITM Proxy)")
    print("="*80)
    print("\nScenario: Victim thinks they're on the real site, but it's the MITM proxy")
    print("The proxy will capture credentials and relay them to the real server.")
    
    # Step 1: Login through proxy
    print(f"\n[2.1] Victim logs in through MITM proxy (port 8080)...")
    print(f"      Victim enters: username={test_user}, password={test_pass}")
    
    try:
        response = requests.post(
            "http://localhost:8080/login",
            json={"username": test_user, "password": test_pass}
        )
        data = response.json()
        print(f"      Response: {data.get('status', 'unknown')}")
        
        if data.get('status') == 'mfa_required':
            print(f"      ✓ MFA required - MITM captured credentials!")
            session_token = data.get('session_token', '')
        else:
            print(f"      Status: {data}")
            session_token = ""
    except Exception as e:
        print(f"      ✗ Login failed: {e}")
        return False
    
    time.sleep(1)
    
    # Step 2: Generate TOTP
    print(f"\n[2.2] Victim generates TOTP code on their device...")
    totp = pyotp.TOTP(totp_secret)
    totp_code = totp.now()
    print(f"      Generated TOTP: {totp_code}")
    print(f"      Victim enters code: {totp_code}")
    
    time.sleep(1)
    
    # Step 3: Relay TOTP through proxy
    print(f"\n[2.3] MITM proxy captures TOTP and relays to real server...")
    try:
        relay_start = time.time()
        response = requests.post(
            "http://localhost:8080/mfa/verify",
            json={"username": test_user, "token": totp_code}
        )
        relay_time = (time.time() - relay_start) * 1000
        
        data = response.json()
        print(f"      Relay latency: {relay_time:.2f}ms")
        print(f"      Response: {data.get('status', 'unknown')}")
        
        if data.get('status') == 'success':
            print(f"\n      ✗✗✗ ATTACK SUCCESSFUL! ✗✗✗")
            print(f"      - MITM proxy captured TOTP: {totp_code}")
            print(f"      - MITM relayed to real server within {relay_time:.2f}ms")
            print(f"      - Real server accepted TOTP (valid within 30-second window)")
            print(f"      - Attacker now has access to victim's account!")
            totp_success = True
        else:
            print(f"      Note: TOTP verification status: {data.get('message', 'unknown')}")
            totp_success = False
    except Exception as e:
        print(f"      ✗ TOTP relay failed: {e}")
        totp_success = False
    
    time.sleep(2)
    
    print("\n" + "="*80)
    print("PHASE 3: WEBAUTHN ORIGIN BINDING PROTECTION")
    print("="*80)
    print("\nScenario: Same attack but with WebAuthn instead of TOTP")
    
    print("\n[3.1] How WebAuthn prevents this attack:")
    print("      1. User visits MITM proxy: http://localhost:8080")
    print("      2. Browser creates WebAuthn assertion with origin: 'http://localhost:8080'")
    print("      3. MITM captures assertion and forwards to: http://localhost:5000")
    print("      4. Real server checks origin in assertion")
    print("      5. Origin mismatch detected: 'localhost:8080' ≠ 'localhost:5000'")
    print("      6. ✓ Authentication REJECTED!")
    
    print("\n[3.2] Why WebAuthn is different from TOTP:")
    
    comparison_table = [
        ("Property", "TOTP/HOTP", "WebAuthn"),
        ("-"*25, "-"*30, "-"*40),
        ("Credential Type", "6-digit number (123456)", "Cryptographic signature"),
        ("Origin Binding", "None", "Bound to domain in ClientData"),
        ("Can be copied", "Yes - just a number", "No - signature includes origin"),
        ("Relay Attack", "VULNERABLE ✗", "PROTECTED ✓"),
        ("Time Window", "~30 seconds", "N/A - origin check happens first"),
        ("User Awareness", "Can't tell if site is fake", "Browser enforces correct origin"),
    ]
    
    for row in comparison_table:
        print(f"      {row[0]:<25} | {row[1]:<30} | {row[2]:<40}")
    
    print("\n[3.3] Technical Details:")
    print("      WebAuthn ClientDataJSON includes:")
    print("      {")
    print("        'type': 'webauthn.get',")
    print("        'challenge': '<server_challenge>',")
    print("        'origin': 'http://localhost:8080'  ← Attacker's domain")
    print("      }")
    print("      ")
    print("      Real server (localhost:5000) expects:")
    print("        origin: 'http://localhost:5000'")
    print("      ")
    print("      Result: Origin mismatch → Authentication FAILS ✓")
    
    time.sleep(1)
    
    print("\n" + "="*80)
    print("DEMONSTRATION SUMMARY")
    print("="*80)
    
    print(f"\n✗ TOTP Relay Attack:   {'SUCCESSFUL (Vulnerable)' if totp_success else 'FAILED (Check setup)'}")
    print(f"✓ WebAuthn Protection: SECURE (Origin binding prevents relay)")
    
    print("\n" + "-"*80)
    print("RECOMMENDATIONS:")
    print("-"*80)
    print("1. For Maximum Security: Use WebAuthn (YubiKey, TouchID, Windows Hello)")
    print("2. If Using OTP: Educate users to verify URL before entering codes")
    print("3. Consider: Implementing both TOTP + WebAuthn for defense in depth")
    print("4. Monitor: Log all authentication attempts for suspicious patterns")
    
    # Check proxy stats
    try:
        print("\n" + "-"*80)
        print("MITM PROXY STATISTICS:")
        print("-"*80)
        response = requests.get("http://localhost:8080/proxy/stats")
        stats = response.json()
        print(f"Total relay attempts: {stats.get('total_relays', 0)}")
        print(f"Successful relays: {stats.get('successful_relays', 0)}")
        print(f"Failed relays: {stats.get('failed_relays', 0)}")
        print(f"OTP captures: {stats.get('otp_captures', 0)}")
        print(f"\nView detailed logs: http://localhost:8080/proxy/captured")
    except:
        pass
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print("\nYou can now see the output above to show:")
    print("  TOTP relay attack SUCCESS (vulnerable to MITM)")
    print("  WebAuthn origin binding PROTECTION (prevents MITM)")
    print("\n")
    
    return True


# Test and demonstration
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "relay-demo":
        # Interactive relay attack demonstration
        print("\nStarting Interactive Relay Attack Demonstration...")
        print("Make sure both servers are running:")
        print("  Terminal 1: python3 integrated_app.py")
        print("  Terminal 2: python3 mitm_proxy.py")
        print("  Terminal 3: python3 fido2_webauthn.py relay-demo")
        input("\nPress ENTER when both servers are ready...")
        
        success = interactive_relay_attack_demo()
        sys.exit(0 if success else 1)
    
    else:
        # Original standalone demonstration
        print("=== FIDO2/WebAuthn Implementation Test ===\n")
        
        manager = WebAuthnManager(rp_id="localhost", rp_name="SecureAuthApp")
        
        print("1. WebAuthn Registration Process")
        print("-" * 50)
        
        username = "webauthn_testuser"
        
        # Begin registration
        reg_data = manager.register_begin(username)
        print(f"Username: {username}")
        print(f"User ID: {reg_data['user_id']}")
        print(f"Challenge: {reg_data['registration_options']['challenge'][:32]}...")
        print(f"RP ID: {reg_data['registration_options']['rp']['id']}")
        
        print("\n2. Origin Binding Security")
        manager.demonstrate_origin_binding()
        
        print("3. Registration and Authentication Logs")
        print("-" * 50)
        print(f"Registration attempts: {len(manager.get_registration_logs())}")
        print(f"Authentication attempts: {len(manager.get_authentication_logs())}")
        
        # Save logs
        manager.save_logs()
        print("\nLogs saved to: webauthn_logs.json")
        
        print("\n" + "="*80)
        print("TIP: For interactive relay attack demonstration, run:")
        print("     python3 fido2_webauthn.py relay-demo")
        print("="*80)
        
        print("\n=== Test Complete ===")
