"""
FIDO2/WebAuthn Implementation
Person B - MFA Component
Demonstrates origin/RP-ID binding that prevents MITM attacks
"""

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.client import CollectedClientData
from fido2 import cbor
import secrets
import json
import os
from datetime import datetime

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


# Test and demonstration
if __name__ == "__main__":
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
    
    print("\n=== Test Complete ===")
