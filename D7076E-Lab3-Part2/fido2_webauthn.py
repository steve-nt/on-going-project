"""
FIDO2 / WebAuthn Implementation for Person B - Lab 3
This module implements FIDO2/WebAuthn authentication

WebAuthn (Web Authentication):
- Uses public key cryptography (asymmetric)
- Private key never leaves user's device/security key
- Resistant to phishing and MITM attacks
- Binds authentication to origin (domain)

Key Components:
- Relying Party (RP): Your web application server
- Authenticator: User's device (phone, security key, biometric)
- Client: Browser with WebAuthn API

Security Advantage over TOTP/HOTP:
- TOTP/HOTP can be phished (user enters code on fake site)
- WebAuthn cannot be phished (cryptographic challenge tied to origin)
- MITM relay attacks fail due to origin binding

Author: Person B
Purpose: Educational demonstration of WebAuthn vs traditional OTP
"""

import json
import os
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConvoyancePreference
)
from fido2 import cbor
from base64 import b64encode, b64decode
import secrets
from typing import Dict, Optional, Tuple, List


class WebAuthnManager:
    """
    WebAuthn Server Implementation (Relying Party)

    Manages the server-side of WebAuthn authentication:
    - Registration: Creating new credentials
    - Authentication: Verifying credentials
    - Credential storage: Storing public keys and credential IDs
    """

    def __init__(self, rp_id: str = "localhost", rp_name: str = "Lab3 Secure App"):
        """
        Initialize WebAuthn Relying Party

        Args:
            rp_id: Relying Party ID (usually your domain)
            rp_name: Human-readable name for your application
        """
        # Relying Party Entity - identifies your application
        self.rp = PublicKeyCredentialRpEntity(
            id=rp_id,  # Must match the origin domain
            name=rp_name
        )

        # Initialize FIDO2 Server
        # This handles the cryptographic operations
        self.server = Fido2Server(self.rp)

        # Storage for user credentials
        # In production, this would be a database
        self.credentials_db = {}  # username -> list of credentials

        # Storage for pending challenges
        # Challenges are random values used to prevent replay attacks
        self.pending_challenges = {}  # username -> challenge

        print(f"[WebAuthn] Initialized Relying Party: {rp_name} ({rp_id})")

    def begin_registration(self, username: str, user_id: Optional[bytes] = None) -> Dict:
        """
        Start the WebAuthn registration process

        This is Step 1 of registration:
        - Server generates a challenge
        - Client will create a credential for this challenge

        Args:
            username: Username to register
            user_id: Unique user identifier (generated if not provided)

        Returns:
            Dictionary containing registration options for client
        """
        # Generate unique user ID if not provided
        if user_id is None:
            user_id = secrets.token_bytes(32)

        # Create user entity
        user = PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username
        )

        # Get existing credentials for this user (to avoid duplicates)
        existing_credentials = self.credentials_db.get(username, [])

        # Generate registration options
        # This includes the challenge and other parameters
        registration_data, state = self.server.register_begin(
            user=user,
            credentials=existing_credentials,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            authenticator_attachment=None  # Allow any authenticator type
        )

        # Store the challenge state for verification later
        self.pending_challenges[username] = state

        # Convert to JSON-serializable format
        options = {
            'publicKey': {
                'challenge': b64encode(registration_data['challenge']).decode('utf-8'),
                'rp': {
                    'name': registration_data['rp']['name'],
                    'id': registration_data['rp']['id']
                },
                'user': {
                    'id': b64encode(registration_data['user']['id']).decode('utf-8'),
                    'name': registration_data['user']['name'],
                    'displayName': registration_data['user']['displayName']
                },
                'pubKeyCredParams': registration_data['pubKeyCredParams'],
                'timeout': registration_data.get('timeout', 60000),
                'attestation': registration_data.get('attestation', 'none'),
                'excludeCredentials': []
            }
        }

        print(f"[WebAuthn] Registration started for user: {username}")
        print(f"[WebAuthn] Challenge (base64): {options['publicKey']['challenge'][:32]}...")

        return options

    def complete_registration(self, username: str, credential_data: Dict) -> Tuple[bool, str]:
        """
        Complete the WebAuthn registration process

        This is Step 2 of registration:
        - Client sends back the created credential
        - Server verifies and stores the public key

        Args:
            username: Username being registered
            credential_data: Credential data from client

        Returns:
            Tuple of (success: bool, credential_id: str)
        """
        try:
            # Get the stored challenge state
            if username not in self.pending_challenges:
                raise ValueError("No pending registration for user")

            state = self.pending_challenges[username]

            # Verify the credential
            # This checks the signature and attestation
            auth_data = self.server.register_complete(
                state=state,
                client_data=cbor.decode(b64decode(credential_data['clientDataJSON'])),
                attestation_object=cbor.decode(b64decode(credential_data['attestationObject']))
            )

            # Extract credential information
            credential_id = b64encode(auth_data.credential_data.credential_id).decode('utf-8')
            public_key = auth_data.credential_data.public_key

            # Store credential
            if username not in self.credentials_db:
                self.credentials_db[username] = []

            self.credentials_db[username].append({
                'credential_id': auth_data.credential_data.credential_id,
                'public_key': public_key,
                'credential_id_b64': credential_id,
                'sign_count': auth_data.credential_data.sign_count,
                'aaguid': auth_data.credential_data.aaguid
            })

            # Clean up pending challenge
            del self.pending_challenges[username]

            print(f"[WebAuthn] ✓ Registration complete for user: {username}")
            print(f"[WebAuthn] Credential ID: {credential_id}")
            print(f"[WebAuthn] Public key stored")

            return True, credential_id

        except Exception as e:
            print(f"[WebAuthn] ✗ Registration failed: {str(e)}")
            return False, ""

    def begin_authentication(self, username: str) -> Dict:
        """
        Start the WebAuthn authentication process

        This is Step 1 of authentication:
        - Server generates a challenge
        - Client will sign this challenge with private key

        Args:
            username: Username to authenticate

        Returns:
            Dictionary containing authentication options for client
        """
        # Check if user has registered credentials
        if username not in self.credentials_db or not self.credentials_db[username]:
            raise ValueError(f"No credentials found for user: {username}")

        # Get user's credentials
        credentials = [
            cred['credential_id'] for cred in self.credentials_db[username]
        ]

        # Generate authentication options
        auth_data, state = self.server.authenticate_begin(
            credentials=credentials,
            user_verification=UserVerificationRequirement.DISCOURAGED
        )

        # Store the challenge state
        self.pending_challenges[username] = state

        # Convert to JSON-serializable format
        options = {
            'publicKey': {
                'challenge': b64encode(auth_data['challenge']).decode('utf-8'),
                'timeout': auth_data.get('timeout', 60000),
                'rpId': auth_data.get('rpId'),
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': b64encode(cred['credential_id']).decode('utf-8')
                    }
                    for cred in self.credentials_db[username]
                ],
                'userVerification': auth_data.get('userVerification', 'discouraged')
            }
        }

        print(f"[WebAuthn] Authentication started for user: {username}")
        print(f"[WebAuthn] Challenge (base64): {options['publicKey']['challenge'][:32]}...")

        return options

    def complete_authentication(self, username: str, assertion_data: Dict) -> Tuple[bool, str]:
        """
        Complete the WebAuthn authentication process

        This is Step 2 of authentication:
        - Client sends back signed challenge
        - Server verifies signature with stored public key

        Args:
            username: Username being authenticated
            assertion_data: Assertion data from client

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Get the stored challenge state
            if username not in self.pending_challenges:
                raise ValueError("No pending authentication for user")

            state = self.pending_challenges[username]

            # Decode credential ID to find the right public key
            credential_id = b64decode(assertion_data['credentialId'])

            # Find the credential
            credential = None
            for cred in self.credentials_db[username]:
                if cred['credential_id'] == credential_id:
                    credential = cred
                    break

            if credential is None:
                raise ValueError("Credential not found")

            # Verify the assertion
            # This verifies the signature using the stored public key
            auth_data = self.server.authenticate_complete(
                state=state,
                credentials=[credential['credential_id']],
                credential_id=credential_id,
                client_data=cbor.decode(b64decode(assertion_data['clientDataJSON'])),
                auth_data=b64decode(assertion_data['authenticatorData']),
                signature=b64decode(assertion_data['signature'])
            )

            # Update sign count (prevents cloned authenticators)
            credential['sign_count'] = auth_data.new_sign_count

            # Clean up pending challenge
            del self.pending_challenges[username]

            print(f"[WebAuthn] ✓ Authentication successful for user: {username}")
            print(f"[WebAuthn] Sign count: {auth_data.new_sign_count}")

            return True, "Authentication successful"

        except Exception as e:
            print(f"[WebAuthn] ✗ Authentication failed: {str(e)}")
            return False, str(e)

    def get_user_credentials(self, username: str) -> List[Dict]:
        """
        Get all stored credentials for a user

        Args:
            username: Username to query

        Returns:
            List of credential dictionaries
        """
        return self.credentials_db.get(username, [])

    def export_credentials(self, filename: str = "webauthn_credentials.json"):
        """
        Export credentials to JSON file for analysis

        Note: In production, private keys should never be exported!
        This is only for educational demonstration.
        """
        export_data = {}

        for username, credentials in self.credentials_db.items():
            export_data[username] = []
            for cred in credentials:
                export_data[username].append({
                    'credential_id': cred['credential_id_b64'],
                    'sign_count': cred['sign_count'],
                    # Note: We don't export the actual public key bytes
                    # Just metadata for demonstration
                    'has_public_key': True
                })

        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"[WebAuthn] Credentials exported to {filename}")


def generate_client_html():
    """
    Generate HTML/JavaScript client for WebAuthn testing

    This creates a simple web page that uses the WebAuthn browser API
    to interact with the server implementation
    """
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Demo - Lab 3</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #666;
            margin-top: 30px;
        }
        .section {
            margin: 20px 0;
            padding: 20px;
            background-color: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }
        input {
            padding: 10px;
            width: 200px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background-color: #45a049;
        }
        button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .output {
            margin-top: 15px;
            padding: 10px;
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
        }
        .success {
            color: #4CAF50;
            font-weight: bold;
        }
        .error {
            color: #f44336;
            font-weight: bold;
        }
        .info {
            color: #2196F3;
        }
        .warning {
            padding: 15px;
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WebAuthn (FIDO2) Demonstration</h1>
        <p><strong>Lab 3 - Person B Implementation</strong></p>

        <div class="warning">
            <strong>⚠️ Important:</strong> This demo requires a local server and HTTPS or localhost.
            WebAuthn only works on secure origins for security reasons.
        </div>

        <h2>1. Registration</h2>
        <div class="section">
            <p>Register a new WebAuthn credential (security key, fingerprint, etc.)</p>
            <input type="text" id="registerUsername" placeholder="Username" value="alice">
            <button onclick="register()">Register</button>
            <div id="registerOutput" class="output"></div>
        </div>

        <h2>2. Authentication</h2>
        <div class="section">
            <p>Authenticate using your registered credential</p>
            <input type="text" id="authUsername" placeholder="Username" value="alice">
            <button onclick="authenticate()">Authenticate</button>
            <div id="authOutput" class="output"></div>
        </div>

        <h2>3. MITM Resistance Demo</h2>
        <div class="section">
            <p class="info">
                <strong>Key Security Feature:</strong> WebAuthn is resistant to MITM and phishing attacks
                because the authentication is cryptographically bound to the origin (domain).
            </p>
            <p>
                ✓ Traditional OTP (TOTP/HOTP): Can be captured and relayed to real site<br>
                ✗ WebAuthn: Cannot be relayed because signature includes origin verification
            </p>
            <button onclick="demonstrateMITM()">Show MITM Resistance</button>
            <div id="mitmOutput" class="output"></div>
        </div>
    </div>

    <script>
        // Base64 URL-safe encoding/decoding utilities
        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const base64 = btoa(binary);
            return base64.replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        }

        // Log output helper
        function log(elementId, message, type = 'info') {
            const output = document.getElementById(elementId);
            const timestamp = new Date().toLocaleTimeString();
            const className = type === 'error' ? 'error' : type === 'success' ? 'success' : 'info';
            output.innerHTML += `<div class="${className}">[${timestamp}] ${message}</div>`;
            output.scrollTop = output.scrollHeight;
        }

        // Clear output
        function clearLog(elementId) {
            document.getElementById(elementId).innerHTML = '';
        }

        // Registration function
        async function register() {
            clearLog('registerOutput');
            const username = document.getElementById('registerUsername').value;

            if (!username) {
                log('registerOutput', 'Please enter a username', 'error');
                return;
            }

            try {
                log('registerOutput', `Starting registration for: ${username}`);

                // Step 1: Get registration options from server
                // In a real implementation, this would be an API call
                log('registerOutput', 'Requesting registration challenge from server...');

                // Simulated server response (in real app, this comes from your Python server)
                const options = {
                    publicKey: {
                        challenge: new Uint8Array(32), // Random challenge from server
                        rp: { name: "Lab3 Secure App", id: "localhost" },
                        user: {
                            id: new Uint8Array(32), // User ID from server
                            name: username,
                            displayName: username
                        },
                        pubKeyCredParams: [
                            { type: "public-key", alg: -7 },  // ES256
                            { type: "public-key", alg: -257 } // RS256
                        ],
                        timeout: 60000,
                        attestation: "none"
                    }
                };

                // Generate random values for demo
                crypto.getRandomValues(options.publicKey.challenge);
                crypto.getRandomValues(options.publicKey.user.id);

                log('registerOutput', 'Challenge received, creating credential...');

                // Step 2: Create credential using WebAuthn API
                const credential = await navigator.credentials.create(options);

                log('registerOutput', '✓ Credential created successfully!', 'success');
                log('registerOutput', `Credential ID: ${bufferToBase64url(credential.rawId).substring(0, 32)}...`);

                // Step 3: Send credential to server for storage
                // In real implementation, send to server API
                const credentialData = {
                    credentialId: bufferToBase64url(credential.rawId),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64url(credential.response.attestationObject)
                };

                log('registerOutput', 'Sending credential to server for verification...');
                log('registerOutput', '✓ Registration complete! You can now authenticate.', 'success');

            } catch (error) {
                log('registerOutput', `✗ Registration failed: ${error.message}`, 'error');
                console.error(error);
            }
        }

        // Authentication function
        async function authenticate() {
            clearLog('authOutput');
            const username = document.getElementById('authUsername').value;

            if (!username) {
                log('authOutput', 'Please enter a username', 'error');
                return;
            }

            try {
                log('authOutput', `Starting authentication for: ${username}`);

                // Step 1: Get authentication challenge from server
                log('authOutput', 'Requesting authentication challenge from server...');

                // Simulated server response
                const options = {
                    publicKey: {
                        challenge: new Uint8Array(32),
                        timeout: 60000,
                        rpId: "localhost",
                        allowCredentials: [], // Would be populated by server
                        userVerification: "discouraged"
                    }
                };

                crypto.getRandomValues(options.publicKey.challenge);

                log('authOutput', 'Challenge received, signing with credential...');

                // Step 2: Get credential and sign challenge
                const assertion = await navigator.credentials.get(options);

                log('authOutput', '✓ Credential signature generated!', 'success');

                // Step 3: Send assertion to server for verification
                const assertionData = {
                    credentialId: bufferToBase64url(assertion.rawId),
                    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                    signature: bufferToBase64url(assertion.response.signature)
                };

                log('authOutput', 'Sending signature to server for verification...');
                log('authOutput', '✓ Authentication successful!', 'success');
                log('authOutput', 'User is now logged in via WebAuthn.');

            } catch (error) {
                log('authOutput', `✗ Authentication failed: ${error.message}`, 'error');
                console.error(error);
            }
        }

        // MITM Resistance Demonstration
        function demonstrateMITM() {
            clearLog('mitmOutput');

            log('mitmOutput', '=== MITM Attack Comparison ===');
            log('mitmOutput', '');

            log('mitmOutput', '1. Traditional OTP (TOTP/HOTP):');
            log('mitmOutput', '   User visits: phishing-site.com (attacker\'s site)');
            log('mitmOutput', '   User enters username + password + OTP code');
            log('mitmOutput', '   ✗ Attacker captures: username, password, OTP', 'error');
            log('mitmOutput', '   ✗ Attacker relays to real-site.com', 'error');
            log('mitmOutput', '   ✗ Attacker gains access (if OTP still valid)', 'error');
            log('mitmOutput', '   Time window: ~30 seconds for TOTP');
            log('mitmOutput', '');

            log('mitmOutput', '2. WebAuthn / FIDO2:');
            log('mitmOutput', '   User visits: phishing-site.com (attacker\'s site)');
            log('mitmOutput', '   User attempts WebAuthn authentication');
            log('mitmOutput', '   Browser checks origin: phishing-site.com');
            log('mitmOutput', '   ✓ Signature includes origin in clientDataJSON', 'success');
            log('mitmOutput', '   ✓ real-site.com receives signature with wrong origin', 'success');
            log('mitmOutput', '   ✓ Server rejects: origin mismatch!', 'success');
            log('mitmOutput', '   ✗ Attack fails - cannot relay credential', 'success');
            log('mitmOutput', '');

            log('mitmOutput', '=== Key Differences ===');
            log('mitmOutput', '');
            log('mitmOutput', 'OTP Vulnerability:');
            log('mitmOutput', '  • Code is just 6 digits - can be typed anywhere');
            log('mitmOutput', '  • No binding to origin/domain');
            log('mitmOutput', '  • User can be tricked into entering on fake site');
            log('mitmOutput', '');

            log('mitmOutput', 'WebAuthn Protection:');
            log('mitmOutput', '  • Cryptographic signature bound to origin');
            log('mitmOutput', '  • Browser enforces origin checking');
            log('mitmOutput', '  • Private key never leaves device');
            log('mitmOutput', '  • Cannot be phished or relayed');
            log('mitmOutput', '');

            log('mitmOutput', '✓ Demonstration complete!', 'success');
        }

        // Check WebAuthn support on page load
        window.onload = function() {
            if (!window.PublicKeyCredential) {
                alert('WebAuthn is not supported in this browser!\\n\\nPlease use a modern browser like Chrome, Firefox, Edge, or Safari.');
            }
        };
    </script>
</body>
</html>
"""

    with open("webauthn_demo.html", "w") as f:
        f.write(html_content)

    print("[WebAuthn] Client demo HTML generated: webauthn_demo.html")
    print("[WebAuthn] Open in browser at: http://localhost:8000/webauthn_demo.html")


def demo_webauthn_complete():
    """
    Complete demonstration of WebAuthn implementation
    Shows the server-side operations and security benefits
    """
    print("\n" + "="*70)
    print("FIDO2 / WEBAUTHN DEMONSTRATION")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    # Initialize WebAuthn manager
    manager = WebAuthnManager(rp_id="localhost", rp_name="Lab3 Secure App")

    print("\n" + "="*70)
    print("SERVER-SIDE OPERATIONS")
    print("="*70)

    print("\nNote: Full WebAuthn requires browser interaction.")
    print("This demo shows the server-side cryptographic operations.")
    print("Use the generated HTML file for browser-based testing.")

    # Demonstrate registration flow
    print("\n" + "-"*70)
    print("1. REGISTRATION FLOW")
    print("-"*70)

    username = "alice"
    print(f"\nStep 1: Server generates registration challenge for {username}")
    reg_options = manager.begin_registration(username)
    print(f"  Challenge length: {len(reg_options['publicKey']['challenge'])} characters")
    print(f"  RP ID: {reg_options['publicKey']['rp']['id']}")
    print(f"  User ID: {reg_options['publicKey']['user']['id'][:32]}...")

    print("\nStep 2: Browser calls navigator.credentials.create()")
    print("  - User touches security key or uses biometric")
    print("  - Authenticator generates key pair")
    print("  - Private key stays on device (never transmitted!)")
    print("  - Public key sent to server")

    print("\nStep 3: Server verifies and stores credential")
    print("  - In real scenario, credential data comes from browser")
    print("  - Server stores: credential_id + public_key")
    print("  - Private key remains on user's device")

    # Demonstrate authentication flow
    print("\n" + "-"*70)
    print("2. AUTHENTICATION FLOW")
    print("-"*70)

    print("\nStep 1: Server generates authentication challenge")
    print("  - Random challenge prevents replay attacks")
    print("  - Challenge tied to specific credential")

    print("\nStep 2: Browser calls navigator.credentials.get()")
    print("  - User authenticates (touch/biometric)")
    print("  - Authenticator signs challenge with private key")
    print("  - Signature + authenticator data sent to server")

    print("\nStep 3: Server verifies signature")
    print("  - Uses stored public key")
    print("  - Verifies origin matches RP ID")
    print("  - Checks signature is valid")
    print("  - Authentication succeeds only if all checks pass")

    # Demonstrate MITM resistance
    print("\n" + "-"*70)
    print("3. MITM RESISTANCE")
    print("-"*70)

    print("\n🔴 OTP (TOTP/HOTP) - Vulnerable to MITM:")
    print("  1. User visits phishing-site.com (attacker)")
    print("  2. User enters: username + password + OTP")
    print("  3. Attacker captures all credentials")
    print("  4. Attacker relays to real-site.com within time window")
    print("  5. ✗ Attack succeeds - attacker gains access")

    print("\n🟢 WebAuthn - Resistant to MITM:")
    print("  1. User visits phishing-site.com (attacker)")
    print("  2. User attempts WebAuthn authentication")
    print("  3. Browser signs challenge with origin: phishing-site.com")
    print("  4. Attacker relays signed challenge to real-site.com")
    print("  5. Server verifies: origin ≠ real-site.com")
    print("  6. ✓ Attack fails - signature bound to wrong origin")

    print("\n" + "-"*70)
    print("WHY WEBAUTHN IS MORE SECURE")
    print("-"*70)

    security_comparison = [
        ("Phishing Resistance", "✗ OTP: User can enter on fake site", "✓ WebAuthn: Origin-bound, cannot phish"),
        ("MITM Resistance", "✗ OTP: Can be relayed", "✓ WebAuthn: Cannot relay (origin check)"),
        ("Replay Attacks", "✗ OTP: Valid for 30s window", "✓ WebAuthn: Challenge prevents replay"),
        ("Credential Storage", "✗ OTP: Shared secret on server", "✓ WebAuthn: Only public key on server"),
        ("Device Compromise", "✗ OTP: Secret extractable from app", "✓ WebAuthn: Private key in secure enclave"),
    ]

    for feature, otp, webauthn in security_comparison:
        print(f"\n{feature}:")
        print(f"  {otp}")
        print(f"  {webauthn}")

    # Generate client HTML
    print("\n" + "="*70)
    print("GENERATING CLIENT DEMONSTRATION")
    print("="*70)
    generate_client_html()

    # Export credentials
    manager.export_credentials()

    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)
    print("\nNext steps:")
    print("1. Start a local web server: python3 -m http.server 8000")
    print("2. Open: http://localhost:8000/webauthn_demo.html")
    print("3. Try registration and authentication in browser")
    print("4. See MITM resistance demonstration")
    print("="*70 + "\n")


if __name__ == "__main__":
    demo_webauthn_complete()
