"""
API Testing Script
Tests all authentication endpoints and MFA flows
"""

import requests
import time
import json
import pyotp
from tabulate import tabulate

# Configuration
API_URL = "http://localhost:5000"
PROXY_URL = "http://localhost:5001"

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.CYAN}ℹ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def test_api_status():
    """Test API status endpoint"""
    print_header("Test 1: API Status")
    try:
        response = requests.get(f"{API_URL}/status")
        if response.status_code == 200:
            data = response.json()
            print_success("API is running")
            print_info(f"Algorithms: {', '.join(data['data']['algorithms'])}")
            print_info(f"MFA Types: {', '.join(data['data']['mfa_types'])}")
            return True
        else:
            print_error(f"API returned status {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Cannot connect to API: {e}")
        return False

def test_registration(username, password, algorithm='sha256', use_pepper=False):
    """Test user registration"""
    print_header(f"Test 2: User Registration ({algorithm})")
    try:
        data = {
            'username': username,
            'password': password,
            'algorithm': algorithm,
            'use_pepper': use_pepper
        }
        response = requests.post(f"{API_URL}/register", json=data)

        if response.status_code == 201:
            result = response.json()
            print_success(f"User '{username}' registered successfully")
            print_info(f"Algorithm: {result['data']['algorithm']}")
            print_info(f"Pepper used: {result['data']['pepper_used']}")
            print_info(f"Salt (base64): {result['data']['salt'][:32]}...")
            print_info(f"Hash (base64): {result['data']['hash'][:32]}...")
            return True, result
        else:
            print_error(f"Registration failed: {response.json().get('error')}")
            return False, None
    except Exception as e:
        print_error(f"Registration error: {e}")
        return False, None

def test_login(username, password, timing_vulnerable=False):
    """Test user login"""
    print_header(f"Test 3: User Login")
    try:
        data = {
            'username': username,
            'password': password,
            'timing_vulnerable': timing_vulnerable
        }
        response = requests.post(f"{API_URL}/login", json=data)

        if response.status_code == 200:
            result = response.json()
            print_success(f"Login successful for '{username}'")
            print_info(f"MFA Enabled: {result['data']['mfa_enabled']}")
            print_info(f"MFA Required: {result['data']['mfa_required']}")
            print_info(f"Verification Time: {result['data']['verification_time_us']:.2f} μs")
            return True, result
        else:
            print_error(f"Login failed: {response.json().get('error')}")
            return False, None
    except Exception as e:
        print_error(f"Login error: {e}")
        return False, None

def test_totp_enrollment(username):
    """Test TOTP enrollment"""
    print_header("Test 4: TOTP Enrollment")
    try:
        data = {'username': username}
        response = requests.post(f"{API_URL}/mfa/totp/enroll", json=data)

        if response.status_code == 200:
            result = response.json()
            secret = result['data']['secret']
            qr_file = result['data']['qr_code_file']
            print_success(f"TOTP enrolled for '{username}'")
            print_info(f"Secret: {secret}")
            print_info(f"QR Code saved: {qr_file}")
            print_info(f"URI: {result['data']['provisioning_uri']}")
            return True, secret
        else:
            print_error(f"TOTP enrollment failed: {response.json().get('error')}")
            return False, None
    except Exception as e:
        print_error(f"TOTP enrollment error: {e}")
        return False, None

def test_totp_verification(username, secret, window=0):
    """Test TOTP verification"""
    print_header(f"Test 5: TOTP Verification (window=±{window})")
    try:
        # Generate current TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        print_info(f"Generated TOTP code: {code}")

        data = {
            'username': username,
            'code': code,
            'window': window
        }
        response = requests.post(f"{API_URL}/mfa/totp/verify", json=data)

        if response.status_code == 200:
            print_success("TOTP verification successful")
            return True
        else:
            print_error(f"TOTP verification failed: {response.json().get('error')}")
            return False
    except Exception as e:
        print_error(f"TOTP verification error: {e}")
        return False

def test_hotp_enrollment(username):
    """Test HOTP enrollment"""
    print_header("Test 6: HOTP Enrollment")
    try:
        data = {'username': username}
        response = requests.post(f"{API_URL}/mfa/hotp/enroll", json=data)

        if response.status_code == 200:
            result = response.json()
            secret = result['data']['secret']
            qr_file = result['data']['qr_code_file']
            print_success(f"HOTP enrolled for '{username}'")
            print_info(f"Secret: {secret}")
            print_info(f"QR Code saved: {qr_file}")
            print_info(f"Counter: {result['data']['counter']}")
            return True, secret
        else:
            print_error(f"HOTP enrollment failed: {response.json().get('error')}")
            return False, None
    except Exception as e:
        print_error(f"HOTP enrollment error: {e}")
        return False, None

def test_hotp_verification(username, secret, counter):
    """Test HOTP verification"""
    print_header(f"Test 7: HOTP Verification (counter={counter})")
    try:
        # Generate HOTP code for current counter
        hotp = pyotp.HOTP(secret)
        code = hotp.at(counter)

        print_info(f"Generated HOTP code for counter {counter}: {code}")

        data = {
            'username': username,
            'code': code,
            'look_ahead': 3
        }
        response = requests.post(f"{API_URL}/mfa/hotp/verify", json=data)

        if response.status_code == 200:
            result = response.json()
            print_success("HOTP verification successful")
            print_info(f"Counter used: {result['data']['counter_used']}")
            print_info(f"Counter drift: {result['data']['counter_drift']}")
            return True
        else:
            print_error(f"HOTP verification failed: {response.json().get('error')}")
            return False
    except Exception as e:
        print_error(f"HOTP verification error: {e}")
        return False

def test_mfa_logs(username=None):
    """Test MFA logs retrieval"""
    print_header("Test 8: MFA Logs")
    try:
        params = {'username': username} if username else {}
        response = requests.get(f"{API_URL}/mfa/logs", params=params)

        if response.status_code == 200:
            result = response.json()
            logs = result['data']['logs']
            print_success(f"Retrieved {len(logs)} MFA log entries")

            if logs:
                # Display logs in table format
                table_data = []
                for log in logs[:10]:  # Show last 10
                    table_data.append([
                        log.get('username', 'N/A'),
                        log['mfa_type'],
                        '✓' if log['success'] else '✗',
                        log['timestamp'],
                        log.get('details', '')[:30]
                    ])

                print("\nRecent MFA Attempts:")
                print(tabulate(table_data,
                             headers=['Username', 'Type', 'Success', 'Timestamp', 'Details'],
                             tablefmt='grid'))
            return True
        else:
            print_error(f"Failed to retrieve logs: {response.json().get('error')}")
            return False
    except Exception as e:
        print_error(f"MFA logs error: {e}")
        return False

def test_algorithm_comparison():
    """Test different hashing algorithms"""
    print_header("Test 9: Algorithm Comparison")

    algorithms = ['sha256', 'sha3', 'bcrypt', 'argon2']
    results = []

    for algo in algorithms:
        username = f"test_{algo}_user"
        password = "test_password_123"

        print(f"\nTesting {algo.upper()}...")

        # Register
        success, _ = test_registration(username, password, algo, use_pepper=False)
        if not success:
            continue

        # Login and measure time
        start = time.time()
        success, result = test_login(username, password)
        elapsed = (time.time() - start) * 1000

        if success:
            verify_time = result['data']['verification_time_us']
            results.append([algo.upper(), f"{elapsed:.2f} ms", f"{verify_time:.2f} μs"])

    if results:
        print("\n" + Colors.BOLD + "Algorithm Performance Comparison:" + Colors.END)
        print(tabulate(results,
                     headers=['Algorithm', 'Total Time', 'Verification Time'],
                     tablefmt='grid'))

def test_pepper_comparison():
    """Test salt vs salt+pepper"""
    print_header("Test 10: Salt vs Pepper Comparison")

    username_no_pepper = "test_no_pepper"
    username_with_pepper = "test_with_pepper"
    password = "test_password"

    # Register without pepper
    print("\nRegistering WITHOUT pepper:")
    success1, _ = test_registration(username_no_pepper, password, 'sha256', use_pepper=False)

    # Register with pepper
    print("\nRegistering WITH pepper:")
    success2, _ = test_registration(username_with_pepper, password, 'sha256', use_pepper=True)

    if success1 and success2:
        print("\n" + Colors.BOLD + "Analysis:" + Colors.END)
        print_info("Both users have same password but different security levels")
        print_info("Without pepper: Attacker with DB can crack passwords")
        print_info("With pepper: Attacker needs both DB AND server secret")

def run_all_tests():
    """Run complete test suite"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("="*80)
    print("SECURE AUTHENTICATION API - TEST SUITE".center(80))
    print("D7076E Security Lab 3".center(80))
    print("="*80)
    print(Colors.END)

    # Test 1: API Status
    if not test_api_status():
        print_error("API is not running. Please start the API first.")
        return

    # Test 2-3: Registration and Login
    username = "alice"
    password = "secure_password_123"
    test_registration(username, password, 'argon2', use_pepper=True)
    test_login(username, password)

    # Test 4-5: TOTP
    success, totp_secret = test_totp_enrollment(username)
    if success:
        time.sleep(1)  # Wait a moment
        test_totp_verification(username, totp_secret, window=1)

    # Test 6-7: HOTP
    success, hotp_secret = test_hotp_enrollment(username)
    if success:
        test_hotp_verification(username, hotp_secret, counter=0)
        test_hotp_verification(username, hotp_secret, counter=1)

    # Test 8: MFA Logs
    test_mfa_logs(username)

    # Test 9-10: Comparisons
    test_algorithm_comparison()
    test_pepper_comparison()

    print_header("Test Suite Complete")
    print_success("All tests completed!")
    print_info("Check the logs and artifacts for detailed results")

if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == 'status':
            test_api_status()
        elif sys.argv[1] == 'register':
            username = input("Username: ")
            password = input("Password: ")
            algorithm = input("Algorithm (sha256/sha3/bcrypt/argon2): ") or 'sha256'
            use_pepper = input("Use pepper? (y/n): ").lower() == 'y'
            test_registration(username, password, algorithm, use_pepper)
        elif sys.argv[1] == 'login':
            username = input("Username: ")
            password = input("Password: ")
            test_login(username, password)
        elif sys.argv[1] == 'logs':
            username = input("Username (leave blank for all): ") or None
            test_mfa_logs(username)
        else:
            print(f"Unknown command: {sys.argv[1]}")
    else:
        run_all_tests()
