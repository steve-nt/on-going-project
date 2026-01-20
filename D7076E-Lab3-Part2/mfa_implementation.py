"""
MFA Implementation for Person B - Lab 3
This module implements Multi-Factor Authentication using TOTP and HOTP

TOTP (Time-based One-Time Password):
- Generates codes that change every 30 seconds
- More secure as codes expire quickly
- Used by Google Authenticator, Authy, etc.

HOTP (HMAC-based One-Time Password):
- Generates codes based on a counter
- Counter increments with each use
- Can have desync issues if counter mismatches

Author: Person B
Purpose: Educational demonstration of MFA mechanisms
"""

import pyotp
import qrcode
import io
import base64
import json
import time
from datetime import datetime
from typing import Dict, Optional, Tuple


class MFAStats:
    """
    Statistical tracker for MFA authentication attempts
    Logs success/failure rates, timing data, and desync events
    """

    def __init__(self):
        # Initialize statistics storage
        self.stats = {
            'totp': {
                'total_attempts': 0,
                'successful': 0,
                'failed': 0,
                'avg_verification_time': 0.0,
                'verification_times': []
            },
            'hotp': {
                'total_attempts': 0,
                'successful': 0,
                'failed': 0,
                'desync_events': 0,
                'counter_adjustments': 0,
                'avg_verification_time': 0.0,
                'verification_times': []
            }
        }

    def log_attempt(self, mfa_type: str, success: bool, verification_time: float,
                    desync: bool = False, counter_adjustment: int = 0):
        """
        Log an MFA authentication attempt

        Args:
            mfa_type: 'totp' or 'hotp'
            success: Whether authentication succeeded
            verification_time: Time taken to verify (in seconds)
            desync: Whether counter desynchronization occurred (HOTP only)
            counter_adjustment: How much counter was adjusted (HOTP only)
        """
        stats = self.stats[mfa_type]
        stats['total_attempts'] += 1

        if success:
            stats['successful'] += 1
        else:
            stats['failed'] += 1

        # Track verification timing
        stats['verification_times'].append(verification_time)
        stats['avg_verification_time'] = sum(stats['verification_times']) / len(stats['verification_times'])

        # HOTP-specific tracking
        if mfa_type == 'hotp':
            if desync:
                stats['desync_events'] += 1
            if counter_adjustment > 0:
                stats['counter_adjustments'] += 1

    def get_stats(self, mfa_type: Optional[str] = None) -> Dict:
        """
        Retrieve statistics for a specific MFA type or all types

        Args:
            mfa_type: 'totp', 'hotp', or None for all stats

        Returns:
            Dictionary containing statistics
        """
        if mfa_type:
            return self.stats[mfa_type]
        return self.stats

    def print_stats(self):
        """Print formatted statistics to console"""
        print("\n" + "="*60)
        print("MFA AUTHENTICATION STATISTICS")
        print("="*60)

        for mfa_type, data in self.stats.items():
            print(f"\n{mfa_type.upper()} Statistics:")
            print("-" * 40)
            print(f"  Total Attempts: {data['total_attempts']}")
            print(f"  Successful: {data['successful']}")
            print(f"  Failed: {data['failed']}")

            if data['total_attempts'] > 0:
                success_rate = (data['successful'] / data['total_attempts']) * 100
                print(f"  Success Rate: {success_rate:.2f}%")

            print(f"  Avg Verification Time: {data['avg_verification_time']:.6f}s")

            # HOTP-specific stats
            if mfa_type == 'hotp':
                print(f"  Desync Events: {data['desync_events']}")
                print(f"  Counter Adjustments: {data['counter_adjustments']}")

        print("="*60 + "\n")

    def save_to_file(self, filename: str = "mfa_stats.json"):
        """Save statistics to JSON file for later analysis"""
        with open(filename, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"Statistics saved to {filename}")


class TOTPManager:
    """
    TOTP (Time-based One-Time Password) Manager

    TOTP generates codes based on current time:
    - Code = HMAC-SHA1(secret, time_counter)
    - time_counter = floor(current_unix_time / 30)
    - Default validity: 30 seconds
    - Allows configurable time windows for clock drift
    """

    def __init__(self, stats_logger: MFAStats):
        """
        Initialize TOTP Manager

        Args:
            stats_logger: MFAStats instance for logging
        """
        self.stats_logger = stats_logger
        self.users = {}  # Store user TOTP secrets

    def generate_secret(self, username: str) -> str:
        """
        Generate a random secret key for a user

        The secret is base32-encoded random data that serves as the
        shared secret between server and authenticator app

        Args:
            username: Username to generate secret for

        Returns:
            Base32-encoded secret string
        """
        secret = pyotp.random_base32()
        self.users[username] = {
            'secret': secret,
            'enrolled_at': datetime.now().isoformat()
        }
        print(f"[TOTP] Generated secret for user: {username}")
        return secret

    def generate_qr_code(self, username: str, issuer: str = "Lab3-SecureApp") -> str:
        """
        Generate QR code for TOTP enrollment

        The QR code encodes a URI in the format:
        otpauth://totp/issuer:username?secret=SECRET&issuer=ISSUER

        Users scan this with Google Authenticator, Authy, etc.

        Args:
            username: Username for TOTP enrollment
            issuer: Application name shown in authenticator app

        Returns:
            Base64-encoded PNG image of QR code
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found. Generate secret first.")

        secret = self.users[username]['secret']

        # Create TOTP URI for authenticator apps
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64 for easy transmission/storage
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()

        # Also save to file
        filename = f"totp_qr_{username}.png"
        img.save(filename)
        print(f"[TOTP] QR code saved to {filename}")
        print(f"[TOTP] Provisioning URI: {provisioning_uri}")

        return img_str

    def verify_token(self, username: str, token: str,
                     valid_window: int = 1) -> Tuple[bool, float]:
        """
        Verify a TOTP token with configurable time window

        Time windows account for clock drift between server and client:
        - valid_window=0: Only accept current 30-second window
        - valid_window=1: Accept current + previous + next window (±30s)
        - valid_window=2: Accept ±60 seconds, etc.

        Args:
            username: Username to verify
            token: 6-digit TOTP code from authenticator
            valid_window: Number of time steps to accept before/after current

        Returns:
            Tuple of (success: bool, verification_time: float)
        """
        start_time = time.time()

        if username not in self.users:
            print(f"[TOTP] User {username} not enrolled")
            return False, 0.0

        secret = self.users[username]['secret']
        totp = pyotp.TOTP(secret)

        # Verify token within the specified time window
        # valid_window=1 means accept tokens from t-1, t, t+1
        is_valid = totp.verify(token, valid_window=valid_window)

        verification_time = time.time() - start_time

        # Log the attempt
        self.stats_logger.log_attempt('totp', is_valid, verification_time)

        if is_valid:
            print(f"[TOTP] ✓ Token verified for {username} (window: ±{valid_window})")
        else:
            print(f"[TOTP] ✗ Token verification failed for {username}")

        return is_valid, verification_time

    def get_current_token(self, username: str) -> str:
        """
        Get current TOTP token (for testing purposes)

        In production, this would only be on the client side.
        Included here for demonstration and testing.

        Args:
            username: Username to generate token for

        Returns:
            Current 6-digit TOTP code
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found")

        secret = self.users[username]['secret']
        totp = pyotp.TOTP(secret)
        return totp.now()

    def demo_time_window(self, username: str):
        """
        Demonstrate time window configuration
        Shows how different window sizes affect token acceptance
        """
        print("\n" + "="*60)
        print("TOTP TIME WINDOW DEMONSTRATION")
        print("="*60)

        current_token = self.get_current_token(username)
        print(f"Current token for {username}: {current_token}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Test different window sizes
        for window in [0, 1, 2]:
            print(f"\nTesting with valid_window={window}:")
            print(f"  (Accepts tokens from ±{window * 30} seconds)")
            result, timing = self.verify_token(username, current_token, valid_window=window)
            print(f"  Result: {'ACCEPTED' if result else 'REJECTED'}")
            print(f"  Verification time: {timing:.6f}s")


class HOTPManager:
    """
    HOTP (HMAC-based One-Time Password) Manager

    HOTP generates codes based on a counter:
    - Code = HMAC-SHA1(secret, counter)
    - Counter increments with each authentication
    - Must stay synchronized between client and server
    - Vulnerable to desynchronization attacks
    """

    def __init__(self, stats_logger: MFAStats):
        """
        Initialize HOTP Manager

        Args:
            stats_logger: MFAStats instance for logging
        """
        self.stats_logger = stats_logger
        self.users = {}  # Store user HOTP secrets and counters

    def generate_secret(self, username: str, initial_counter: int = 0) -> str:
        """
        Generate a random secret key for a user

        Args:
            username: Username to generate secret for
            initial_counter: Starting counter value (usually 0)

        Returns:
            Base32-encoded secret string
        """
        secret = pyotp.random_base32()
        self.users[username] = {
            'secret': secret,
            'counter': initial_counter,
            'enrolled_at': datetime.now().isoformat()
        }
        print(f"[HOTP] Generated secret for user: {username}")
        print(f"[HOTP] Initial counter: {initial_counter}")
        return secret

    def verify_token(self, username: str, token: str,
                     look_ahead_window: int = 3) -> Tuple[bool, float, int]:
        """
        Verify an HOTP token with counter resynchronization

        Look-ahead window helps recover from desynchronization:
        - If client counter gets ahead (e.g., user generates codes without using them)
        - Server checks next N counter values
        - If match found, server syncs to that counter

        Args:
            username: Username to verify
            token: 6-digit HOTP code
            look_ahead_window: How many counter values ahead to check

        Returns:
            Tuple of (success: bool, verification_time: float, counter_adjustment: int)
        """
        start_time = time.time()

        if username not in self.users:
            print(f"[HOTP] User {username} not enrolled")
            return False, 0.0, 0

        secret = self.users[username]['secret']
        current_counter = self.users[username]['counter']

        hotp = pyotp.HOTP(secret)

        # Try current counter first
        is_valid = False
        counter_adjustment = 0
        desync_detected = False

        # Check current counter and look-ahead window
        for offset in range(look_ahead_window + 1):
            test_counter = current_counter + offset
            expected_token = hotp.at(test_counter)

            if token == expected_token:
                is_valid = True
                counter_adjustment = offset

                # Update server counter to next expected value
                self.users[username]['counter'] = test_counter + 1

                if offset > 0:
                    desync_detected = True
                    print(f"[HOTP] ⚠ Desync detected! Counter adjusted by {offset}")
                    print(f"[HOTP] Old counter: {current_counter}, New counter: {test_counter + 1}")

                break

        verification_time = time.time() - start_time

        # Log the attempt
        self.stats_logger.log_attempt(
            'hotp',
            is_valid,
            verification_time,
            desync=desync_detected,
            counter_adjustment=counter_adjustment
        )

        if is_valid:
            print(f"[HOTP] ✓ Token verified for {username} (counter: {current_counter + counter_adjustment})")
        else:
            print(f"[HOTP] ✗ Token verification failed for {username}")
            print(f"[HOTP] Expected counter: {current_counter}")

        return is_valid, verification_time, counter_adjustment

    def get_current_token(self, username: str) -> str:
        """
        Get current HOTP token (for testing purposes)

        WARNING: This increments the client counter!
        Simulates user pressing "generate code" button.

        Args:
            username: Username to generate token for

        Returns:
            Current 6-digit HOTP code
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found")

        secret = self.users[username]['secret']
        counter = self.users[username]['counter']

        hotp = pyotp.HOTP(secret)
        token = hotp.at(counter)

        print(f"[HOTP] Generated token at counter {counter}: {token}")

        return token

    def simulate_desync(self, username: str, skip_count: int = 3):
        """
        Simulate counter desynchronization

        This happens when:
        - User generates codes without using them
        - Network issues cause missed authentications
        - Client device resets or reinstalls app

        Args:
            username: Username to desynchronize
            skip_count: How many counter values to skip
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found")

        old_counter = self.users[username]['counter']

        # Simulate user generating codes without submitting them
        print(f"\n[HOTP] Simulating desync: user generates {skip_count} codes...")
        for i in range(skip_count):
            token = self.get_current_token(username)
            # Increment counter on client side (but not server!)
            # In real scenario, server counter stays at old_counter
            # But client counter advances

        # Reset server counter to simulate the desync scenario
        print(f"[HOTP] Server counter still at: {old_counter}")
        print(f"[HOTP] Client counter now at: {old_counter + skip_count}")
        print(f"[HOTP] Desynchronization of {skip_count} steps created!")

    def demo_counter_desync(self, username: str):
        """
        Demonstrate counter desynchronization and recovery
        """
        print("\n" + "="*60)
        print("HOTP COUNTER DESYNCHRONIZATION DEMONSTRATION")
        print("="*60)

        # Get initial state
        initial_counter = self.users[username]['counter']
        print(f"\nInitial server counter: {initial_counter}")

        # Normal authentication
        print("\n1. Normal authentication (counters in sync):")
        token1 = self.get_current_token(username)
        self.users[username]['counter'] += 1  # Increment client counter
        result1, time1, adj1 = self.verify_token(username, token1)
        print(f"   Result: {'SUCCESS' if result1 else 'FAILED'}")

        # Create desynchronization
        print("\n2. Creating desynchronization:")
        print("   User generates 3 codes but doesn't submit them...")
        saved_counter = self.users[username]['counter']

        # User generates codes
        for i in range(3):
            token = self.get_current_token(username)
            self.users[username]['counter'] += 1
            print(f"   Generated (unused): {token}")

        # Reset server counter to simulate desync
        client_counter = self.users[username]['counter']
        self.users[username]['counter'] = saved_counter
        print(f"\n   Server counter: {saved_counter}")
        print(f"   Client counter: {client_counter}")
        print(f"   Desync: {client_counter - saved_counter} steps")

        # Try authentication with desynced token
        print("\n3. Authentication with desynced token:")
        hotp = pyotp.HOTP(self.users[username]['secret'])
        desynced_token = hotp.at(client_counter)
        print(f"   Client generates token at counter {client_counter}: {desynced_token}")

        result2, time2, adj2 = self.verify_token(username, desynced_token, look_ahead_window=5)
        print(f"   Result: {'SUCCESS (recovered)' if result2 else 'FAILED'}")
        print(f"   Counter adjustment: {adj2}")


def demo_mfa_complete():
    """
    Complete demonstration of TOTP and HOTP implementations
    Shows enrollment, authentication, stats tracking, and edge cases
    """
    print("\n" + "="*70)
    print("MULTI-FACTOR AUTHENTICATION (MFA) DEMONSTRATION")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    # Initialize stats logger
    stats = MFAStats()

    # ========== TOTP DEMONSTRATION ==========
    print("\n" + "="*70)
    print("PART 1: TOTP (Time-based One-Time Password)")
    print("="*70)

    totp_manager = TOTPManager(stats)

    # Enroll user
    print("\n1. User Enrollment:")
    secret = totp_manager.generate_secret("alice")
    print(f"   Secret: {secret}")

    # Generate QR code
    print("\n2. QR Code Generation:")
    qr_code = totp_manager.generate_qr_code("alice")
    print("   QR code generated and saved to file")
    print("   User scans QR with Google Authenticator or Authy")

    # Verify tokens
    print("\n3. Token Verification:")
    print("   Simulating authentication attempts...")

    # Successful verification
    current_token = totp_manager.get_current_token("alice")
    print(f"\n   User submits token: {current_token}")
    success, timing = totp_manager.verify_token("alice", current_token)

    # Failed verification (wrong token)
    print(f"\n   User submits wrong token: 000000")
    success, timing = totp_manager.verify_token("alice", "000000")

    # Demonstrate time window
    totp_manager.demo_time_window("alice")

    # ========== HOTP DEMONSTRATION ==========
    print("\n" + "="*70)
    print("PART 2: HOTP (HMAC-based One-Time Password)")
    print("="*70)

    hotp_manager = HOTPManager(stats)

    # Enroll user
    print("\n1. User Enrollment:")
    secret = hotp_manager.generate_secret("bob")
    print(f"   Secret: {secret}")

    # Normal authentication sequence
    print("\n2. Normal Authentication Sequence:")
    for i in range(3):
        token = hotp_manager.get_current_token("bob")
        hotp_manager.users["bob"]['counter'] += 1  # Increment client
        print(f"\n   Attempt {i+1}:")
        success, timing, adj = hotp_manager.verify_token("bob", token)

    # Demonstrate counter desync
    hotp_manager.demo_counter_desync("bob")

    # ========== STATISTICS ==========
    print("\n" + "="*70)
    print("PART 3: AUTHENTICATION STATISTICS")
    print("="*70)

    stats.print_stats()
    stats.save_to_file("mfa_stats.json")

    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)
    print("\nKey Findings:")
    print("✓ TOTP is time-based, codes expire every 30 seconds")
    print("✓ HOTP is counter-based, vulnerable to desynchronization")
    print("✓ Time windows in TOTP help with clock drift")
    print("✓ Look-ahead windows in HOTP help recover from desync")
    print("✓ Both use HMAC-SHA1 for cryptographic security")
    print("="*70 + "\n")


if __name__ == "__main__":
    # Run complete demonstration
    demo_mfa_complete()
