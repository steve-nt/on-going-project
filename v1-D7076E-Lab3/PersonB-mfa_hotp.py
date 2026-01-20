"""
HOTP (HMAC-based One-Time Password) Implementation
Person B - MFA Component with Counter Desync Demonstration
"""

import pyotp
import json
import os
from datetime import datetime

class HOTPManager:
    def __init__(self, stats_file='hotp_stats.json'):
        self.stats_file = stats_file
        self.stats = self.load_stats()
        self.user_counters = {}  # Track counter per user
    
    def load_stats(self):
        """Load HOTP verification statistics"""
        if os.path.exists(self.stats_file):
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        return {
            'total_attempts': 0,
            'successful': 0,
            'failed': 0,
            'desync_events': 0,
            'verification_history': []
        }
    
    def save_stats(self):
        """Save HOTP verification statistics"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def generate_secret(self):
        """Generate a new HOTP secret"""
        return pyotp.random_base32()
    
    def enroll_user(self, username, secret=None):
        """
        Enroll a user with HOTP
        Returns secret and initial counter
        """
        if secret is None:
            secret = self.generate_secret()
        
        # Initialize counter at 0
        self.user_counters[username] = 0
        
        return {
            'username': username,
            'secret': secret,
            'counter': 0,
            'hotp': pyotp.HOTP(secret)
        }
    
    def generate_token(self, secret, counter):
        """Generate HOTP token for given counter"""
        hotp = pyotp.HOTP(secret)
        return hotp.at(counter)
    
    def verify_hotp(self, username, secret, token, allow_resync=True, resync_window=10):
        """
        Verify HOTP token with counter desync handling
        
        Args:
            username: Username for counter tracking
            secret: User's HOTP secret
            token: Token to verify
            allow_resync: Allow counter resynchronization
            resync_window: How many counters ahead to check
        
        Returns:
            dict with verification result and counter info
        """
        hotp = pyotp.HOTP(secret)
        
        # Get current counter for user
        if username not in self.user_counters:
            self.user_counters[username] = 0
        
        current_counter = self.user_counters[username]
        verified = False
        new_counter = current_counter
        desync_detected = False
        
        # Try current counter first
        if hotp.verify(token, current_counter):
            verified = True
            new_counter = current_counter + 1
        elif allow_resync:
            # Try look-ahead window to handle desync
            for offset in range(1, resync_window + 1):
                if hotp.verify(token, current_counter + offset):
                    verified = True
                    new_counter = current_counter + offset + 1
                    desync_detected = True
                    self.stats['desync_events'] += 1
                    break
        
        # Update counter on success
        if verified:
            self.user_counters[username] = new_counter
            self.stats['successful'] += 1
        else:
            self.stats['failed'] += 1
        
        self.stats['total_attempts'] += 1
        
        # Log verification attempt
        self.stats['verification_history'].append({
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'counter_before': current_counter,
            'counter_after': new_counter,
            'verified': verified,
            'desync_detected': desync_detected
        })
        
        self.save_stats()
        
        return {
            'valid': verified,
            'counter_before': current_counter,
            'counter_after': new_counter,
            'desync_detected': desync_detected,
            'timestamp': datetime.now().isoformat()
        }
    
    def demonstrate_counter_desync(self, username, secret):
        """
        Demonstrate counter desynchronization scenario
        """
        print("\n=== HOTP Counter Desync Demonstration ===\n")
        
        # Initialize user
        self.user_counters[username] = 0
        hotp = pyotp.HOTP(secret)
        
        print("Scenario 1: Normal Operation")
        print("-" * 50)
        for i in range(3):
            token = hotp.at(self.user_counters[username])
            print(f"Counter {self.user_counters[username]}: Token = {token}")
            result = self.verify_hotp(username, secret, token)
            print(f"  Verification: {result['valid']}, New Counter: {result['counter_after']}")
        
        print("\nScenario 2: User Generates Token but Doesn't Submit")
        print("-" * 50)
        # User generates tokens but doesn't use them (simulating accidental generation)
        skipped_tokens = []
        for i in range(3):
            token = hotp.at(self.user_counters[username] + i)
            skipped_tokens.append(token)
            print(f"Counter {self.user_counters[username] + i}: Generated Token = {token} (not submitted)")
        
        print("\nScenario 3: User Submits Next Token (Desync)")
        print("-" * 50)
        # Now user submits the next token
        next_counter = self.user_counters[username] + 3
        token = hotp.at(next_counter)
        print(f"Counter {next_counter}: Token = {token}")
        print(f"Server Counter: {self.user_counters[username]}")
        
        result = self.verify_hotp(username, secret, token, allow_resync=True, resync_window=10)
        print(f"  Verification: {result['valid']}")
        print(f"  Desync Detected: {result['desync_detected']}")
        print(f"  Counter adjusted from {result['counter_before']} to {result['counter_after']}")
        
        print("\nScenario 4: Continue Normal Operation After Resync")
        print("-" * 50)
        for i in range(2):
            token = hotp.at(self.user_counters[username])
            print(f"Counter {self.user_counters[username]}: Token = {token}")
            result = self.verify_hotp(username, secret, token)
            print(f"  Verification: {result['valid']}, New Counter: {result['counter_after']}")
    
    def get_summary_stats(self):
        """Get summary statistics"""
        total = self.stats['total_attempts']
        if total == 0:
            success_rate = 0
        else:
            success_rate = (self.stats['successful'] / total) * 100
        
        return {
            'total_attempts': total,
            'successful': self.stats['successful'],
            'failed': self.stats['failed'],
            'desync_events': self.stats['desync_events'],
            'success_rate': f"{success_rate:.2f}%"
        }


# Test and demonstration
if __name__ == "__main__":
    print("=== HOTP Implementation Test ===\n")
    
    manager = HOTPManager()
    
    # Enroll test user
    username = "hotp_testuser"
    secret = manager.generate_secret()
    
    print(f"1. User Enrollment")
    print(f"   Username: {username}")
    print(f"   Secret: {secret}")
    print(f"   Initial Counter: 0")
    
    enrollment = manager.enroll_user(username, secret)
    
    # Demonstrate counter desync
    manager.demonstrate_counter_desync(username, secret)
    
    # Display statistics
    print("\n=== Final Statistics ===")
    stats = manager.get_summary_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n=== Test Complete ===")
