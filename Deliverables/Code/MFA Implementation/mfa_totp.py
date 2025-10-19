"""
TOTP (Time-based One-Time Password) Implementation
Person B - MFA Component
"""

import pyotp
import qrcode
import io
import base64
from datetime import datetime
import json
import os

class TOTPManager:
    def __init__(self, stats_file='totp_stats.json'):
        self.stats_file = stats_file
        self.stats = self.load_stats()
    
    def load_stats(self):
        """Load TOTP verification statistics"""
        if os.path.exists(self.stats_file):
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        return {
            'total_attempts': 0,
            'successful': 0,
            'failed': 0,
            'time_window_used': []
        }
    
    def save_stats(self):
        """Save TOTP verification statistics"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def generate_secret(self):
        """Generate a new TOTP secret for a user"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, username, secret, issuer='SecureAuthApp'):
        """
        Generate QR code for TOTP enrollment
        Returns: QR code image data (base64 encoded)
        """
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code to file
        qr_filename = f'qr_{username}_totp.png'
        img.save(qr_filename)
        
        # Convert to base64 for API response
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return {
            'qr_code': img_str,
            'qr_file': qr_filename,
            'secret': secret,
            'provisioning_uri': provisioning_uri
        }
    
    def verify_totp(self, secret, token, time_window=0):
        """
        Verify TOTP token with configurable time window
        
        Args:
            secret: User's TOTP secret
            token: Token to verify
            time_window: Number of time steps to check (±0, ±1, etc.)
                        0 = current time only
                        1 = current time ± 30 seconds
                        2 = current time ± 60 seconds
        
        Returns:
            dict with verification result and stats
        """
        totp = pyotp.TOTP(secret)
        
        # Verify with time window
        # valid_window parameter allows checking past/future intervals
        is_valid = totp.verify(token, valid_window=time_window)
        
        # Update statistics
        self.stats['total_attempts'] += 1
        if is_valid:
            self.stats['successful'] += 1
            self.stats['time_window_used'].append({
                'timestamp': datetime.now().isoformat(),
                'window': time_window,
                'status': 'success'
            })
        else:
            self.stats['failed'] += 1
            self.stats['time_window_used'].append({
                'timestamp': datetime.now().isoformat(),
                'window': time_window,
                'status': 'failed'
            })
        
        self.save_stats()
        
        return {
            'valid': is_valid,
            'timestamp': datetime.now().isoformat(),
            'time_window': time_window,
            'current_token': totp.now(),
            'stats': self.get_summary_stats()
        }
    
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
            'success_rate': f"{success_rate:.2f}%"
        }
    
    def demonstrate_time_windows(self, secret):
        """
        Demonstrate TOTP with different time windows
        """
        print("\n=== TOTP Time Window Demonstration ===")
        totp = pyotp.TOTP(secret)
        current_token = totp.now()
        
        print(f"Current Token: {current_token}")
        print(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Test with different windows
        windows = [0, 1, 2]
        for window in windows:
            result = self.verify_totp(secret, current_token, time_window=window)
            print(f"\nTime Window ±{window} (±{window*30}s):")
            print(f"  Valid: {result['valid']}")
            print(f"  Success Rate: {result['stats']['success_rate']}")


# Test and demonstration
if __name__ == "__main__":
    print("=== TOTP Implementation Test ===\n")
    
    manager = TOTPManager()
    
    # Enroll a test user
    username = "testuser1"
    secret = manager.generate_secret()
    
    print(f"1. User Enrollment")
    print(f"   Username: {username}")
    print(f"   Secret: {secret}")
    
    # Generate QR code
    qr_data = manager.generate_qr_code(username, secret)
    print(f"   QR Code saved to: {qr_data['qr_file']}")
    print(f"   Provisioning URI: {qr_data['provisioning_uri']}")
    
    # Generate current token
    totp = pyotp.TOTP(secret)
    current_token = totp.now()
    
    print(f"\n2. Token Verification")
    print(f"   Current Token: {current_token}")
    
    # Test with window=0 (exact time match)
    result = manager.verify_totp(secret, current_token, time_window=0)
    print(f"   Window ±0: Valid={result['valid']}")
    
    # Test with window=1 (±30 seconds)
    result = manager.verify_totp(secret, current_token, time_window=1)
    print(f"   Window ±1: Valid={result['valid']}")
    
    # Test invalid token
    print(f"\n3. Invalid Token Test")
    result = manager.verify_totp(secret, "000000", time_window=1)
    print(f"   Token: 000000")
    print(f"   Valid: {result['valid']}")
    
    # Display statistics
    print(f"\n4. Statistics Summary")
    stats = manager.get_summary_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n=== Test Complete ===")
