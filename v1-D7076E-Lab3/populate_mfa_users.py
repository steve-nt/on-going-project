#!/usr/bin/env python3
"""
Helper Script to Add MFA Users to Database
This directly modifies users.db to add test users with MFA enabled
"""

import sqlite3
import secrets
import bcrypt
import pyotp

PEPPER = b"system_pepper_secret_key"

def add_mfa_user(username, password, mfa_type='totp'):
    """
    Add a user with MFA enabled directly to database
    
    Args:
        username: Username
        password: Password
        mfa_type: 'totp' or 'hotp'
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Generate bcrypt hash
    password_hash = bcrypt.hashpw(password.encode() + PEPPER, bcrypt.gensalt(rounds=8))
    
    # Generate MFA secret
    if mfa_type == 'totp':
        totp_secret = pyotp.random_base32()
        hotp_secret = None
        hotp_counter = 0
        print(f"TOTP Secret: {totp_secret}")
        
        # Generate QR code
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name='SecureAuthApp'
        )
        print(f"Provisioning URI: {provisioning_uri}")
        
        # Save QR code
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            qr_filename = f'qr_{username}_totp.png'
            img.save(qr_filename)
            print(f"QR Code saved: {qr_filename}")
        except ImportError:
            print("QRCode library not available, skipping QR generation")
    
    elif mfa_type == 'hotp':
        totp_secret = None
        hotp_secret = pyotp.random_base32()
        hotp_counter = 0
        print(f"HOTP Secret: {hotp_secret}")
    
    else:
        print(f"Unknown MFA type: {mfa_type}")
        conn.close()
        return False
    
    # Insert or update user
    try:
        c.execute("""
            INSERT INTO users (username, salt, hash, hash_type, mfa_enabled, mfa_type, 
                             totp_secret, hotp_secret, hotp_counter)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, b'', password_hash, 'bcrypt', 1, mfa_type, 
              totp_secret, hotp_secret, hotp_counter))
        print(f"✓ User '{username}' created with {mfa_type.upper()} MFA")
    except sqlite3.IntegrityError:
        # User exists, update instead
        c.execute("""
            UPDATE users 
            SET mfa_enabled=1, mfa_type=?, totp_secret=?, hotp_secret=?, hotp_counter=?
            WHERE username=?
        """, (mfa_type, totp_secret, hotp_secret, hotp_counter, username))
        print(f"✓ User '{username}' updated with {mfa_type.upper()} MFA")
    
    conn.commit()
    conn.close()
    return True


def show_database_users():
    """Display all users in database"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    print("\n" + "="*70)
    print("Current Database Users:")
    print("="*70)
    
    c.execute("SELECT username, hash_type, mfa_enabled, mfa_type FROM users")
    users = c.fetchall()
    
    if not users:
        print("No users in database")
    else:
        for user in users:
            username, hash_type, mfa_enabled, mfa_type = user
            mfa_status = f"{mfa_type.upper()}" if mfa_enabled else "Disabled"
            print(f"  {username:20s} | Hash: {hash_type:8s} | MFA: {mfa_status}")
    
    conn.close()
    print("="*70 + "\n")


if __name__ == "__main__":
    print("=== MFA User Database Populator ===\n")
    
    # Check if database exists and has correct schema
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not c.fetchone():
            print("ERROR: users table doesn't exist!")
            print("Run PersonB-integrated_app.py first to initialize database.")
            conn.close()
            exit(1)
        conn.close()
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
    
    # Show existing users
    show_database_users()
    
    # Add test users with MFA
    print("Adding test users with MFA...\n")
    
    # Add TOTP user
    print("1. Creating TOTP user:")
    print("-" * 70)
    add_mfa_user("totp_user", "password123", "totp")
    print()
    
    # Add HOTP user
    print("2. Creating HOTP user:")
    print("-" * 70)
    add_mfa_user("hotp_user", "password123", "hotp")
    print()
    
    # Add another TOTP user
    print("3. Creating second TOTP user:")
    print("-" * 70)
    add_mfa_user("alice_mfa", "secure_pass", "totp")
    print()
    
    # Show updated database
    show_database_users()
    
    print("✓ Database population complete!")
    print("\nTo test these users:")
    print("1. Start: python3 PersonB-integrated_app.py")
    print("2. Login with username and password")
    print("3. Use generated TOTP secret with authenticator app")
    print("4. Or generate token: python3 -c \"import pyotp; print(pyotp.TOTP('SECRET').now())\"")
