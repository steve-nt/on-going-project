"""
Password Cracking Demonstration
Implements dictionary and brute-force attacks against different hashing schemes
For educational purposes to demonstrate the importance of strong hashing algorithms
"""

import os
import time
import hashlib
import string
import itertools
import bcrypt
import argon2
from Crypto.Hash import SHA3_256

PEPPER = b'system_wide_secret_pepper_key_12345'

class PasswordCracker:
    def __init__(self, target_hash, salt, algorithm='sha256', use_pepper=False):
        self.target_hash = target_hash
        self.salt = salt
        self.algorithm = algorithm
        self.use_pepper = use_pepper
        self.attempts = 0
        self.start_time = None

    def hash_password_sha256(self, password):
        """Hash password using SHA-256"""
        pwd = password.encode('utf-8')
        if self.use_pepper:
            pwd = pwd + PEPPER
        return hashlib.sha256(self.salt + pwd).digest()

    def hash_password_sha3(self, password):
        """Hash password using SHA-3"""
        pwd = password.encode('utf-8')
        if self.use_pepper:
            pwd = pwd + PEPPER
        h = SHA3_256.new()
        h.update(self.salt + pwd)
        return h.digest()

    def hash_password_bcrypt(self, password):
        """Hash password using bcrypt"""
        pwd = password.encode('utf-8')
        if self.use_pepper:
            pwd = pwd + PEPPER
        try:
            return bcrypt.hashpw(pwd, self.salt)
        except:
            return None

    def hash_password_argon2(self, password):
        """Hash password using Argon2"""
        pwd = password.encode('utf-8')
        if self.use_pepper:
            pwd = pwd + PEPPER
        ph = argon2.PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16
        )
        try:
            return ph.hash(pwd).encode('utf-8')
        except:
            return None

    def hash_password(self, password):
        """Hash password using specified algorithm"""
        if self.algorithm == 'sha256':
            return self.hash_password_sha256(password)
        elif self.algorithm == 'sha3':
            return self.hash_password_sha3(password)
        elif self.algorithm == 'bcrypt':
            return self.hash_password_bcrypt(password)
        elif self.algorithm == 'argon2':
            return self.hash_password_argon2(password)
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")

    def verify_password(self, password):
        """Verify if password matches target hash"""
        self.attempts += 1

        if self.algorithm == 'bcrypt':
            pwd = password.encode('utf-8')
            if self.use_pepper:
                pwd = pwd + PEPPER
            try:
                return bcrypt.checkpw(pwd, self.target_hash)
            except:
                return False
        elif self.algorithm == 'argon2':
            pwd = password.encode('utf-8')
            if self.use_pepper:
                pwd = pwd + PEPPER
            ph = argon2.PasswordHasher()
            try:
                ph.verify(self.target_hash.decode('utf-8'), pwd)
                return True
            except:
                return False
        else:
            computed_hash = self.hash_password(password)
            return computed_hash == self.target_hash

    def dictionary_attack(self, dictionary_file='common_passwords.txt', max_passwords=None):
        """Perform dictionary attack"""
        print(f"\n{'='*60}")
        print(f"DICTIONARY ATTACK")
        print(f"Algorithm: {self.algorithm}")
        print(f"Pepper used: {self.use_pepper}")
        print(f"Dictionary file: {dictionary_file}")
        print(f"{'='*60}\n")

        self.start_time = time.time()
        self.attempts = 0

        try:
            with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_passwords and i >= max_passwords:
                        break

                    password = line.strip()
                    if not password:
                        continue

                    if self.verify_password(password):
                        elapsed_time = time.time() - self.start_time
                        print(f"[SUCCESS] Password cracked: '{password}'")
                        print(f"Attempts: {self.attempts}")
                        print(f"Time: {elapsed_time:.4f} seconds")
                        print(f"Rate: {self.attempts/elapsed_time:.2f} hashes/second")
                        return password

                    if self.attempts % 100 == 0:
                        elapsed_time = time.time() - self.start_time
                        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                        print(f"Progress: {self.attempts} attempts, {rate:.2f} hashes/sec", end='\r')

        except FileNotFoundError:
            print(f"[ERROR] Dictionary file not found: {dictionary_file}")
            return None

        elapsed_time = time.time() - self.start_time
        print(f"\n[FAILED] Password not found in dictionary")
        print(f"Total attempts: {self.attempts}")
        print(f"Time: {elapsed_time:.4f} seconds")
        return None

    def brute_force_attack(self, charset=string.ascii_lowercase, max_length=4):
        """Perform brute-force attack"""
        print(f"\n{'='*60}")
        print(f"BRUTE-FORCE ATTACK")
        print(f"Algorithm: {self.algorithm}")
        print(f"Pepper used: {self.use_pepper}")
        print(f"Charset: {charset}")
        print(f"Max length: {max_length}")
        print(f"{'='*60}\n")

        self.start_time = time.time()
        self.attempts = 0

        for length in range(1, max_length + 1):
            print(f"\nTrying length {length}...")
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)

                if self.verify_password(password):
                    elapsed_time = time.time() - self.start_time
                    print(f"\n[SUCCESS] Password cracked: '{password}'")
                    print(f"Attempts: {self.attempts}")
                    print(f"Time: {elapsed_time:.4f} seconds")
                    print(f"Rate: {self.attempts/elapsed_time:.2f} hashes/second")
                    return password

                if self.attempts % 1000 == 0:
                    elapsed_time = time.time() - self.start_time
                    rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                    print(f"Progress: {self.attempts} attempts, {rate:.2f} hashes/sec", end='\r')

        elapsed_time = time.time() - self.start_time
        print(f"\n[FAILED] Password not found")
        print(f"Total attempts: {self.attempts}")
        print(f"Time: {elapsed_time:.4f} seconds")
        return None

    def targeted_attack(self, passwords):
        """Try specific list of passwords"""
        print(f"\n{'='*60}")
        print(f"TARGETED ATTACK")
        print(f"Algorithm: {self.algorithm}")
        print(f"Pepper used: {self.use_pepper}")
        print(f"Passwords to try: {len(passwords)}")
        print(f"{'='*60}\n")

        self.start_time = time.time()
        self.attempts = 0

        for password in passwords:
            if self.verify_password(password):
                elapsed_time = time.time() - self.start_time
                print(f"[SUCCESS] Password cracked: '{password}'")
                print(f"Attempts: {self.attempts}")
                print(f"Time: {elapsed_time:.4f} seconds")
                print(f"Rate: {self.attempts/elapsed_time:.2f} hashes/second")
                return password

        elapsed_time = time.time() - self.start_time
        print(f"[FAILED] Password not found")
        print(f"Total attempts: {self.attempts}")
        print(f"Time: {elapsed_time:.4f} seconds")
        return None


def benchmark_hashing_algorithms():
    """Benchmark different hashing algorithms"""
    print(f"\n{'='*60}")
    print(f"HASHING ALGORITHM BENCHMARK")
    print(f"{'='*60}\n")

    password = "test_password_123"
    salt = os.urandom(32)
    iterations = 100

    algorithms = {
        'SHA-256': lambda: hashlib.sha256(salt + password.encode('utf-8')).digest(),
        'SHA-3': lambda: SHA3_256.new(salt + password.encode('utf-8')).digest(),
        'bcrypt': lambda: bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)),
        'Argon2': lambda: argon2.PasswordHasher().hash(password)
    }

    results = {}

    for name, hash_func in algorithms.items():
        print(f"Testing {name}...")
        start_time = time.time()

        for _ in range(iterations):
            hash_func()

        elapsed_time = time.time() - start_time
        avg_time = elapsed_time / iterations
        rate = iterations / elapsed_time

        results[name] = {
            'total_time': elapsed_time,
            'avg_time': avg_time,
            'rate': rate
        }

        print(f"  Total time: {elapsed_time:.4f}s")
        print(f"  Average time: {avg_time*1000:.2f}ms")
        print(f"  Rate: {rate:.2f} hashes/sec")
        print()

    return results


def compare_salt_pepper():
    """Compare cracking with and without pepper"""
    print(f"\n{'='*60}")
    print(f"SALT vs PEPPER COMPARISON")
    print(f"{'='*60}\n")

    password = "test123"
    salt = os.urandom(32)

    # Without pepper
    print("Cracking WITHOUT pepper (salt only):")
    hash_without_pepper = hashlib.sha256(salt + password.encode('utf-8')).digest()
    cracker1 = PasswordCracker(hash_without_pepper, salt, 'sha256', use_pepper=False)
    result1 = cracker1.targeted_attack(['password', 'admin', '123456', 'test123'])

    # With pepper
    print("\nCracking WITH pepper (salt + pepper):")
    pwd_with_pepper = password.encode('utf-8') + PEPPER
    hash_with_pepper = hashlib.sha256(salt + pwd_with_pepper).digest()
    cracker2 = PasswordCracker(hash_with_pepper, salt, 'sha256', use_pepper=True)
    result2 = cracker2.targeted_attack(['password', 'admin', '123456', 'test123'])

    print("\n" + "="*60)
    print("ANALYSIS:")
    print("- Without pepper: Attacker who gets DB can crack passwords")
    print("- With pepper: Attacker needs both DB AND pepper (server secret)")
    print("- Pepper adds defense-in-depth but must be kept secret")
    print("="*60)


def create_common_passwords_file():
    """Create a common passwords dictionary file"""
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football', 'welcome',
        'jesus', 'ninja', 'mustang', 'password1', '123456789',
        'test', 'admin', 'root', 'toor', 'pass',
        'test123', 'password123', 'admin123', 'root123', 'demo',
        'secret', 'hello', 'love', 'money', 'princess',
        'starwars', 'computer', 'whatever', 'dragon', 'charlie'
    ]

    with open('common_passwords.txt', 'w') as f:
        for pwd in common_passwords:
            f.write(pwd + '\n')

    print(f"Created common_passwords.txt with {len(common_passwords)} passwords")


if __name__ == '__main__':
    import sys

    # Create common passwords file
    create_common_passwords_file()

    print("\n" + "="*60)
    print("PASSWORD CRACKING DEMONSTRATION")
    print("Educational Lab - D7076E Security")
    print("="*60)

    # Benchmark algorithms
    print("\n[1] Benchmarking hashing algorithms...")
    benchmark_results = benchmark_hashing_algorithms()

    # Compare salt vs pepper
    print("\n[2] Comparing salt vs pepper...")
    compare_salt_pepper()

    # Example: Crack weak password with SHA-256
    print("\n[3] Cracking weak password (SHA-256)...")
    weak_password = "password"
    salt = os.urandom(32)
    weak_hash = hashlib.sha256(salt + weak_password.encode('utf-8')).digest()
    cracker = PasswordCracker(weak_hash, salt, 'sha256', use_pepper=False)
    cracker.dictionary_attack('common_passwords.txt')

    # Example: Brute force short password
    print("\n[4] Brute-force short password (SHA-256)...")
    short_password = "abc"
    short_hash = hashlib.sha256(salt + short_password.encode('utf-8')).digest()
    cracker = PasswordCracker(short_hash, salt, 'sha256', use_pepper=False)
    cracker.brute_force_attack(charset=string.ascii_lowercase, max_length=3)

    # Example: Try to crack bcrypt (will be slow)
    print("\n[5] Attempting to crack bcrypt password...")
    bcrypt_salt = bcrypt.gensalt(rounds=12)
    bcrypt_hash = bcrypt.hashpw(b"password", bcrypt_salt)
    cracker = PasswordCracker(bcrypt_hash, bcrypt_salt, 'bcrypt', use_pepper=False)
    cracker.dictionary_attack('common_passwords.txt', max_passwords=50)

    print("\n" + "="*60)
    print("KEY FINDINGS:")
    print("- SHA-256/SHA-3 are FAST: thousands of hashes/second")
    print("- bcrypt/Argon2 are SLOW: much fewer hashes/second")
    print("- Fast algorithms = easier to crack")
    print("- Use bcrypt or Argon2 for password hashing!")
    print("- Add salt (per-user) and pepper (system-wide)")
    print("="*60)
