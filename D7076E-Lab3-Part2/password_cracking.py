"""
Password Cracking Scripts for Person B - Lab 3
Educational demonstration of password cracking techniques

WARNING: For educational purposes only!
This demonstrates why strong password hashing is critical.

Attack Types:
1. Dictionary Attack: Try common passwords from a wordlist
2. Brute Force Attack: Try all possible character combinations

Hash Algorithms Tested:
- SHA-256: Fast, no salt/pepper protection
- SHA-3: Fast, modern but still vulnerable without salt
- bcrypt: Slow by design, resistant to brute force
- Argon2: Memory-hard, most resistant to GPU/ASIC attacks

Author: Person B
Purpose: Demonstrate importance of proper password hashing
"""

import hashlib
import bcrypt
import argon2
import time
import itertools
import string
from typing import List, Dict, Tuple, Optional
import json


class PasswordHasher:
    """
    Password hashing utility supporting multiple algorithms
    Used to create test hashes for cracking demonstrations
    """

    @staticmethod
    def hash_sha256(password: str, salt: str = "") -> str:
        """
        Hash password with SHA-256
        Fast but vulnerable to brute force without proper salt/pepper

        Args:
            password: Plain text password
            salt: Optional salt (should be random per user)

        Returns:
            Hexadecimal hash string
        """
        data = (salt + password).encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_sha3(password: str, salt: str = "") -> str:
        """
        Hash password with SHA3-256
        More modern than SHA-256 but still fast

        Args:
            password: Plain text password
            salt: Optional salt

        Returns:
            Hexadecimal hash string
        """
        data = (salt + password).encode('utf-8')
        return hashlib.sha3_256(data).hexdigest()

    @staticmethod
    def hash_bcrypt(password: str, rounds: int = 12) -> str:
        """
        Hash password with bcrypt
        Slow by design, includes salt automatically

        Args:
            password: Plain text password
            rounds: Work factor (4-31, default 12)

        Returns:
            bcrypt hash string (includes salt)
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password_bytes, salt).decode('utf-8')

    @staticmethod
    def hash_argon2(password: str, time_cost: int = 2,
                    memory_cost: int = 65536, parallelism: int = 1) -> str:
        """
        Hash password with Argon2
        Winner of Password Hashing Competition
        Memory-hard, resistant to GPU/ASIC attacks

        Args:
            password: Plain text password
            time_cost: Number of iterations (default 2)
            memory_cost: Memory in KiB (default 64MB)
            parallelism: Degree of parallelism (default 1)

        Returns:
            Argon2 hash string (includes salt and parameters)
        """
        ph = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism
        )
        return ph.hash(password)

    @staticmethod
    def verify_bcrypt(password: str, hash_str: str) -> bool:
        """Verify password against bcrypt hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))

    @staticmethod
    def verify_argon2(password: str, hash_str: str) -> bool:
        """Verify password against Argon2 hash"""
        ph = argon2.PasswordHasher()
        try:
            ph.verify(hash_str, password)
            return True
        except:
            return False


class DictionaryAttack:
    """
    Dictionary attack implementation
    Tries passwords from a wordlist (most common passwords, leaked passwords, etc.)

    Why it works:
    - Many users choose common passwords
    - Even with salting, dictionary attacks can crack weak passwords
    - Much faster than brute force
    """

    def __init__(self):
        # Common passwords from real-world data breaches
        # Source: Most common passwords from various security reports
        self.common_passwords = [
            "password", "123456", "123456789", "12345678", "12345",
            "qwerty", "abc123", "password1", "111111", "1234567890",
            "123123", "000000", "1234567", "password123", "admin",
            "letmein", "welcome", "monkey", "dragon", "master",
            "sunshine", "princess", "football", "qwertyuiop", "login",
            "starwars", "shadow", "baseball", "superman", "michael",
            "hello", "bailey", "charlie", "hunter", "trustno1",
            "summer", "access", "iloveyou", "batman", "test",
            # Add more realistic passwords
            "password!", "Password1", "Welcome1", "Admin123",
            "P@ssw0rd", "letmein123", "qwerty123", "test123"
        ]

        self.stats = {
            'attempts': 0,
            'time_taken': 0.0,
            'passwords_tested': 0
        }

    def load_wordlist(self, filename: str) -> List[str]:
        """
        Load passwords from a wordlist file

        Args:
            filename: Path to wordlist file

        Returns:
            List of passwords
        """
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[Dictionary] Wordlist not found: {filename}")
            print(f"[Dictionary] Using built-in common passwords instead")
            return self.common_passwords

    def attack_sha256(self, target_hash: str, salt: str = "",
                      wordlist: Optional[List[str]] = None) -> Tuple[Optional[str], float]:
        """
        Perform dictionary attack on SHA-256 hash

        Args:
            target_hash: Hash to crack
            salt: Salt used in hashing
            wordlist: List of passwords to try (None = use common passwords)

        Returns:
            Tuple of (cracked_password or None, time_taken)
        """
        if wordlist is None:
            wordlist = self.common_passwords

        print(f"\n[Dictionary] Starting SHA-256 attack...")
        print(f"[Dictionary] Target hash: {target_hash[:32]}...")
        print(f"[Dictionary] Testing {len(wordlist)} passwords...")

        start_time = time.time()
        attempts = 0

        for password in wordlist:
            attempts += 1

            # Hash the candidate password
            candidate_hash = PasswordHasher.hash_sha256(password, salt)

            if candidate_hash == target_hash:
                time_taken = time.time() - start_time
                print(f"\n[Dictionary] ✓ PASSWORD CRACKED!")
                print(f"[Dictionary] Password: {password}")
                print(f"[Dictionary] Attempts: {attempts}")
                print(f"[Dictionary] Time: {time_taken:.4f} seconds")
                print(f"[Dictionary] Rate: {attempts/time_taken:.2f} passwords/second")
                return password, time_taken

        time_taken = time.time() - start_time
        print(f"\n[Dictionary] ✗ Password not found in wordlist")
        print(f"[Dictionary] Attempts: {attempts}")
        print(f"[Dictionary] Time: {time_taken:.4f} seconds")
        return None, time_taken

    def attack_bcrypt(self, target_hash: str,
                      wordlist: Optional[List[str]] = None) -> Tuple[Optional[str], float]:
        """
        Perform dictionary attack on bcrypt hash

        Note: bcrypt is MUCH slower to crack due to work factor
        This demonstrates the importance of slow hashing algorithms

        Args:
            target_hash: bcrypt hash to crack
            wordlist: List of passwords to try

        Returns:
            Tuple of (cracked_password or None, time_taken)
        """
        if wordlist is None:
            wordlist = self.common_passwords

        print(f"\n[Dictionary] Starting bcrypt attack...")
        print(f"[Dictionary] Note: bcrypt is intentionally slow!")
        print(f"[Dictionary] Testing {len(wordlist)} passwords...")

        start_time = time.time()
        attempts = 0

        for password in wordlist:
            attempts += 1

            # Show progress every 10 attempts (bcrypt is slow)
            if attempts % 10 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"[Dictionary] Progress: {attempts}/{len(wordlist)} ({rate:.2f} p/s)")

            # Check password
            if PasswordHasher.verify_bcrypt(password, target_hash):
                time_taken = time.time() - start_time
                print(f"\n[Dictionary] ✓ PASSWORD CRACKED!")
                print(f"[Dictionary] Password: {password}")
                print(f"[Dictionary] Attempts: {attempts}")
                print(f"[Dictionary] Time: {time_taken:.4f} seconds")
                print(f"[Dictionary] Rate: {attempts/time_taken:.2f} passwords/second")
                return password, time_taken

        time_taken = time.time() - start_time
        print(f"\n[Dictionary] ✗ Password not found in wordlist")
        print(f"[Dictionary] Attempts: {attempts}")
        print(f"[Dictionary] Time: {time_taken:.4f} seconds")
        return None, time_taken


class BruteForceAttack:
    """
    Brute force attack implementation
    Tries all possible combinations of characters

    Why it's challenging:
    - Exponential growth: 62^8 = 218 trillion for 8 char alphanumeric
    - Time increases dramatically with password length
    - Slow hashing algorithms make it impractical
    """

    def __init__(self):
        # Character sets for brute force
        self.charset_digits = string.digits  # 0-9
        self.charset_lowercase = string.ascii_lowercase  # a-z
        self.charset_uppercase = string.ascii_uppercase  # A-Z
        self.charset_alphanumeric = self.charset_digits + self.charset_lowercase + self.charset_uppercase
        self.charset_special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        self.charset_all = self.charset_alphanumeric + self.charset_special

    def generate_candidates(self, charset: str, max_length: int):
        """
        Generate all possible password combinations

        Args:
            charset: Character set to use
            max_length: Maximum password length to try

        Yields:
            Password candidates
        """
        for length in range(1, max_length + 1):
            for combination in itertools.product(charset, repeat=length):
                yield ''.join(combination)

    def attack_sha256(self, target_hash: str, salt: str = "",
                      max_length: int = 4, charset: str = None) -> Tuple[Optional[str], float, int]:
        """
        Perform brute force attack on SHA-256 hash

        WARNING: Even with fast SHA-256, this becomes impractical quickly!
        - Length 4, digits only (10^4): ~10,000 combinations
        - Length 6, alphanumeric (62^6): ~56 billion combinations
        - Length 8, alphanumeric (62^8): ~218 trillion combinations

        Args:
            target_hash: Hash to crack
            salt: Salt used in hashing
            max_length: Maximum password length (keep small for demo!)
            charset: Characters to try (None = digits only)

        Returns:
            Tuple of (cracked_password or None, time_taken, attempts)
        """
        if charset is None:
            charset = self.charset_digits  # Default to digits only

        print(f"\n[BruteForce] Starting SHA-256 attack...")
        print(f"[BruteForce] Target hash: {target_hash[:32]}...")
        print(f"[BruteForce] Max length: {max_length}")
        print(f"[BruteForce] Charset: {len(charset)} characters")

        # Calculate total combinations
        total_combinations = sum(len(charset)**i for i in range(1, max_length + 1))
        print(f"[BruteForce] Total combinations to try: {total_combinations:,}")

        start_time = time.time()
        attempts = 0
        last_progress = 0

        for password in self.generate_candidates(charset, max_length):
            attempts += 1

            # Progress updates
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                progress = (attempts / total_combinations) * 100
                if progress - last_progress >= 5:  # Update every 5%
                    print(f"[BruteForce] Progress: {progress:.1f}% ({attempts:,}/{total_combinations:,}) - {rate:.0f} p/s")
                    last_progress = progress

            # Hash and check
            candidate_hash = PasswordHasher.hash_sha256(password, salt)

            if candidate_hash == target_hash:
                time_taken = time.time() - start_time
                print(f"\n[BruteForce] ✓ PASSWORD CRACKED!")
                print(f"[BruteForce] Password: {password}")
                print(f"[BruteForce] Attempts: {attempts:,}")
                print(f"[BruteForce] Time: {time_taken:.4f} seconds")
                print(f"[BruteForce] Rate: {attempts/time_taken:.0f} passwords/second")
                return password, time_taken, attempts

        time_taken = time.time() - start_time
        print(f"\n[BruteForce] ✗ Password not found")
        print(f"[BruteForce] Attempts: {attempts:,}")
        print(f"[BruteForce] Time: {time_taken:.4f} seconds")
        return None, time_taken, attempts

    def estimate_time(self, password_length: int, charset_size: int, hashes_per_second: float):
        """
        Estimate time to crack password of given length

        Args:
            password_length: Length of password
            charset_size: Size of character set
            hashes_per_second: Hash rate (hashes/second)

        Returns:
            Dictionary with time estimates
        """
        total_combinations = charset_size ** password_length
        avg_attempts = total_combinations / 2  # Average case: find in middle

        seconds = avg_attempts / hashes_per_second
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        years = days / 365

        return {
            'total_combinations': total_combinations,
            'avg_attempts': avg_attempts,
            'seconds': seconds,
            'minutes': minutes,
            'hours': hours,
            'days': days,
            'years': years
        }


class CrackingBenchmark:
    """
    Benchmark different hashing algorithms
    Demonstrates time-to-crack under various scenarios
    """

    def __init__(self):
        self.results = []

    def benchmark_hash_speed(self, algorithm: str, iterations: int = 1000):
        """
        Measure hashing speed for different algorithms

        Args:
            algorithm: Algorithm to benchmark
            iterations: Number of hashes to perform
        """
        print(f"\n[Benchmark] Testing {algorithm} speed...")
        print(f"[Benchmark] Iterations: {iterations}")

        test_password = "TestPassword123"

        start_time = time.time()

        if algorithm == "sha256":
            for _ in range(iterations):
                PasswordHasher.hash_sha256(test_password)
        elif algorithm == "sha3":
            for _ in range(iterations):
                PasswordHasher.hash_sha3(test_password)
        elif algorithm == "bcrypt":
            for _ in range(iterations):
                PasswordHasher.hash_bcrypt(test_password, rounds=10)
        elif algorithm == "argon2":
            for _ in range(iterations):
                PasswordHasher.hash_argon2(test_password, time_cost=1, memory_cost=8192)

        time_taken = time.time() - start_time
        hashes_per_second = iterations / time_taken

        print(f"[Benchmark] Time: {time_taken:.4f} seconds")
        print(f"[Benchmark] Rate: {hashes_per_second:.2f} hashes/second")

        return hashes_per_second

    def compare_algorithms(self):
        """
        Compare cracking difficulty across different hash algorithms
        """
        print("\n" + "="*70)
        print("HASH ALGORITHM COMPARISON")
        print("="*70)

        algorithms = [
            ("SHA-256", "sha256"),
            ("SHA-3", "sha3"),
            ("bcrypt (rounds=10)", "bcrypt"),
            ("Argon2", "argon2")
        ]

        results = []

        for name, algo in algorithms:
            rate = self.benchmark_hash_speed(algo, iterations=100 if algo in ["bcrypt", "argon2"] else 1000)
            results.append((name, rate))

        print("\n" + "="*70)
        print("CRACKING TIME ESTIMATES")
        print("="*70)
        print("\nAssumptions:")
        print("- 8 character password")
        print("- Alphanumeric charset (62 characters)")
        print("- Average case: find password at 50% of search space")
        print()

        bf = BruteForceAttack()

        for name, rate in results:
            print(f"\n{name}:")
            print(f"  Hash rate: {rate:.2f} hashes/second")

            estimate = bf.estimate_time(8, 62, rate)

            if estimate['years'] > 1:
                print(f"  Time to crack: {estimate['years']:.2e} years")
            elif estimate['days'] > 1:
                print(f"  Time to crack: {estimate['days']:.2e} days")
            elif estimate['hours'] > 1:
                print(f"  Time to crack: {estimate['hours']:.2f} hours")
            elif estimate['minutes'] > 1:
                print(f"  Time to crack: {estimate['minutes']:.2f} minutes")
            else:
                print(f"  Time to crack: {estimate['seconds']:.2f} seconds")


def demo_password_cracking():
    """
    Complete demonstration of password cracking techniques
    """
    print("\n" + "="*70)
    print("PASSWORD CRACKING DEMONSTRATION")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    print("\nWARNING: For educational purposes only!")
    print("This demonstrates why proper password hashing is critical.\n")

    # ========== SETUP TEST CASES ==========
    print("="*70)
    print("SETUP: Creating test password hashes")
    print("="*70)

    test_passwords = {
        'weak': 'password',      # Common dictionary word
        'medium': '123456',      # Very common numeric
        'short': 'test',         # Short brute-forceable
        'digits': '9876'         # 4 digit PIN
    }

    # Create hashes
    hashes = {}
    for name, pwd in test_passwords.items():
        hashes[name] = {
            'password': pwd,
            'sha256': PasswordHasher.hash_sha256(pwd),
            'bcrypt': PasswordHasher.hash_bcrypt(pwd, rounds=10)
        }
        print(f"\n{name.upper()}: '{pwd}'")
        print(f"  SHA-256: {hashes[name]['sha256'][:32]}...")

    # ========== DICTIONARY ATTACK ==========
    print("\n" + "="*70)
    print("PART 1: DICTIONARY ATTACK")
    print("="*70)

    dict_attacker = DictionaryAttack()

    print("\nTest 1a: Dictionary attack on weak SHA-256 password")
    result, time_taken = dict_attacker.attack_sha256(hashes['weak']['sha256'])

    print("\nTest 1b: Dictionary attack on weak bcrypt password")
    print("Note: This will be MUCH slower due to bcrypt's work factor")
    result, time_taken = dict_attacker.attack_bcrypt(hashes['weak']['bcrypt'])

    # ========== BRUTE FORCE ATTACK ==========
    print("\n" + "="*70)
    print("PART 2: BRUTE FORCE ATTACK")
    print("="*70)

    brute_attacker = BruteForceAttack()

    print("\nTest 2a: Brute force 4-digit PIN (SHA-256)")
    result, time_taken, attempts = brute_attacker.attack_sha256(
        hashes['digits']['sha256'],
        max_length=4,
        charset=brute_attacker.charset_digits
    )

    print("\nTest 2b: Brute force short password (SHA-256)")
    print("Trying all lowercase letters, up to 4 characters")
    result, time_taken, attempts = brute_attacker.attack_sha256(
        hashes['short']['sha256'],
        max_length=4,
        charset=brute_attacker.charset_lowercase
    )

    # ========== ALGORITHM COMPARISON ==========
    print("\n" + "="*70)
    print("PART 3: HASH ALGORITHM COMPARISON")
    print("="*70)

    benchmark = CrackingBenchmark()
    benchmark.compare_algorithms()

    # ========== KEY FINDINGS ==========
    print("\n" + "="*70)
    print("KEY FINDINGS & RECOMMENDATIONS")
    print("="*70)

    findings = [
        ("SHA-256/SHA-3", "Fast hashing = Fast cracking", "Add proper salt + pepper, or use bcrypt/Argon2"),
        ("bcrypt", "Slow by design, configurable work factor", "Good choice, increase rounds over time"),
        ("Argon2", "Memory-hard, resistant to GPU/ASIC", "Best choice for new systems"),
        ("Dictionary Attacks", "Effective against common passwords", "Enforce strong password policies"),
        ("Brute Force", "Exponential with length", "Require minimum 12+ character passwords"),
        ("Salt", "Prevents rainbow table attacks", "Always use unique salt per user"),
        ("Pepper", "Secret key adds extra protection", "Store separately from database"),
    ]

    for topic, finding, recommendation in findings:
        print(f"\n{topic}:")
        print(f"  Finding: {finding}")
        print(f"  Recommendation: {recommendation}")

    # Save results
    results = {
        'test_cases': test_passwords,
        'findings': 'See output above',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }

    with open('cracking_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("\n" + "="*70)
    print("Results saved to: cracking_results.json")
    print("="*70 + "\n")


if __name__ == "__main__":
    demo_password_cracking()
