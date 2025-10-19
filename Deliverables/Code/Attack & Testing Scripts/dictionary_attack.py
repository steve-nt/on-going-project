"""
Dictionary and Brute-Force Password Attack 
"""

import hashlib
import bcrypt
from argon2 import PasswordHasher as Argon2PasswordHasher
import time
import itertools
import string
from datetime import datetime

class PasswordCracker:
    def __init__(self, pepper=b"system_pepper_secret_key"):
        self.pepper = pepper
        self.results = []
    
    def load_dictionary(self, filename='common_passwords.txt'):
        """
        Load password dictionary from file
        Returns list of common passwords
        """
        # Common passwords for demonstration
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'welcome',
            'jesus', 'ninja', 'mustang', 'password1', 'admin'
        ]
        
        try:
            with open(filename, 'r') as f:
                loaded = [line.strip() for line in f if line.strip()]
                if loaded:
                    return loaded
        except FileNotFoundError:
            pass
        
        return common_passwords
    
    def dictionary_attack_sha256(self, target_hash, salt, dictionary, rounds=100):
        """
        Dictionary attack against SHA-256 hash
        
        Args:
            target_hash: Hash to crack
            salt: Salt used in hashing
            dictionary: List of passwords to try
            rounds: Number of hash iterations
        
        Returns:
            dict with results
        """
        start_time = time.time()
        attempts = 0
        
        for password in dictionary:
            attempts += 1
            
            # Compute hash
            test_hash = password.encode() + salt + self.pepper
            for _ in range(rounds):
                test_hash = hashlib.sha256(test_hash).digest()
            
            if test_hash == target_hash:
                elapsed = time.time() - start_time
                result = {
                    'success': True,
                    'password': password,
                    'attempts': attempts,
                    'time_seconds': elapsed,
                    'rate': attempts / elapsed if elapsed > 0 else 0,
                    'method': 'dictionary',
                    'algorithm': 'sha256'
                }
                self.results.append(result)
                return result
        
        elapsed = time.time() - start_time
        result = {
            'success': False,
            'password': None,
            'attempts': attempts,
            'time_seconds': elapsed,
            'rate': attempts / elapsed if elapsed > 0 else 0,
            'method': 'dictionary',
            'algorithm': 'sha256'
        }
        self.results.append(result)
        return result
    
    def brute_force_attack(self, target_hash, salt, max_length=4, 
                          charset=None, hash_type='sha256', rounds=100):
        """
        Brute-force attack with configurable character set
        
        Args:
            target_hash: Hash to crack
            salt: Salt used
            max_length: Maximum password length to try
            charset: Character set (default: lowercase + digits)
            hash_type: Hash algorithm used
            rounds: Iteration rounds
        
        Returns:
            dict with results
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        start_time = time.time()
        attempts = 0
        
        for length in range(1, max_length + 1):
            for candidate_tuple in itertools.product(charset, repeat=length):
                password = ''.join(candidate_tuple)
                attempts += 1
                
                # Compute hash based on type
                if hash_type == 'sha256':
                    test_hash = password.encode() + salt + self.pepper
                    for _ in range(rounds):
                        test_hash = hashlib.sha256(test_hash).digest()
                else:
                    continue  # Only SHA-256 for brute force demo
                
                if test_hash == target_hash:
                    elapsed = time.time() - start_time
                    result = {
                        'success': True,
                        'password': password,
                        'attempts': attempts,
                        'time_seconds': elapsed,
                        'rate': attempts / elapsed if elapsed > 0 else 0,
                        'method': 'brute_force',
                        'algorithm': hash_type,
                        'charset_size': len(charset),
                        'max_length': max_length
                    }
                    self.results.append(result)
                    return result
                
                # Progress indicator
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"  Attempts: {attempts}, Elapsed: {elapsed:.2f}s, Rate: {attempts/elapsed:.2f}/s")
        
        elapsed = time.time() - start_time
        result = {
            'success': False,
            'password': None,
            'attempts': attempts,
            'time_seconds': elapsed,
            'rate': attempts / elapsed if elapsed > 0 else 0,
            'method': 'brute_force',
            'algorithm': hash_type
        }
        self.results.append(result)
        return result
    
    def compare_hash_algorithms(self, password, salt):
        """
        Compare time-to-crack for different hash algorithms
        
        Returns:
            dict with timing comparisons
        """
        print("\n=== Hash Algorithm Comparison ===\n")
        
        results = {}
        
        # SHA-256 (100 rounds)
        print("1. SHA-256 (100 rounds)")
        start = time.time()
        for _ in range(1000):
            test_hash = password.encode() + salt + self.pepper
            for _ in range(100):
                test_hash = hashlib.sha256(test_hash).digest()
        sha256_time = (time.time() - start) / 1000
        results['sha256_100'] = sha256_time
        print(f"   Average time per hash: {sha256_time*1000:.4f}ms")
        
        # SHA-256 (10000 rounds)
        print("\n2. SHA-256 (10000 rounds)")
        start = time.time()
        for _ in range(100):
            test_hash = password.encode() + salt + self.pepper
            for _ in range(10000):
                test_hash = hashlib.sha256(test_hash).digest()
        sha256_10k_time = (time.time() - start) / 100
        results['sha256_10000'] = sha256_10k_time
        print(f"   Average time per hash: {sha256_10k_time*1000:.4f}ms")
        
        # bcrypt
        print("\n3. bcrypt (cost=8)")
        start = time.time()
        for _ in range(100):
            bcrypt.hashpw(password.encode() + self.pepper, bcrypt.gensalt(rounds=8))
        bcrypt_time = (time.time() - start) / 100
        results['bcrypt_8'] = bcrypt_time
        print(f"   Average time per hash: {bcrypt_time*1000:.4f}ms")
        
        # Argon2
        print("\n4. Argon2 (time_cost=1, memory_cost=8192)")
        ph = Argon2PasswordHasher(time_cost=1, memory_cost=8192)
        start = time.time()
        for _ in range(100):
            ph.hash(password + self.pepper.decode('utf-8', errors='ignore'))
        argon2_time = (time.time() - start) / 100
        results['argon2'] = argon2_time
        print(f"   Average time per hash: {argon2_time*1000:.4f}ms")
        
        # Calculate relative strength
        print("\n5. Relative Cracking Difficulty")
        print("-" * 50)
        baseline = sha256_time
        for algo, time_per_hash in results.items():
            relative = time_per_hash / baseline
            print(f"   {algo:20s}: {relative:8.2f}x slower than SHA-256(100)")
        
        return results
    
    def generate_report(self, filename='dictionary_attack_report.txt'):
        """Generate detailed cracking report"""
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PASSWORD CRACKING ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total attacks performed: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r['success'])
            f.write(f"Successful cracks: {successful}\n")
            f.write(f"Failed attempts: {len(self.results) - successful}\n\n")
            
            f.write("DETAILED RESULTS\n")
            f.write("-" * 80 + "\n")
            for i, result in enumerate(self.results, 1):
                f.write(f"\nAttack #{i}\n")
                f.write(f"  Method: {result['method']}\n")
                f.write(f"  Algorithm: {result['algorithm']}\n")
                f.write(f"  Success: {result['success']}\n")
                if result['success']:
                    f.write(f"  Password: {result['password']}\n")
                f.write(f"  Attempts: {result['attempts']}\n")
                f.write(f"  Time: {result['time_seconds']:.2f} seconds\n")
                f.write(f"  Rate: {result['rate']:.2f} attempts/second\n")
        
        print(f"\nReport saved to: {filename}")


# Test and demonstration
if __name__ == "__main__":
    print("=== Password Cracking Demonstration ===\n")
    
    cracker = PasswordCracker()
    salt = b"test_salt_16_bytes_"
    
    # Test 1: Dictionary attack
    print("Test 1: Dictionary Attack")
    print("-" * 50)
    test_password = "password"
    test_hash = test_password.encode() + salt + cracker.pepper
    for _ in range(100):
        test_hash = hashlib.sha256(test_hash).digest()
    
    dictionary = cracker.load_dictionary()
    print(f"Dictionary size: {len(dictionary)} passwords")
    print(f"Target password: {test_password}")
    
    result = cracker.dictionary_attack_sha256(test_hash, salt, dictionary)
    print(f"\nResult:")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Password found: {result['password']}")
    print(f"  Attempts: {result['attempts']}")
    print(f"  Time: {result['time_seconds']:.4f} seconds")
    print(f"  Rate: {result['rate']:.2f} passwords/second")
    
    # Test 2: Brute force attack
    print("\n\nTest 2: Brute Force Attack")
    print("-" * 50)
    test_password = "ab1"
    test_hash = test_password.encode() + salt + cracker.pepper
    for _ in range(100):
        test_hash = hashlib.sha256(test_hash).digest()
    
    print(f"Target password: {test_password}")
    print(f"Character set: lowercase + digits (36 chars)")
    print(f"Max length: 3")
    
    result = cracker.brute_force_attack(test_hash, salt, max_length=3)
    print(f"\nResult:")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Password found: {result['password']}")
    print(f"  Attempts: {result['attempts']}")
    print(f"  Time: {result['time_seconds']:.2f} seconds")
    print(f"  Rate: {result['rate']:.2f} attempts/second")
    
    # Test 3: Algorithm comparison
    cracker.compare_hash_algorithms("testpass", salt)
    
    # Generate report
    cracker.generate_report()
    
    print("\n=== Test Complete ===")
