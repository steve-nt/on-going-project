import hashlib
import time
import itertools
import string

def crack_sha256(target_hash, salt, max_length=4):
    #Simple brute force
    chars = string.ascii_lowercase + string.digits
    start_time = time.time()
    attempts = 0
    
    for length in range(1, max_length + 1):
        for candidate in itertools.product(chars, repeat=length):
            password = ''.join(candidate)
            attempts += 1
            
            # Test hash
            test_hash = password.encode() + salt + b"system_pepper_secret_key"
            for _ in range(100000):  
                test_hash = hashlib.sha256(test_hash).digest()
            
            if test_hash == target_hash:
                elapsed = time.time() - start_time
                return password, attempts, elapsed
                
            if attempts % 1000 == 0:
                print(f"Tried {attempts} passwords...")
    
    return None, attempts, time.time() - start_time

# Test 
if __name__ == "__main__":
    
    salt = b"test_salt_16_bytes_"
    password = "abc"
    test_hash = password.encode() + salt + b"system_pepper_secret_key"
    for _ in range(100000):
        test_hash = hashlib.sha256(test_hash).digest()
    
    print("Cracking password 'abc'...")
    result = crack_sha256(test_hash, salt, max_length=4)
    print(f"Result: {result}")
