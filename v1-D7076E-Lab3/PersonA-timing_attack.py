import time
import statistics
import hmac

def naive_compare(a, b):
    #Vulnerable comparison
    return a == b

def secure_compare(a, b):
    #Secure comparison
    return hmac.compare_digest(a, b)

def timing_demo():
    correct = "correct_password_hash_64_chars_long_aaaaaaaaaaaaaaaaaaaa"
    
    # Test different wrong passwords
    test_cases = [
        "wrong_password_hash_64_chars_long_bbbbbbbbbbbbbbbbbbbbbb",  # different start
        "correct_password_hash_64_chars_long_bbbbbbbbbbbbbbbbbbbbb",  # same start
        "correct_password_hash_64_chars_long_aaaaaaaaaaaaaaaaaaab",   # different end
    ]
    
    for i, wrong in enumerate(test_cases):
        times_naive = []
        times_secure = []
        
        # Test naive comparison
        for _ in range(1000):
            start = time.perf_counter()
            naive_compare(correct, wrong)
            end = time.perf_counter()
            times_naive.append(end - start)
        
        # Test secure comparison
        for _ in range(1000):
            start = time.perf_counter()
            secure_compare(correct, wrong)
            end = time.perf_counter()
            times_secure.append(end - start)
        
        print(f"Test case {i+1}:")
        print(f"Naive avg: {statistics.mean(times_naive):.2e} seconds")
        print(f"Secure avg: {statistics.mean(times_secure):.2e} seconds")

if __name__ == "__main__":
    timing_demo()
