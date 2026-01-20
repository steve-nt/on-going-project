"""
Timing Attack Demonstration
Shows how timing vulnerabilities in password/hash comparison can leak information
Demonstrates both vulnerable and secure comparison methods
"""

import time
import hashlib
import hmac
import statistics
import matplotlib.pyplot as plt
from collections import defaultdict

def vulnerable_compare(a, b):
    """
    VULNERABLE: Byte-by-byte comparison that leaks timing information
    Returns as soon as first mismatch is found
    """
    if len(a) != len(b):
        return False

    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Early exit leaks position of mismatch
    return True

def secure_compare(a, b):
    """
    SECURE: Constant-time comparison using hmac.compare_digest
    Always compares all bytes regardless of mismatches
    """
    return hmac.compare_digest(a, b)

def measure_comparison_time(compare_func, correct_hash, test_hash, iterations=1000):
    """
    Measure average time taken to compare hashes
    """
    times = []

    for _ in range(iterations):
        start = time.perf_counter()
        result = compare_func(correct_hash, test_hash)
        end = time.perf_counter()
        times.append((end - start) * 1000000)  # Convert to microseconds

    return {
        'min': min(times),
        'max': max(times),
        'mean': statistics.mean(times),
        'median': statistics.median(times),
        'stdev': statistics.stdev(times) if len(times) > 1 else 0,
        'times': times
    }

def demonstrate_timing_attack():
    """
    Demonstrate timing attack by comparing hashes with different numbers of matching bytes
    """
    print("="*80)
    print("TIMING ATTACK DEMONSTRATION")
    print("="*80)
    print("\nThis demonstrates how timing differences can leak information about secrets.")
    print("We'll compare hashes with varying numbers of matching initial bytes.\n")

    # Create a correct hash
    correct_password = "correct_password_123"
    correct_hash = hashlib.sha256(correct_password.encode()).digest()

    # Create test hashes with 0, 4, 8, 12, 16, 20, 24, 28, 32 matching bytes
    test_cases = []
    for matching_bytes in [0, 4, 8, 12, 16, 20, 24, 28, 31, 32]:
        if matching_bytes == 32:
            # Completely matching hash
            test_hash = correct_hash
        elif matching_bytes == 0:
            # Completely different hash
            test_hash = hashlib.sha256(b"wrong_password").digest()
        else:
            # Partially matching hash
            test_hash = bytearray(correct_hash)
            # Keep first N bytes, change the rest
            for i in range(matching_bytes, 32):
                test_hash[i] = (test_hash[i] + 1) % 256
            test_hash = bytes(test_hash)

        test_cases.append((matching_bytes, test_hash))

    print("\nTesting VULNERABLE comparison (byte-by-byte with early exit):")
    print("-" * 80)
    print(f"{'Matching Bytes':<20} {'Mean Time (μs)':<20} {'Std Dev (μs)':<20}")
    print("-" * 80)

    vulnerable_results = []
    for matching_bytes, test_hash in test_cases:
        stats = measure_comparison_time(vulnerable_compare, correct_hash, test_hash, iterations=1000)
        vulnerable_results.append((matching_bytes, stats['mean'], stats['stdev']))
        print(f"{matching_bytes:<20} {stats['mean']:<20.4f} {stats['stdev']:<20.4f}")

    print("\n\nTesting SECURE comparison (constant-time using hmac.compare_digest):")
    print("-" * 80)
    print(f"{'Matching Bytes':<20} {'Mean Time (μs)':<20} {'Std Dev (μs)':<20}")
    print("-" * 80)

    secure_results = []
    for matching_bytes, test_hash in test_cases:
        stats = measure_comparison_time(secure_compare, correct_hash, test_hash, iterations=1000)
        secure_results.append((matching_bytes, stats['mean'], stats['stdev']))
        print(f"{matching_bytes:<20} {stats['mean']:<20.4f} {stats['stdev']:<20.4f}")

    # Calculate timing differences
    print("\n" + "="*80)
    print("ANALYSIS:")
    print("="*80)

    vuln_times = [t for _, t, _ in vulnerable_results]
    secure_times = [t for _, t, _ in secure_results]

    vuln_variance = max(vuln_times) - min(vuln_times)
    secure_variance = max(secure_times) - min(secure_times)

    print(f"\nVulnerable comparison:")
    print(f"  - Timing variance: {vuln_variance:.4f} μs")
    print(f"  - Min time: {min(vuln_times):.4f} μs (early mismatch)")
    print(f"  - Max time: {max(vuln_times):.4f} μs (full match)")
    print(f"  - Timing leak: {(vuln_variance/min(vuln_times)*100):.1f}% difference")

    print(f"\nSecure comparison:")
    print(f"  - Timing variance: {secure_variance:.4f} μs")
    print(f"  - Min time: {min(secure_times):.4f} μs")
    print(f"  - Max time: {max(secure_times):.4f} μs")
    print(f"  - Timing leak: {(secure_variance/min(secure_times)*100):.1f}% difference")

    print("\n" + "="*80)
    print("KEY FINDINGS:")
    print("="*80)
    print("1. Vulnerable comparison shows CLEAR correlation between matching bytes and time")
    print("2. More matching bytes → longer comparison time (due to later early exit)")
    print("3. Attacker can use this to guess hash byte-by-byte")
    print("4. Secure comparison shows MINIMAL timing variation regardless of content")
    print("5. Always use hmac.compare_digest() for security-sensitive comparisons!")
    print("="*80)

    # Plot results
    plot_timing_results(vulnerable_results, secure_results)

    return vulnerable_results, secure_results

def plot_timing_results(vulnerable_results, secure_results):
    """
    Plot timing results to visualize the timing attack
    """
    try:
        vuln_x = [x for x, _, _ in vulnerable_results]
        vuln_y = [y for _, y, _ in vulnerable_results]
        vuln_err = [e for _, _, e in vulnerable_results]

        sec_x = [x for x, _, _ in secure_results]
        sec_y = [y for _, y, _ in secure_results]
        sec_err = [e for _, _, e in secure_results]

        plt.figure(figsize=(12, 6))

        plt.subplot(1, 2, 1)
        plt.errorbar(vuln_x, vuln_y, yerr=vuln_err, marker='o', capsize=5, label='Vulnerable')
        plt.xlabel('Matching Bytes')
        plt.ylabel('Comparison Time (μs)')
        plt.title('Vulnerable Comparison\n(Timing Leak Visible)')
        plt.grid(True, alpha=0.3)
        plt.legend()

        plt.subplot(1, 2, 2)
        plt.errorbar(sec_x, sec_y, yerr=sec_err, marker='s', capsize=5, label='Secure', color='green')
        plt.xlabel('Matching Bytes')
        plt.ylabel('Comparison Time (μs)')
        plt.title('Secure Comparison\n(Constant Time)')
        plt.grid(True, alpha=0.3)
        plt.legend()

        plt.tight_layout()
        plt.savefig('timing_attack_results.png', dpi=150)
        print(f"\nPlot saved to: timing_attack_results.png")

    except Exception as e:
        print(f"\nNote: Could not generate plot ({e})")

def demonstrate_remote_timing_attack():
    """
    Simulate a remote timing attack scenario
    """
    print("\n" + "="*80)
    print("REMOTE TIMING ATTACK SIMULATION")
    print("="*80)
    print("\nSimulating attacker trying to guess an API token character by character...")

    correct_token = "SECRET_TOKEN_ABC123"
    correct_hash = hashlib.sha256(correct_token.encode()).digest()

    # Attacker tries to guess first character
    print("\nAttacker guessing first character of token:")
    print("-" * 80)

    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"
    timing_results = {}

    for char in charset[:10]:  # Test first 10 chars for demo
        guess = char + "?" * (len(correct_token) - 1)
        guess_hash = hashlib.sha256(guess.encode()).digest()

        # Measure timing
        stats = measure_comparison_time(vulnerable_compare, correct_hash, guess_hash, iterations=100)
        timing_results[char] = stats['mean']
        print(f"  Trying '{char}': {stats['mean']:.4f} μs")

    # Find character with longest time (most matches)
    best_guess = max(timing_results.items(), key=lambda x: x[1])
    print(f"\nBest guess (longest time): '{best_guess[0]}' ({best_guess[1]:.4f} μs)")
    print(f"Actual first character: '{correct_token[0]}'")
    print(f"Match: {best_guess[0] == correct_token[0]}")

    print("\n" + "="*80)
    print("MITIGATION:")
    print("="*80)
    print("1. Use constant-time comparison (hmac.compare_digest)")
    print("2. Add random delays to responses")
    print("3. Rate limiting to prevent timing measurements")
    print("4. Use cryptographic MACs instead of direct hash comparison")
    print("="*80)

def demonstrate_mac_comparison():
    """
    Demonstrate secure MAC comparison
    """
    print("\n" + "="*80)
    print("SECURE MAC COMPARISON")
    print("="*80)

    secret_key = b"secret_mac_key_12345"
    message = b"important_data"

    # Create MAC
    mac = hmac.new(secret_key, message, hashlib.sha256).digest()
    print(f"\nMessage: {message}")
    print(f"MAC: {mac.hex()[:32]}...")

    # Correct verification
    print("\n1. Verifying correct MAC (should succeed):")
    start = time.perf_counter()
    is_valid = hmac.compare_digest(mac, mac)
    elapsed = (time.perf_counter() - start) * 1000000
    print(f"   Result: {is_valid}")
    print(f"   Time: {elapsed:.4f} μs")

    # Incorrect verification
    print("\n2. Verifying incorrect MAC (should fail):")
    wrong_mac = hashlib.sha256(b"wrong").digest()
    start = time.perf_counter()
    is_valid = hmac.compare_digest(mac, wrong_mac)
    elapsed = (time.perf_counter() - start) * 1000000
    print(f"   Result: {is_valid}")
    print(f"   Time: {elapsed:.4f} μs")

    print("\n3. Verifying partially correct MAC (should fail):")
    partial_mac = bytearray(mac)
    partial_mac[-1] = (partial_mac[-1] + 1) % 256
    partial_mac = bytes(partial_mac)
    start = time.perf_counter()
    is_valid = hmac.compare_digest(mac, partial_mac)
    elapsed = (time.perf_counter() - start) * 1000000
    print(f"   Result: {is_valid}")
    print(f"   Time: {elapsed:.4f} μs")

    print("\n" + "="*80)
    print("Notice: All comparisons take similar time regardless of correctness!")
    print("="*80)

if __name__ == '__main__':
    print("\n" + "="*80)
    print("TIMING ATTACK DEMONSTRATION - Educational Lab")
    print("D7076E Security")
    print("="*80)

    # Main timing attack demonstration
    demonstrate_timing_attack()

    # Remote timing attack simulation
    demonstrate_remote_timing_attack()

    # MAC comparison demonstration
    demonstrate_mac_comparison()

    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print("\nAll security-sensitive comparisons should use constant-time algorithms!")
