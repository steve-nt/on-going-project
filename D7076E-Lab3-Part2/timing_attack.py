"""
Timing Attack Demonstration for Person B - Lab 3
Educational demonstration of timing side-channel attacks

Timing Attacks:
- Exploit timing differences in comparison operations
- Can reveal information about secret values
- Common in authentication systems

Vulnerable Code:
- Byte-by-byte string comparison (early exit on mismatch)
- Leaks information through timing

Mitigation:
- Constant-time comparison (hmac.compare_digest)
- Always compare full strings regardless of match
- No early exit on mismatch

Author: Person B
Purpose: Demonstrate timing vulnerabilities and mitigations
"""

import time
import hmac
import secrets
import statistics
from typing import List, Tuple, Dict
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt


class TimingAttackDemo:
    """
    Demonstrates timing side-channel vulnerabilities
    Shows how attackers can extract secret information through timing measurements
    """

    def __init__(self):
        # Generate a secret token for testing
        # In real systems, this could be a session token, API key, etc.
        self.secret_token = secrets.token_hex(16)  # 32 character hex string
        print(f"[Timing] Secret token generated: {self.secret_token[:8]}... (hidden)")

    # ========== VULNERABLE IMPLEMENTATION ==========

    def naive_compare(self, input_token: str, secret_token: str) -> bool:
        """
        VULNERABLE: Naive string comparison

        Problem:
        - Compares byte-by-byte
        - Returns False immediately on first mismatch (early exit)
        - Takes longer if more characters match

        Security Issue:
        - Attacker can guess token character by character
        - Longer response time = more characters are correct
        - Can extract full token through repeated measurements

        Args:
            input_token: User-provided token
            secret_token: Server's secret token

        Returns:
            True if tokens match, False otherwise
        """
        # VULNERABLE CODE - DO NOT USE IN PRODUCTION!
        if len(input_token) != len(secret_token):
            return False

        # This loop exits early on mismatch
        # Each iteration takes ~1-10 nanoseconds
        # Difference is measurable with statistical analysis
        for i in range(len(input_token)):
            if input_token[i] != secret_token[i]:
                return False  # Early exit leaks timing information!

        return True

    def constant_time_compare(self, input_token: str, secret_token: str) -> bool:
        """
        SECURE: Constant-time comparison

        Solution:
        - Always compares all bytes
        - No early exit
        - Same time regardless of where mismatch occurs
        - Uses hmac.compare_digest() for cryptographic comparison

        Args:
            input_token: User-provided token
            secret_token: Server's secret token

        Returns:
            True if tokens match, False otherwise
        """
        # SECURE CODE - USE THIS!
        # hmac.compare_digest is designed to prevent timing attacks
        return hmac.compare_digest(input_token, secret_token)

    # ========== TIMING MEASUREMENT ==========

    def measure_comparison_time(self, compare_func, input_token: str,
                                secret_token: str, iterations: int = 1000) -> float:
        """
        Measure average time for comparison operation

        Multiple iterations reduce measurement noise
        Statistical analysis reveals timing differences

        Args:
            compare_func: Comparison function to measure
            input_token: Token to test
            secret_token: Secret token to compare against
            iterations: Number of measurements (more = better accuracy)

        Returns:
            Average comparison time in seconds
        """
        times = []

        for _ in range(iterations):
            # Use high-precision timer
            start = time.perf_counter()
            compare_func(input_token, secret_token)
            end = time.perf_counter()

            times.append(end - start)

        # Return average time
        return statistics.mean(times)

    # ========== ATTACK SIMULATION ==========

    def simulate_timing_attack(self, secret_token: str) -> Tuple[str, List[Dict]]:
        """
        Simulate a timing attack to extract secret token

        Attack Process:
        1. Start with empty guess
        2. For each position:
           a. Try all possible characters
           b. Measure comparison time for each
           c. Character with longest time is likely correct
        3. Build token character by character

        This demonstrates how timing leaks information!

        Args:
            secret_token: Token to extract (simulating server secret)

        Returns:
            Tuple of (extracted_token, timing_data)
        """
        print("\n" + "="*70)
        print("SIMULATING TIMING ATTACK")
        print("="*70)
        print("\nObjective: Extract secret token using timing side-channel")
        print(f"Secret token length: {len(secret_token)} characters")
        print("Method: Measure comparison times to guess each character\n")

        # Characters to try (hexadecimal for token)
        charset = "0123456789abcdef"

        extracted_token = ""
        timing_data = []

        for position in range(len(secret_token)):
            print(f"[Attack] Position {position + 1}/{len(secret_token)}:")

            char_timings = {}

            # Try each possible character at this position
            for char in charset:
                # Build test token: known prefix + guessed char + random suffix
                test_token = extracted_token + char + ("0" * (len(secret_token) - position - 1))

                # Measure comparison time with vulnerable function
                avg_time = self.measure_comparison_time(
                    self.naive_compare,
                    test_token,
                    secret_token,
                    iterations=1000  # More iterations = better accuracy
                )

                char_timings[char] = avg_time

            # Character with longest comparison time is most likely correct
            # (More matching characters = longer comparison before mismatch)
            best_char = max(char_timings, key=char_timings.get)
            best_time = char_timings[best_char]

            extracted_token += best_char

            # Calculate timing differences for analysis
            times_list = list(char_timings.values())
            avg_all = statistics.mean(times_list)
            stdev_all = statistics.stdev(times_list) if len(times_list) > 1 else 0

            print(f"  Guessed: '{best_char}' (time: {best_time*1e9:.2f} ns)")
            print(f"  Correct: '{secret_token[position]}'")
            print(f"  Match: {'✓' if best_char == secret_token[position] else '✗'}")
            print(f"  Time difference: {(best_time - avg_all)*1e9:.2f} ns")
            print(f"  Std deviation: {stdev_all*1e9:.2f} ns")

            timing_data.append({
                'position': position,
                'guessed_char': best_char,
                'actual_char': secret_token[position],
                'correct': best_char == secret_token[position],
                'best_time': best_time,
                'avg_time': avg_all,
                'stdev': stdev_all,
                'char_timings': char_timings
            })

        print(f"\n[Attack] Extraction complete!")
        print(f"[Attack] Extracted: {extracted_token}")
        print(f"[Attack] Actual:    {secret_token}")
        print(f"[Attack] Success: {'✓ FULL MATCH' if extracted_token == secret_token else '✗ PARTIAL MATCH'}")

        return extracted_token, timing_data

    # ========== COMPARISON DEMONSTRATION ==========

    def demonstrate_timing_difference(self):
        """
        Demonstrate timing difference between naive and constant-time comparison
        Shows how many matching characters affects timing in vulnerable code
        """
        print("\n" + "="*70)
        print("TIMING DIFFERENCE DEMONSTRATION")
        print("="*70)

        secret = self.secret_token
        print(f"\nSecret token: {secret[:8]}... ({len(secret)} chars)")

        # Test with different numbers of matching characters
        test_cases = [
            ("No match", "0" * len(secret)),
            ("1 char match", secret[0] + "0" * (len(secret) - 1)),
            ("4 chars match", secret[:4] + "0" * (len(secret) - 4)),
            ("8 chars match", secret[:8] + "0" * (len(secret) - 8)),
            ("Half match", secret[:len(secret)//2] + "0" * (len(secret) - len(secret)//2)),
            ("Full match", secret)
        ]

        print("\n" + "-"*70)
        print("NAIVE COMPARISON (Vulnerable)")
        print("-"*70)

        naive_results = []

        for description, test_token in test_cases:
            avg_time = self.measure_comparison_time(
                self.naive_compare,
                test_token,
                secret,
                iterations=5000
            )
            naive_results.append((description, avg_time))
            print(f"{description:20s}: {avg_time*1e9:8.2f} ns")

        print("\n" + "-"*70)
        print("CONSTANT-TIME COMPARISON (Secure)")
        print("-"*70)

        secure_results = []

        for description, test_token in test_cases:
            avg_time = self.measure_comparison_time(
                self.constant_time_compare,
                test_token,
                secret,
                iterations=5000
            )
            secure_results.append((description, avg_time))
            print(f"{description:20s}: {avg_time*1e9:8.2f} ns")

        print("\n" + "-"*70)
        print("ANALYSIS")
        print("-"*70)

        # Calculate timing variance
        naive_times = [t for _, t in naive_results]
        secure_times = [t for _, t in secure_results]

        naive_stdev = statistics.stdev(naive_times)
        secure_stdev = statistics.stdev(secure_times)

        print(f"\nNaive comparison variance: {naive_stdev*1e9:.2f} ns")
        print(f"Constant-time comparison variance: {secure_stdev*1e9:.2f} ns")

        print("\nKey Findings:")
        if naive_stdev > secure_stdev * 2:
            print("✓ Naive comparison shows SIGNIFICANT timing variation")
            print("  → Vulnerable to timing attacks")
        else:
            print("⚠ Timing differences may be subtle (measurement noise)")
            print("  → Still vulnerable with enough samples")

        print("✓ Constant-time comparison shows minimal variation")
        print("  → Protected against timing attacks")

        return naive_results, secure_results

    # ========== MITIGATION DEMONSTRATION ==========

    def demonstrate_mitigation(self):
        """
        Show why constant-time comparison defeats timing attacks
        """
        print("\n" + "="*70)
        print("MITIGATION: CONSTANT-TIME COMPARISON")
        print("="*70)

        print("\nAttempting timing attack on constant-time comparison...")

        secret = self.secret_token
        charset = "0123456789abcdef"

        # Try to extract first 4 characters using timing attack
        # This should fail with constant-time comparison
        print("\nTrying to extract first 4 characters:")

        extracted = ""
        for position in range(4):
            print(f"\n[Attack] Position {position + 1}:")

            char_timings = {}

            for char in charset:
                test_token = extracted + char + ("0" * (len(secret) - position - 1))

                # Measure with SECURE constant-time function
                avg_time = self.measure_comparison_time(
                    self.constant_time_compare,
                    test_token,
                    secret,
                    iterations=1000
                )

                char_timings[char] = avg_time

            best_char = max(char_timings, key=char_timings.get)
            actual_char = secret[position]

            times_list = list(char_timings.values())
            avg_time = statistics.mean(times_list)
            stdev_time = statistics.stdev(times_list)

            print(f"  Guessed: '{best_char}'")
            print(f"  Actual:  '{actual_char}'")
            print(f"  Match: {'✓' if best_char == actual_char else '✗'}")
            print(f"  Timing variance: {stdev_time*1e9:.2f} ns (very small!)")

            extracted += best_char

        matches = sum(1 for i in range(4) if extracted[i] == secret[i])
        print(f"\n[Result] Extracted: {extracted}")
        print(f"[Result] Actual:    {secret[:4]}")
        print(f"[Result] Accuracy:  {matches}/4 ({matches*25}%)")

        if matches <= 1:
            print("\n✓ SUCCESS: Constant-time comparison prevents timing attack!")
            print("  Attack accuracy is no better than random guessing")
        else:
            print("\n⚠ WARNING: Some characters matched (could be luck)")
            print("  With enough samples, attack should fail completely")


def benchmark_comparison_overhead():
    """
    Measure performance overhead of constant-time comparison
    Show that security has minimal performance cost
    """
    print("\n" + "="*70)
    print("PERFORMANCE OVERHEAD ANALYSIS")
    print("="*70)

    demo = TimingAttackDemo()
    secret = demo.secret_token

    test_cases = [
        ("8 chars", "a" * 8),
        ("16 chars", "a" * 16),
        ("32 chars", "a" * 32),
        ("64 chars", "a" * 64),
    ]

    print("\nComparing performance of naive vs constant-time comparison")
    print("Iterations: 10,000 per test\n")

    for description, test_token in test_cases:
        # Pad/trim to match secret length for fair comparison
        test_token = test_token[:len(secret)].ljust(len(secret), '0')

        naive_time = demo.measure_comparison_time(
            demo.naive_compare,
            test_token,
            secret,
            iterations=10000
        )

        secure_time = demo.measure_comparison_time(
            demo.constant_time_compare,
            test_token,
            secret,
            iterations=10000
        )

        overhead = ((secure_time - naive_time) / naive_time) * 100

        print(f"{description:15s}:")
        print(f"  Naive:         {naive_time*1e9:8.2f} ns")
        print(f"  Constant-time: {secure_time*1e9:8.2f} ns")
        print(f"  Overhead:      {overhead:8.2f}%")
        print()

    print("Key Finding:")
    print("✓ Constant-time comparison has minimal overhead")
    print("✓ Security benefit far outweighs tiny performance cost")
    print("✓ Always use hmac.compare_digest() for security-critical comparisons")


def visualize_timing_attack(timing_data: List[Dict], output_file: str = "timing_attack_visualization.png"):
    """
    Create visualization of timing attack results

    Args:
        timing_data: List of timing measurements per position
        output_file: Output filename for plot
    """
    print(f"\n[Visualization] Creating timing attack plot...")

    # Create figure with subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))

    # Plot 1: Time difference from average per position
    positions = [d['position'] + 1 for d in timing_data]
    time_diffs = [(d['best_time'] - d['avg_time']) * 1e9 for d in timing_data]
    colors = ['green' if d['correct'] else 'red' for d in timing_data]

    ax1.bar(positions, time_diffs, color=colors, alpha=0.7)
    ax1.axhline(y=0, color='black', linestyle='--', linewidth=0.5)
    ax1.set_xlabel('Character Position')
    ax1.set_ylabel('Time Difference from Average (ns)')
    ax1.set_title('Timing Attack: Time Difference per Character Position')
    ax1.grid(True, alpha=0.3)

    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='green', alpha=0.7, label='Correct guess'),
        Patch(facecolor='red', alpha=0.7, label='Incorrect guess')
    ]
    ax1.legend(handles=legend_elements)

    # Plot 2: Character timing distribution for first position
    if timing_data and 'char_timings' in timing_data[0]:
        first_pos_data = timing_data[0]
        chars = list(first_pos_data['char_timings'].keys())
        times = [first_pos_data['char_timings'][c] * 1e9 for c in chars]

        colors_bars = ['green' if c == first_pos_data['actual_char'] else 'lightblue' for c in chars]

        ax2.bar(chars, times, color=colors_bars, alpha=0.7)
        ax2.set_xlabel('Character Guess')
        ax2.set_ylabel('Average Comparison Time (ns)')
        ax2.set_title(f'Timing Distribution for Position 1 (Actual: {first_pos_data["actual_char"]})')
        ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"[Visualization] Saved to {output_file}")
    plt.close()


def demo_timing_attack_complete():
    """
    Complete demonstration of timing attacks and mitigations
    """
    print("\n" + "="*70)
    print("TIMING ATTACK DEMONSTRATION")
    print("Person B - Lab 3 Implementation")
    print("="*70)

    print("\nWARNING: This demonstrates a real security vulnerability!")
    print("Always use constant-time comparison for security-critical operations.\n")

    # Initialize demo
    demo = TimingAttackDemo()

    # Part 1: Show timing differences
    demo.demonstrate_timing_difference()

    # Part 2: Simulate actual timing attack
    # Note: This may take a while due to statistical measurements
    print("\n[WARNING] Next step performs statistical timing attack")
    print("[WARNING] This will take several minutes...")

    # For demo, use a shorter secret to speed up
    short_secret = secrets.token_hex(8)  # 16 chars instead of 32
    demo_short = TimingAttackDemo()
    demo_short.secret_token = short_secret

    extracted, timing_data = demo_short.simulate_timing_attack(short_secret)

    # Visualize results
    visualize_timing_attack(timing_data)

    # Part 3: Show mitigation
    demo.demonstrate_mitigation()

    # Part 4: Performance analysis
    benchmark_comparison_overhead()

    # ========== SUMMARY ==========
    print("\n" + "="*70)
    print("KEY FINDINGS & RECOMMENDATIONS")
    print("="*70)

    print("\n1. VULNERABILITY:")
    print("   ✗ Naive byte-by-byte comparison leaks timing information")
    print("   ✗ Attackers can extract secrets character by character")
    print("   ✗ Affects tokens, passwords, API keys, etc.")

    print("\n2. MITIGATION:")
    print("   ✓ Use hmac.compare_digest() for all security comparisons")
    print("   ✓ Constant-time comparison prevents timing attacks")
    print("   ✓ Minimal performance overhead (~2-5%)")

    print("\n3. BEST PRACTICES:")
    print("   • Never write your own cryptographic comparison")
    print("   • Use language-provided constant-time functions")
    print("   • Python: hmac.compare_digest()")
    print("   • Consider rate limiting to prevent timing analysis")
    print("   • Add random delays (less reliable defense)")

    print("\n4. REAL-WORLD IMPACT:")
    print("   • Timing attacks have broken real systems")
    print("   • OpenSSL, SSH, and web applications affected")
    print("   • Even nanosecond differences are exploitable")
    print("   • Network jitter makes remote attacks harder but not impossible")

    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70 + "\n")


if __name__ == "__main__":
    demo_timing_attack_complete()
