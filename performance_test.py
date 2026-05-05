"""
performance_test.py — Hash Function Performance Comparison
TP2: Lightweight Cryptography using ASCON and Hash Functions
ENSA Tangier — Prof. S. LAZAAR

Compares SHA-256, SHA3-256, and BLAKE2b across:
  - Execution time (10,000 iterations)
  - Throughput (hashes per second)
  - Digest output (hex)

Also benchmarks ASCON encryption performance.
"""

import time
import hashlib
import ascon
import os
from common import measure_hash_performance, SHARED_KEY, generate_nonce

SEPARATOR = "─" * 65


def print_header(title: str) -> None:
    print(f"\n{'═' * 65}")
    print(f"  {title}")
    print(f"{'═' * 65}")


def run_hash_benchmark(password: str = "MySecurePassword2025!", iterations: int = 10_000) -> dict:
    """
    Benchmark SHA-256, SHA3-256, and BLAKE2b.

    WHY 10,000 iterations:
      A single hash call takes microseconds — too fast to measure accurately.
      10,000 repetitions give stable, meaningful averages.
    """
    print_header("PHASE 3 — HASH FUNCTION PERFORMANCE COMPARISON")
    print(f"  Password  : '{password}'")
    print(f"  Iterations: {iterations:,}")
    print(f"  {SEPARATOR}")

    results = measure_hash_performance(password, iterations)

    # ── Display results ──────────────────────────────────────────────
    print(f"\n  {'Algorithm':<12} {'Total (ms)':>12} {'Avg (µs)':>10} {'Rate (H/s)':>12}")
    print(f"  {SEPARATOR}")

    for name, r in results.items():
        rate = 1_000_000 / r['avg_us']
        print(f"  {name:<12} {r['total_ms']:>11.2f}ms {r['avg_us']:>9.3f}µs {rate:>11,.0f}")

    print(f"\n  {'Algorithm':<12} {'Hash Output (first 32 hex chars)'}")
    print(f"  {SEPARATOR}")
    for name, r in results.items():
        print(f"  {name:<12}  {r['hash_hex'][:32]}...")

    return results


def run_ascon_benchmark(iterations: int = 10_000) -> None:
    """
    Benchmark ASCON-128 encrypt and decrypt operations.

    WHY benchmark ASCON:
      In lightweight IoT protocols, the cipher performance directly
      impacts battery life and latency. ASCON was designed to be
      efficient even on 8-bit microcontrollers.
    """
    print_header("ASCON-128 ENCRYPTION PERFORMANCE")
    print(f"  Plaintext : 32-byte payload (simulated H(password))")
    print(f"  Iterations: {iterations:,}")
    print(f"  {SEPARATOR}")

    key        = SHARED_KEY
    nonce      = generate_nonce(16)
    assoc_data = generate_nonce(16)
    plaintext  = os.urandom(32)  # 32-byte payload

    # ── Encryption benchmark ─────────────────────────────────────────
    start = time.perf_counter()
    for _ in range(iterations):
        ct = ascon.encrypt(key, nonce, assoc_data, plaintext, variant="Ascon-128")
    enc_time = time.perf_counter() - start

    # ── Decryption benchmark ─────────────────────────────────────────
    start = time.perf_counter()
    for _ in range(iterations):
        pt = ascon.decrypt(key, nonce, assoc_data, ct, variant="Ascon-128")
    dec_time = time.perf_counter() - start

    enc_avg_us = (enc_time / iterations) * 1_000_000
    dec_avg_us = (dec_time / iterations) * 1_000_000

    print(f"\n  {'Operation':<15} {'Total (ms)':>12} {'Avg (µs)':>10} {'Rate (ops/s)':>14}")
    print(f"  {SEPARATOR}")
    print(f"  {'ASCON Encrypt':<15} {enc_time*1000:>11.2f}ms {enc_avg_us:>9.3f}µs {1e6/enc_avg_us:>13,.0f}")
    print(f"  {'ASCON Decrypt':<15} {dec_time*1000:>11.2f}ms {dec_avg_us:>9.3f}µs {1e6/dec_avg_us:>13,.0f}")
    print(f"\n  Ciphertext size: {len(ct)} bytes (= {len(plaintext)} plaintext + 16 tag)")


def run_comparison_summary(hash_results: dict) -> None:
    """
    Print a ranked summary comparing all algorithms.
    """
    print_header("SUMMARY — RANKED BY SPEED (fastest first)")

    ranked = sorted(hash_results.items(), key=lambda x: x[1]['avg_us'])

    print(f"\n  Rank  {'Algorithm':<12} {'Avg (µs)':>10}  Notes")
    print(f"  {SEPARATOR}")

    notes = {
        "SHA-256":  "NIST standard, hardware-accelerated on x86",
        "BLAKE2b":  "Optimized for 64-bit software, very fast",
        "SHA3-256": "Sponge-based, resistant to length-extension",
    }

    for rank, (name, r) in enumerate(ranked, start=1):
        medal = ["🥇", "🥈", "🥉"][rank - 1]
        print(f"  {medal}  #{rank}  {name:<12} {r['avg_us']:>9.3f}µs  {notes.get(name, '')}")

    best = ranked[0][0]
    print(f"\n  ✓ Fastest algorithm on this machine: {best}")
    print(f"  ✓ All three produce secure 256-bit digests")
    print(f"  ✓ For IoT/embedded: BLAKE2b or SHA-256 (if HW-accelerated)")


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  TP2 — Lightweight Authentication Protocol")
    print("  Performance Evaluation")
    print("  ENSA Tangier — Prof. S. LAZAAR")
    print("=" * 65)

    hash_results = run_hash_benchmark(iterations=10_000)
    run_ascon_benchmark(iterations=10_000)
    run_comparison_summary(hash_results)

    print(f"\n{'=' * 65}")
    print("  Performance evaluation complete.")
    print("=" * 65)
