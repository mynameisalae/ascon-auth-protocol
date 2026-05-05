"""
common.py — Shared utilities for the Lightweight Authentication Protocol
TP2: Lightweight Cryptography using ASCON and Hash Functions
ENSA Tangier — Prof. S. LAZAAR

This module provides:
  - Hash function wrappers (SHA-256, SHA3-256, BLAKE2b)
  - ASCON AEAD encryption/decryption wrappers
  - Nonce generation
  - Shared constants (pre-shared key)
"""

import os
import hashlib
import time
import ascon

# ─────────────────────────────────────────────
#  SHARED SECRET (Pre-shared symmetric key)
#  In a real deployment this would be established
#  via a secure key exchange (e.g., Diffie-Hellman).
#  For this TP, both client and server know K.
# ─────────────────────────────────────────────
SHARED_KEY: bytes = b'\x6a\x3f\x8c\x21\xde\x07\xb4\x50\x99\x1e\xad\x5c\x3b\x0f\x72\xe8'
# Exactly 16 bytes → ASCON-128 key

# ─────────────────────────────────────────────
#  NONCE GENERATION
#  A nonce ("number used once") must be fresh for
#  every session to prevent replay attacks.
# ─────────────────────────────────────────────
def generate_nonce(size: int = 16) -> bytes:
    """
    Generate a cryptographically secure random nonce.

    WHY: os.urandom() reads from the OS entropy pool (e.g., /dev/urandom on Linux),
         making the output unpredictable to adversaries.
    Args:
        size: nonce length in bytes (default 16 → 128-bit security)
    Returns:
        bytes of given size
    """
    return os.urandom(size)


# ─────────────────────────────────────────────
#  HASH FUNCTIONS
# ─────────────────────────────────────────────

def hash_sha256(data: str | bytes) -> bytes:
    """
    SHA-256 — 256-bit output, part of SHA-2 family.
    WHY: Widely deployed, well-studied, collision-resistant.
         NIST standard. Default choice in most systems.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def hash_sha3_256(data: str | bytes) -> bytes:
    """
    SHA3-256 — 256-bit output, Keccak-based (sponge construction).
    WHY: Resistant to length-extension attacks that affect SHA-2.
         Different internal structure → diversity against future attacks.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha3_256(data).digest()


def hash_blake2b(data: str | bytes) -> bytes:
    """
    BLAKE2b — 256-bit output (configured with digest_size=32).
    WHY: Faster than SHA-256 on 64-bit platforms, designed for speed
         without sacrificing security. Used in many modern protocols.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.blake2b(data, digest_size=32).digest()


# Map of available hash functions for easy selection
HASH_FUNCTIONS = {
    "SHA-256":   hash_sha256,
    "SHA3-256":  hash_sha3_256,
    "BLAKE2b":   hash_blake2b,
}


def compute_hash(password: str | bytes, algorithm: str = "SHA-256") -> bytes:
    """
    Compute H(password) using the specified algorithm.

    WHY we hash passwords before storage:
        If the database is leaked, attackers only see hashes, not plaintext.
        Brute-force is the only option — and with a strong hash, it's very slow.

    Args:
        password:  plaintext password (str or bytes)
        algorithm: one of "SHA-256", "SHA3-256", "BLAKE2b"
    Returns:
        digest bytes
    """
    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unknown algorithm '{algorithm}'. Choose from: {list(HASH_FUNCTIONS)}")
    return HASH_FUNCTIONS[algorithm](password)


# ─────────────────────────────────────────────
#  ASCON-128 AEAD WRAPPERS
# ─────────────────────────────────────────────

def ascon_encrypt(key: bytes, nonce: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using ASCON-128 (Authenticated Encryption with Associated Data).

    ASCON-128 produces:  ciphertext ‖ tag
      - ciphertext:  same length as plaintext
      - tag:         16 bytes (authentication tag)
    Total output length = len(plaintext) + 16

    WHY AEAD:
      - Confidentiality: ciphertext reveals nothing about plaintext
      - Integrity/Authenticity: the tag is unforgeable without the key
      - The associated_data (e.g. Ns) is authenticated but NOT encrypted —
        so the server can verify the nonce was not tampered with

    Args:
        key:             16-byte pre-shared key (ASCON-128)
        nonce:           16-byte session nonce (Nc — client nonce)
        associated_data: authenticated but not encrypted (Ns — server nonce)
        plaintext:       data to encrypt (Hp = H(password))
    Returns:
        ciphertext + tag (bytes)
    """
    assert len(key) == 16,   "ASCON-128 requires a 16-byte key"
    assert len(nonce) == 16, "ASCON-128 requires a 16-byte nonce"

    return ascon.encrypt(key, nonce, associated_data, plaintext, variant="Ascon-128")


def ascon_decrypt(key: bytes, nonce: bytes, associated_data: bytes, ciphertext_with_tag: bytes) -> bytes | None:
    """
    Decrypt and verify an ASCON-128 ciphertext+tag.

    WHY verification matters:
      If the tag is invalid (tampered message, wrong key, wrong nonce),
      ASCON raises an exception. We catch it and return None to signal
      authentication failure — do NOT return partial plaintext on failure.

    Returns:
        plaintext bytes if tag is valid, None otherwise
    """
    try:
        plaintext = ascon.decrypt(
            key, nonce, associated_data, ciphertext_with_tag, variant="Ascon-128"
        )
        return plaintext
    except Exception:
        # Tag verification failed → potential tampering or replay attempt
        return None


# ─────────────────────────────────────────────
#  PERFORMANCE MEASUREMENT UTILITY
# ─────────────────────────────────────────────

def measure_hash_performance(password: str = "TestPassword@2025", iterations: int = 10000) -> dict:
    """
    Benchmark all three hash functions over `iterations` calls.

    WHY performance matters for lightweight crypto:
      IoT devices have limited CPU cycles and memory. A hash function
      that is fast and memory-efficient is preferred. We compare:
        - SHA-256   (ubiquitous, hardware-accelerated on many CPUs)
        - SHA3-256  (sponge-based, different performance profile)
        - BLAKE2b   (optimized for software speed)

    Returns:
        dict mapping algorithm name → {'total_ms', 'avg_us', 'hash_hex'}
    """
    results = {}
    data = password.encode('utf-8')

    for name, fn in HASH_FUNCTIONS.items():
        start = time.perf_counter()
        for _ in range(iterations):
            digest = fn(data)
        elapsed = time.perf_counter() - start

        results[name] = {
            'total_ms': elapsed * 1000,
            'avg_us':   (elapsed / iterations) * 1_000_000,
            'hash_hex': digest.hex()
        }

    return results
