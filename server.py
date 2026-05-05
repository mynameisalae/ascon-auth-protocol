"""
server.py — Server-side logic for the Lightweight Authentication Protocol
TP2: Lightweight Cryptography using ASCON and Hash Functions
ENSA Tangier — Prof. S. LAZAAR

Responsibilities:
  Phase 1 (Registration):   Receive H(password) and store it in the DB.
  Phase 2 (Authentication): Exchange nonces, decrypt ASCON message, verify tag,
                             compare Hp with stored hash, respond OK/FAIL.
  Phase 3 (Session):        Confirm secure session and generate session key.
"""

import json
import os
import time
from common import (
    SHARED_KEY,
    generate_nonce,
    compute_hash,
    ascon_decrypt,
)

# ─────────────────────────────────────────────
#  SIMPLE FILE-BASED DATABASE
#  In production: use a proper DB (PostgreSQL, etc.)
#  with bcrypt/Argon2 for password hashing.
#  For this TP: JSON file simulates persistent storage.
# ─────────────────────────────────────────────
DB_FILE = "server_db.json"


def _load_db() -> dict:
    """Load the user database from disk."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_db(db: dict) -> None:
    """Persist the user database to disk."""
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


# ─────────────────────────────────────────────
#  PHASE 1 — REGISTRATION
# ─────────────────────────────────────────────

def register_user(user_id: str, hashed_password: bytes, algorithm: str = "SHA-256") -> dict:
    """
    Store the hashed password for a new user.

    WHY store only H(password):
      The server never needs to know the actual password.
      If the database is compromised, the attacker only sees hashes.
      Reversing a good hash is computationally infeasible.

    Args:
        user_id:         unique identifier (e.g., username or student ID)
        hashed_password: H(password) bytes from the client
        algorithm:       hash algorithm used (for record-keeping)
    Returns:
        dict with status message
    """
    db = _load_db()

    if user_id in db:
        return {"status": "ERROR", "message": f"User '{user_id}' already registered."}

    # Store the hash as a hex string (safe for JSON serialization)
    db[user_id] = {
        "hp_hex":    hashed_password.hex(),
        "algorithm": algorithm,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    _save_db(db)

    print(f"  [SERVER] ✓ Registered user '{user_id}'")
    print(f"  [SERVER] ✓ Stored H(password) = {hashed_password.hex()[:32]}...")
    print(f"  [SERVER] ✓ Hash algorithm used: {algorithm}")

    return {"status": "OK", "message": f"User '{user_id}' registered successfully."}


# ─────────────────────────────────────────────
#  PHASE 2 — AUTHENTICATION  (Step A)
#  Server receives (ID, Nc) and responds with Ns
# ─────────────────────────────────────────────

def start_authentication(user_id: str, nc: bytes) -> dict:
    """
    Handle the first authentication message from the client.
    The client sends (ID, Nc). The server:
      1. Looks up the user in the database
      2. Generates a fresh server nonce Ns
      3. Retrieves H(password) for the user
      4. Sends Ns back to the client

    WHY the server generates its own nonce (Ns):
      This guarantees server-side freshness. Even if an attacker
      replays an old (ID, Nc) pair, the server's new Ns makes the
      session different → the ASCON ciphertext won't match any replay.

    Args:
        user_id: the user's identifier
        nc:      client nonce (16 bytes)
    Returns:
        dict with 'ns' (server nonce) or error status
    """
    db = _load_db()

    if user_id not in db:
        print(f"  [SERVER] ✗ Unknown user '{user_id}'")
        return {"status": "ERROR", "message": "User not found."}

    # Generate fresh server nonce
    ns = generate_nonce(16)

    print(f"  [SERVER] ← Received ID='{user_id}', Nc={nc.hex()[:16]}...")
    print(f"  [SERVER] → Generated Ns={ns.hex()[:16]}...")
    print(f"  [SERVER] ✓ Retrieved H(password) from database")

    # Temporarily return ns (in a real system, this would be sent over the network)
    return {
        "status": "OK",
        "ns":     ns,
        "user_id": user_id  # echo back for confirmation
    }


# ─────────────────────────────────────────────
#  PHASE 2 — AUTHENTICATION  (Step B)
#  Server receives (Msg, Tag) and verifies
# ─────────────────────────────────────────────

def verify_authentication(user_id: str, nc: bytes, ns: bytes,
                           ciphertext_with_tag: bytes) -> dict:
    """
    Verify the client's authentication message.

    The server:
      1. Decrypts Msg using ASCON (key=K, nonce=Nc, assoc_data=Ns)
      2. Verifies the authentication tag (integrity check)
      3. Retrieves H(password) from the database
      4. Compares the decrypted Hp with the stored hash
      5. Returns OK or FAIL

    WHY ASCON tag verification comes BEFORE hash comparison:
      If the tag is invalid (tampered message), we immediately reject.
      This prevents an attacker from probing the hash comparison step
      and leaking timing information about partial matches.

    Args:
        user_id:              the authenticating user
        nc:                   client nonce (used as ASCON nonce)
        ns:                   server nonce (used as ASCON associated data)
        ciphertext_with_tag:  ASCON output = ciphertext ‖ tag
    Returns:
        dict with 'status', 'message', and optionally 'session_key'
    """
    db = _load_db()

    if user_id not in db:
        return {"status": "FAIL", "message": "User not found."}

    # ── Step 1: ASCON Decryption + Tag Verification ──────────────────
    print(f"  [SERVER] ← Received ciphertext+tag ({len(ciphertext_with_tag)} bytes)")
    print(f"  [SERVER] ⏳ Decrypting with ASCON-128...")

    plaintext = ascon_decrypt(
        key=SHARED_KEY,
        nonce=nc,                    # ASCON nonce = client nonce Nc
        associated_data=ns,          # authenticated (not encrypted) = Ns
        ciphertext_with_tag=ciphertext_with_tag
    )

    if plaintext is None:
        # Tag verification FAILED → reject immediately
        print(f"  [SERVER] ✗ ASCON tag verification FAILED — possible tampering!")
        return {"status": "FAIL", "message": "Tag verification failed. Authentication rejected."}

    print(f"  [SERVER] ✓ ASCON tag verified — message integrity confirmed")

    # ── Step 2: Hash Comparison ───────────────────────────────────────
    # Retrieve stored H(password)
    stored_hp_hex = db[user_id]["hp_hex"]
    stored_hp     = bytes.fromhex(stored_hp_hex)

    # The decrypted plaintext IS Hp (= H(password) sent by the client)
    received_hp = plaintext

    print(f"  [SERVER] ⏳ Comparing H(password)...")
    print(f"  [SERVER]    Received Hp = {received_hp.hex()[:32]}...")
    print(f"  [SERVER]    Stored   Hp = {stored_hp_hex[:32]}...")

    # Use constant-time comparison to prevent timing attacks
    # WHY: A character-by-character comparison leaks information about
    #      how many characters match via timing differences.
    import hmac
    if hmac.compare_digest(received_hp, stored_hp):
        # ── SUCCESS ──────────────────────────────────────────────────
        session_key = generate_nonce(32)  # 256-bit session key
        print(f"  [SERVER] ✓ Authentication SUCCESSFUL for user '{user_id}'")
        print(f"  [SERVER] ✓ Session key established: {session_key.hex()[:32]}...")
        return {
            "status": "OK",
            "message": "Authentication successful. Secure session established.",
            "session_key": session_key
        }
    else:
        # ── FAILURE ──────────────────────────────────────────────────
        print(f"  [SERVER] ✗ Hash mismatch — Authentication FAILED for user '{user_id}'")
        return {"status": "FAIL", "message": "Password hash mismatch. Authentication rejected."}


# ─────────────────────────────────────────────
#  UTILITY: Show current database (debug only)
# ─────────────────────────────────────────────

def show_database():
    """Display the server's user database (for debugging/demo)."""
    db = _load_db()
    print("\n  [SERVER DATABASE]")
    print(f"  {'─'*55}")
    if not db:
        print("  (empty)")
    for uid, record in db.items():
        print(f"  User ID  : {uid}")
        print(f"  H(pwd)   : {record['hp_hex'][:32]}...")
        print(f"  Algorithm: {record['algorithm']}")
        print(f"  Created  : {record['created_at']}")
        print(f"  {'─'*55}")


def clear_database():
    """Remove the database file (for test resets)."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("  [SERVER] Database cleared.")
