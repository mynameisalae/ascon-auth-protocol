"""
run_demo.py — Full Protocol Demonstration
TP2: Lightweight Cryptography using ASCON and Hash Functions
ENSA Tangier — Prof. S. LAZAAR

This script demonstrates the complete 3-phase protocol:
  Phase 1: Registration
  Phase 2: Authentication (success + failure)
  Phase 3: Performance benchmarks

Run with:  python run_demo.py
"""

import sys
import os

# Make sure we can import local modules
sys.path.insert(0, os.path.dirname(__file__))

import client
import server
from performance_test import run_hash_benchmark, run_ascon_benchmark, run_comparison_summary

SEP = "═" * 65


def banner(title: str) -> None:
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def section(title: str) -> None:
    print(f"\n  ┌─ {title}")
    print(f"  │")


# ─────────────────────────────────────────────────────────────────
#  CLEAN SLATE: remove any previous database
# ─────────────────────────────────────────────────────────────────
server.clear_database()


# ═════════════════════════════════════════════════════════════════
#  PHASE 1 — REGISTRATION
# ═════════════════════════════════════════════════════════════════
banner("PHASE 1 — REGISTRATION")

USER_ID   = "alice_2025"
PASSWORD  = "SecurePass@ENSA42"
ALGORITHM = "SHA-256"

section("CLIENT: Preparing registration request")
reg_request = client.register(USER_ID, PASSWORD, ALGORITHM)

print(f"\n  │")
section("SERVER: Processing registration")
reg_response = server.register_user(
    user_id          = reg_request["user_id"],
    hashed_password  = reg_request["hashed_password"],
    algorithm        = reg_request["algorithm"]
)

print(f"\n  └─ Result: {reg_response['message']}")

# Show what the database looks like
print()
server.show_database()


# ═════════════════════════════════════════════════════════════════
#  PHASE 2 — AUTHENTICATION (SCENARIO A: Correct password)
# ═════════════════════════════════════════════════════════════════
banner("PHASE 2A — AUTHENTICATION (Correct Password)")

section("CLIENT → SERVER: Sending (ID, Nc)")
auth_start = client.start_authentication(USER_ID)
nc = auth_start["nc"]

print(f"\n  │")
section("SERVER → CLIENT: Returning Ns")
challenge = server.start_authentication(USER_ID, nc)

if challenge["status"] != "OK":
    print(f"  └─ Error: {challenge['message']}")
    sys.exit(1)

ns = challenge["ns"]
print(f"  └─ Ns sent to client")

print(f"\n  │")
section("CLIENT: Building ASCON-encrypted authentication message")
auth_msg = client.build_auth_message(PASSWORD, nc, ns, ALGORITHM)

print(f"\n  │")
section("SERVER: Decrypting and verifying authentication message")
auth_result = server.verify_authentication(
    user_id              = USER_ID,
    nc                   = auth_msg["nc"],
    ns                   = ns,
    ciphertext_with_tag  = auth_msg["ciphertext_with_tag"]
)

print(f"\n  │")
section("CLIENT: Handling server response")
success = client.handle_auth_response(auth_result)

print(f"\n  └─ ✓ AUTHENTICATION RESULT: {'SUCCESS ✓' if success else 'FAILED ✗'}")


# ═════════════════════════════════════════════════════════════════
#  PHASE 2 — AUTHENTICATION (SCENARIO B: Wrong password)
# ═════════════════════════════════════════════════════════════════
banner("PHASE 2B — AUTHENTICATION (Wrong Password — Attack Simulation)")

WRONG_PASSWORD = "WrongPassword123"
print(f"  Simulating: attacker uses password '{WRONG_PASSWORD}'")

section("CLIENT → SERVER: Sending (ID, Nc)")
auth_start2 = client.start_authentication(USER_ID)
nc2 = auth_start2["nc"]

print(f"\n  │")
section("SERVER → CLIENT: Returning Ns")
challenge2 = server.start_authentication(USER_ID, nc2)
ns2 = challenge2["ns"]

print(f"\n  │")
section("CLIENT: Encrypting with WRONG password hash")
auth_msg2 = client.build_auth_message(WRONG_PASSWORD, nc2, ns2, ALGORITHM)

print(f"\n  │")
section("SERVER: Verifying (should FAIL)")
auth_result2 = server.verify_authentication(
    user_id              = USER_ID,
    nc                   = auth_msg2["nc"],
    ns                   = ns2,
    ciphertext_with_tag  = auth_msg2["ciphertext_with_tag"]
)

print(f"\n  │")
section("CLIENT: Handling server response")
success2 = client.handle_auth_response(auth_result2)

print(f"\n  └─ AUTHENTICATION RESULT: {'SUCCESS' if success2 else 'FAILED ✗ (expected)'}")


# ═════════════════════════════════════════════════════════════════
#  PHASE 3 — PERFORMANCE EVALUATION
# ═════════════════════════════════════════════════════════════════
banner("PHASE 3 — PERFORMANCE EVALUATION")

hash_results = run_hash_benchmark(iterations=10_000)
run_ascon_benchmark(iterations=10_000)
run_comparison_summary(hash_results)


# ═════════════════════════════════════════════════════════════════
#  DONE
# ═════════════════════════════════════════════════════════════════
print(f"\n{SEP}")
print("  TP2 Demo complete.")
print("  Phases demonstrated: Registration | Authentication | Performance")
print(SEP)
