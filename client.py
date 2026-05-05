"""
client.py — Client-side logic for the Lightweight Authentication Protocol
TP2: Lightweight Cryptography using ASCON and Hash Functions
ENSA Tangier — Prof. S. LAZAAR

Responsibilities:
  Phase 1 (Registration):   Hash the password and send H(password) to the server.
  Phase 2 (Authentication): Generate Nc, send (ID, Nc), receive Ns,
                             build and encrypt message with ASCON, send (Msg, Tag).
  Phase 3 (Session):        Receive session confirmation.
"""

from common import (
    SHARED_KEY,
    generate_nonce,
    compute_hash,
    ascon_encrypt,
)


# ─────────────────────────────────────────────
#  PHASE 1 — REGISTRATION
# ─────────────────────────────────────────────

def register(user_id: str, password: str, algorithm: str = "SHA-256") -> dict:
    """
    Prepare a registration request.

    WHY the client hashes the password before sending:
      The plaintext password should NEVER travel over the network,
      not even over TLS — defense in depth.
      The server only ever needs H(password), not the password itself.

    Args:
        user_id:   chosen username/ID
        password:  plaintext password chosen by the user
        algorithm: hash function to use
    Returns:
        dict with 'user_id', 'hashed_password', 'algorithm'
    """
    print(f"  [CLIENT] ✓ User ID    : {user_id}")
    print(f"  [CLIENT] ✓ Password   : {'*' * len(password)}")

    # Compute H(password)
    hp = compute_hash(password, algorithm)

    print(f"  [CLIENT] ✓ Algorithm  : {algorithm}")
    print(f"  [CLIENT] ✓ H(password): {hp.hex()[:32]}...  ({len(hp)} bytes)")
    print(f"  [CLIENT] → Sending H(password) to server...")

    return {
        "user_id":          user_id,
        "hashed_password":  hp,
        "algorithm":        algorithm,
    }


# ─────────────────────────────────────────────
#  PHASE 2 — AUTHENTICATION  (Step A)
#  Client generates Nc and sends (ID, Nc)
# ─────────────────────────────────────────────

def start_authentication(user_id: str) -> dict:
    """
    Initiate authentication by generating a client nonce Nc.

    WHY Nc (client nonce):
      Proves the request is fresh — not a replay of a captured session.
      Combined with the server's Ns, the pair (Nc, Ns) is unique per session.

    Args:
        user_id: the user attempting to authenticate
    Returns:
        dict with 'user_id' and 'nc'
    """
    nc = generate_nonce(16)
    print(f"  [CLIENT] → Sending to server: ID='{user_id}', Nc={nc.hex()[:16]}...")
    return {"user_id": user_id, "nc": nc}


# ─────────────────────────────────────────────
#  PHASE 2 — AUTHENTICATION  (Step B)
#  Client receives Ns, builds and encrypts message
# ─────────────────────────────────────────────

def build_auth_message(password: str, nc: bytes, ns: bytes,
                        algorithm: str = "SHA-256") -> dict:
    """
    Build the authentication message and encrypt it with ASCON-128.

    Protocol formula (from TP diagram):
        Hp  = H(password)
        Msg, Tag = ASCON_encrypt(K, nonce=Nc, assoc_data=Ns, plaintext=Hp)

    WHY encrypt H(password) and not send it directly:
      1. Confidentiality: Even H(password) must not be exposed on the wire —
         an attacker who captures it could replay it on another server.
      2. Nonce binding: Encrypting under (K, Nc, Ns) binds this message to
         this specific session. A replay in a different session would use
         different Nc/Ns → ASCON tag verification fails → rejected.
      3. Integrity: The ASCON tag prevents tampering with Hp in transit.

    Args:
        password:  user's plaintext password
        nc:        client nonce (16 bytes) — used as ASCON nonce
        ns:        server nonce (16 bytes) — used as ASCON associated data
        algorithm: hash algorithm for H(password)
    Returns:
        dict with 'ciphertext_with_tag' and 'nc'
    """
    # Step 1: Compute Hp = H(password)
    hp = compute_hash(password, algorithm)
    print(f"  [CLIENT] ✓ Computed Hp = H(password) = {hp.hex()[:32]}...")
    print(f"  [CLIENT] ✓ Nc = {nc.hex()[:16]}...")
    print(f"  [CLIENT] ✓ Ns = {ns.hex()[:16]}...")

    # Step 2: Encrypt Hp using ASCON-128
    #   key   = pre-shared key K (16 bytes)
    #   nonce = Nc (fresh client nonce, 16 bytes)
    #   assoc = Ns (server nonce, authenticated but not encrypted)
    #   plain = Hp (password hash, 32 bytes for SHA-256/SHA3-256/BLAKE2b)
    ciphertext_with_tag = ascon_encrypt(
        key=SHARED_KEY,
        nonce=nc,           # session-unique nonce
        associated_data=ns, # binds message to this server's challenge
        plaintext=hp
    )

    ct_len  = len(ciphertext_with_tag) - 16  # ciphertext portion
    tag_len = 16                              # ASCON-128 tag is always 16 bytes

    print(f"  [CLIENT] ✓ ASCON encryption done:")
    print(f"            Ciphertext ({ct_len} bytes): {ciphertext_with_tag[:ct_len].hex()[:32]}...")
    print(f"            Tag        ({tag_len} bytes): {ciphertext_with_tag[ct_len:].hex()}")
    print(f"  [CLIENT] → Sending (Msg, Tag) to server...")

    return {
        "ciphertext_with_tag": ciphertext_with_tag,
        "nc": nc,  # The server needs Nc to decrypt (it IS the ASCON nonce)
    }


# ─────────────────────────────────────────────
#  PHASE 3 — SECURE SESSION
# ─────────────────────────────────────────────

def handle_auth_response(response: dict) -> bool:
    """
    Handle the server's OK/FAIL response.

    Args:
        response: dict from server with 'status', 'message', optional 'session_key'
    Returns:
        True if authentication succeeded, False otherwise
    """
    if response["status"] == "OK":
        session_key = response.get("session_key", b"")
        print(f"  [CLIENT] ✓ Authentication SUCCESSFUL!")
        print(f"  [CLIENT] ✓ Secure session established.")
        print(f"  [CLIENT] ✓ Session key: {session_key.hex()[:32]}...")
        return True
    else:
        print(f"  [CLIENT] ✗ Authentication FAILED: {response['message']}")
        return False
