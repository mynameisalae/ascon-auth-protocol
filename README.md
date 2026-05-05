**Lightweight Cryptography**

**Design and Analysis of a Lightweight Authentication Protocol Using
ASCON and Hash Functions**


# 1. Introduction

The explosion of connected devices in the Internet of Things (IoT)
landscape --- sensors, smart meters, medical implants, industrial
controllers --- has created an urgent need for cryptographic protocols
that are both secure and resource-efficient. Traditional cryptographic
algorithms (AES, RSA, SHA-2) were designed for general-purpose hardware
with ample CPU cycles and memory. On a microcontroller running at 8 MHz
with 256 bytes of RAM, these algorithms may be too slow or simply too
large to fit.

Lightweight cryptography addresses this gap. In 2023, NIST (the National
Institute of Standards and Technology) standardized ASCON as the primary
lightweight authenticated encryption algorithm after a rigorous
multi-year competition. ASCON was specifically designed for constrained
environments while maintaining robust security guarantees.

This practical lab (TP) explores the design and implementation of a
complete authentication protocol built upon ASCON-128 (for authenticated
encryption) and a selection of hash functions (SHA-256, SHA3-256,
BLAKE2b). The protocol allows a client to prove its identity to a server
without transmitting the password in any recoverable form.

# 2. Objective

The primary objective of this laboratory is to design, implement, and
analyze a lightweight mutual authentication protocol. The specific goals
are:

1.  Implement a three-phase authentication protocol: Registration,
    Authentication, and Secure Session establishment.

2.  Apply ASCON-128 AEAD encryption to protect the authentication
    message, ensuring confidentiality and integrity simultaneously.

3.  Use cryptographic hash functions (SHA-256, SHA3-256, BLAKE2b) for
    password hashing, and compare their performance characteristics.

4.  Analyze the security properties of the protocol against common
    attacks: replay attacks, eavesdropping, identity impersonation,
    message tampering, and man-in-the-middle attacks.

5.  Evaluate the execution performance of the chosen hash functions
    through systematic benchmarking.

# 3. System Architecture

## 3.1 Participants

The protocol involves two parties:

- **Client ---** The Client: represents a user (or IoT device) that
  wishes to authenticate. It computes H(password) and performs ASCON
  encryption using a pre-shared key K.

- **Server ---** The Server: holds a database of registered users
  (storing only H(password), never the plaintext). It generates
  challenges, verifies ASCON-authenticated messages, and grants or
  denies access.

Communication is assumed to occur over an insecure channel (e.g., a
public network). The pre-shared key K is established out-of-band (e.g.,
during device provisioning). In a production system, K would be
established via a Diffie-Hellman key exchange or a certificate-based
handshake.

## 3.2 Protocol Flow (Three Phases)

### Phase 1 --- Registration (one-time)

The client chooses a password and computes its hash H(password) using
the agreed algorithm. Only the hash is transmitted to the server. The
server stores H(password) in its database. The plaintext password never
leaves the client device.

| Partie | Direction | Données / Action |
| :--- | :---: | :--- |
| **Client** | | Calcule $H(password)$ |
| **Client** | → Serveur | Envoie : `user_id`, `H(password)` |
| **Serveur** | | Stocke `H(password)` dans la base de données |

### Phase 2 --- Authentication (per session)

This phase uses a challenge-response mechanism with two fresh nonces to
prevent replay attacks:

| Partie | Direction | Données / Action |
| :--- | :---: | :--- |
| **Client** | → Serveur | Envoie : `user_id`, `Nc` (Nonce client frais) |
| **Serveur** | | Génère `Ns` frais ; récupère `H(password)` de la DB |
| **Serveur** | → Client | Envoie : `Ns` (Nonce serveur) |
| **Client** | | Calcule : `Hp = H(password)` ; chiffre avec ASCON |
| **Client** | → Serveur | Envoie : `Msg = ASCON_Enc(K, nonce=Nc, assoc=Ns, plain=Hp)`, `Tag` |
| **Serveur** | | Déchiffre avec ASCON ; vérifie le `Tag` ; compare `Hp` |
| **Serveur** | → Client | Envoie : `OK` ou `FAIL` |

### Phase 3 --- Secure Session

Upon successful authentication, the server generates a fresh session key
(256-bit random value) and confirms session establishment. Both parties
can use this session key for subsequent encrypted communication.

## 3.3 Key Design Parameters

| Paramètre | Valeur | Raisonnement de Sécurité |
| :--- | :--- | :--- |
| **Variante ASCON** | Ascon-128 | [cite_start]Niveau de sécurité 128 bits, clé de 16 octets  |
| **Nonce ASCON** | `Nc` (16 octets) | [cite_start]Généré par le client, unique par session  |
| **Données Associées** | `Ns` (16 octets) | [cite_start]Lie le texte chiffré au défi (challenge) du serveur  |
| **Texte en Clair** | `Hp = H(password)` | [cite_start]32 octets (condensat SHA-256)  |
| **Clé de Session** | 32 octets (aléatoire) | [cite_start]Clé éphémère de 256 bits par session [cite: 48, 88] |
| **Comparaison de Hash** | `hmac.compare_digest()` | [cite_start]Temps constant : prévient les attaques par analyse temporelle  |

# 4. Implementation Details

## 4.1 Environment Setup

The implementation uses Python 3.10+ with the following dependencies:

> pip install ascon

The ascon library provides ASCON-128, ASCON-128a, and ASCON-80pq
variants. Built-in Python modules (hashlib, os, hmac, time) handle hash
functions, nonce generation, and timing. No external dependencies are
required beyond ascon.

Project structure:

> ascon_auth_protocol/
>
> common.py \# Shared utilities: hash functions, ASCON wrappers, nonce
> generation
>
> server.py \# Server: registration DB, authentication verification
>
> client.py \# Client: registration request, auth message construction
>
> performance_test.py# Benchmark: hash function and ASCON timing
>
> run_demo.py \# Orchestrates the full 3-phase protocol demo

## 4.2 Phase 1 --- Registration Implementation

On the client side, the password is hashed using the chosen algorithm
before any network transmission. The hash is computed as:

> Hp = hashlib.sha256(password.encode(\'utf-8\')).digest() \# 32 bytes

The server receives Hp and stores it as a hex string in a JSON file
(simulating a database). The server never stores the plaintext password,
so even a complete database leak only exposes password hashes.

<img width="888" height="633" alt="image" src="https://github.com/user-attachments/assets/17e87457-563f-431c-a423-6b1c760d6443" />


## 4.3 Phase 2 --- Authentication Implementation

The ASCON-128 encryption is performed as follows:

> ciphertext_tag = ascon.encrypt(
>
> key = K, \# 16-byte pre-shared key
>
> nonce = Nc, \# 16-byte client nonce (session-unique)
>
> associateddata = Ns, \# 16-byte server nonce (authenticated, not
> encrypted)
>
> plaintext = Hp, \# 32-byte password hash
>
> variant = \'Ascon-128\'
>
> ) \# Returns 48 bytes: 32 ciphertext + 16 tag

The output is 48 bytes: 32 bytes of ciphertext (same length as Hp)
followed by a 16-byte authentication tag. The server decrypts and
verifies:

> plaintext = ascon.decrypt(K, Nc, Ns, ciphertext_tag,
> variant=\'Ascon-128\')
>
> \# Raises exception if tag is invalid --- never returns partial
> plaintext

The hash comparison uses hmac.compare_digest() to ensure constant-time
evaluation, preventing timing side-channel attacks:

> import hmac
>
> if hmac.compare_digest(received_hp, stored_hp): \# constant-time
>
> \# Grant access

<img width="969" height="1204" alt="image" src="https://github.com/user-attachments/assets/d6eb8fc6-0a1d-4661-884a-2d428c7b15cb" />

<img width="969" height="1057" alt="image" src="https://github.com/user-attachments/assets/72cbc7b1-fd30-4f5f-9fd2-812febe4deab" />

## 4.4 Phase 3 --- Session Key

Upon successful authentication, the server generates a 256-bit (32-byte)
session key using os.urandom(32). This key is sent to the client and can
be used for symmetric encryption of subsequent communications. The
session key is ephemeral --- a new one is generated for every
authentication --- providing forward secrecy: compromise of one session
key does not affect past or future sessions.

NOTE: The implementation was tested using a full demo script
(run_demo.py) that executes:

\- Registration phase

\- Successful authentication

\- Failed authentication (wrong password simulation)

\- Performance benchmarking

The outputs confirm correct protocol behavior.

# 5. Security Analysis

## 5.1 Protection Against Replay Attacks

A replay attack occurs when an adversary captures a valid authentication
message and retransmits it in a future session to gain unauthorized
access.

This protocol is protected against replay attacks by the dual-nonce
mechanism:

- Nc is generated fresh by the client for every authentication attempt.
  It is used as the ASCON nonce --- ASCON guarantees that using the same
  nonce twice under the same key produces different ciphertext, but more
  importantly, the nonce is fresh so no old ciphertext was ever produced
  under this Nc.

- Ns is generated fresh by the server as a per-session challenge. Even
  if an attacker replays (ID, Nc) from a previous session, the server
  will respond with a new Ns. The ASCON ciphertext that the attacker has
  from the old session was encrypted under the old Ns as associated
  data. It will fail ASCON tag verification under the new Ns.

Formally: the ASCON tag covers (key=K, nonce=Nc, assoc_data=Ns,
plaintext=Hp). For a replayed message to pass, the attacker would need
to forge a valid tag under different Ns, which requires breaking the
ASCON authentication --- infeasible under the 128-bit security level.

## 5.2 Confidentiality

The password hash Hp is never transmitted in plaintext. It is encrypted
by ASCON-128, which is a stream cipher with polynomial MAC. The
ciphertext is computationally indistinguishable from random without the
key K. An eavesdropper who intercepts (Msg, Tag) cannot recover Hp (or
the password) without K.

Additionally, even Hp itself is a one-way transformation of the
password. An attacker who somehow obtains Hp cannot reverse it to the
password without brute force.

## 5.3 Integrity and Authentication

The 16-byte ASCON authentication tag provides integrity guarantees. Any
modification to the ciphertext --- even a single bit --- will cause tag
verification to fail with overwhelming probability (probability 2\^-128
of a random tag being valid). This protects against:

- Message tampering: an attacker modifying Msg in transit will cause the
  server to reject the message.

- Identity impersonation: an attacker who does not know K cannot forge a
  valid (Msg, Tag) pair for a legitimate user.

- Man-in-the-middle attacks: the associated data Ns binds the message to
  the server's challenge. An active attacker who modifies Ns will break
  tag verification; one who keeps the original Ns cannot replay it in a
  different session.

## 5.4 Protected Attack Surface

| Attaque | Mécanisme | Protection |
| :--- | :--- | :--- |
| **Écoute clandestine** | Interception passive des messages | [cite_start]Chiffrement ASCON du hash `Hp` [cite: 107, 108, 120] |
| **Attaque par rejeu** | Retransmission d'une session capturée | [cite_start]Nonces `Nc` et `Ns` frais par session [cite: 98, 120] |
| **Usurpation d'identité** | Forger des messages comme un autre utilisateur | [cite_start]Tag ASCON — nécessite la clé secrète `K` [cite: 112, 115, 120] |
| **Altération de message** | Modifier le texte chiffré en transit | [cite_start]Tag d'authentification ASCON [cite: 112, 114, 120] |
| **Fuite de la base de données** | Lecture directe de la base du serveur | [cite_start]Seul le hash `H(password)` est stocké, pas le texte clair [cite: 120, 145] |
| **Canal auxiliaire temporel** | Mesure du temps de comparaison des hashs | [cite_start]`hmac.compare_digest()` en temps constant [cite: 120, 148] |

# 6. Performance Evaluation

## 6.1 Hash Function Comparison

Three hash functions were evaluated over 10,000 iterations on a standard
desktop CPU. All three produce 256-bit (32-byte) digests, making them
equivalent in security output size. The differences lie in their
internal construction and software performance:

| Algorithme | Design Interne | Sortie | Temps Moyen | Notes |
| :--- | :--- | :---: | :---: | :--- |
| **SHA-256** | Merkle-Damgaard | 256 bits | ~0.48 µs | Standard NIST, accélération matérielle sur x86 |
| **SHA3-256** | Keccak sponge | 256 bits | ~0.72 µs | Résiste aux attaques par extension de longueur |
| **BLAKE2b** | HAIFA + ChaCha | 256 bits | ~0.52 µs | Le plus rapide en logiciel ; utilisé dans WireGuard |

These results confirm that SHA-256 is the fastest on our machine, likely
due to hardware acceleration.

Note: Actual timings will vary depending on your hardware. On x86-64
CPUs with SHA-NI instructions, SHA-256 may be faster than BLAKE2b. On
ARM Cortex-M (IoT devices without SHA-NI), BLAKE2b often wins.

<img width="969" height="1099" alt="image" src="https://github.com/user-attachments/assets/17898276-7bea-4451-ae5f-61da878c59c9" />

## 6.2 ASCON-128 Performance

ASCON-128 encryption and decryption were benchmarked at approximately
3,500 operations per second in Python for 32-byte payloads. This figure
is expected for a Python software implementation --- the reference C
implementation achieves several hundred megabytes per second, and
hardware implementations on FPGAs can reach tens of gigabytes per
second.

The Python ascon library is a reference implementation intended for
correctness and education, not production throughput. For production IoT
deployment, ASCON would be implemented in C/C++ firmware or with
hardware acceleration. The protocol overhead per authentication session
is negligible: one ASCON encrypt + one ASCON decrypt + one hash
computation.

## 6.3 Suitability for Lightweight Environments

From the performance analysis, we draw the following conclusions for IoT
deployment:

- SHA-256 is the preferred hash for devices with SHA-NI hardware
  acceleration (many modern ARM Cortex-A and RISC-V cores include this).

- BLAKE2b is preferred in pure software environments due to its higher
  throughput and low memory footprint (no lookup tables required).

- SHA3-256 offers the strongest design diversity (different from SHA-2
  family) at the cost of slightly lower throughput --- appropriate when
  length-extension resistance is required.

- ASCON-128 is the ideal AEAD cipher for this protocol: winner of the
  NIST Lightweight Cryptography competition, designed for 8-bit to
  64-bit platforms, with a small state and simple operations.

# 7. Conclusion

This laboratory successfully designed and implemented a three-phase
lightweight authentication protocol based on ASCON-128 authenticated
encryption and cryptographic hash functions. The protocol achieves its
security objectives:

- Registration stores only H(password), protecting user credentials even
  in the event of database compromise.

- Authentication uses dual nonces (Nc, Ns) to prevent replay attacks,
  ensuring each session is cryptographically unique.

- ASCON-128 provides simultaneous confidentiality and integrity of the
  transmitted password hash, with a minimal 16-byte tag overhead.

- The server uses constant-time comparison to prevent timing
  side-channel attacks on the hash verification step.

The performance evaluation demonstrated that all three hash functions
(SHA-256, SHA3-256, BLAKE2b) are practically viable for IoT
authentication, with sub-microsecond average execution times. BLAKE2b
achieved the highest throughput in software (\~1.5 million hashes per
second), while SHA-256 is the most universally deployable given hardware
acceleration support.

ASCON\'s selection by NIST as the lightweight cryptography standard
validates its use in this protocol. Its sponge-based permutation
requires minimal hardware resources (as few as 2,000 gates on ASIC)
while maintaining 128-bit security, making it ideal for IoT and embedded
systems authentication protocols.

Future work could extend this protocol with mutual authentication
(server also proves its identity to the client), key derivation from the
session nonces, and formal security verification using tools such as
ProVerif or Tamarin prover.
