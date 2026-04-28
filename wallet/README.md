# Wallet Proof

This module validates the final Bitcoin-side derivation step used in the
paper:

"An Empirical Analysis of CryptGenRandom in Windows XP SP3 and Its
Historical Relevance to Bitcoin 0.1.5"

It starts from a captured RAND_bytes output observed after the OpenSSL
PRNG path and checks that this 32-byte value is exactly the secret key
material used to derive the corresponding Bitcoin wallet key and address.

------------------------------------------------------------------

### Relation validated

RAND_bytes output
→ 32-byte secret candidate
→ WIF
→ public key
→ P2PKH address

The script verifies both uncompressed and compressed encodings for
completeness, although historical Bitcoin 0.1.5 wallet keys are associated
with uncompressed public keys.

------------------------------------------------------------------

### Files

sample01/
├── prng_log_excerpt.jsonl   (excerpt containing the RAND_bytes output)
└── expected.json            (expected WIF and address values)

------------------------------------------------------------------

### Usage

python3 wallet_proof.py sample01/prng_log_excerpt.jsonl

------------------------------------------------------------------

### Expected result

The script should report:

RAND==SECRET:   OK
WIF uncomp:     OK
WIF comp:       OK
P2PKH uncomp:   OK
P2PKH comp:     OK

------------------------------------------------------------------

### Interpretation

This validation does not replay OpenSSL or Bitcoin internally. Instead, it
checks the deterministic Bitcoin key-derivation consequence of a captured
32-byte RAND_bytes output.

In other words, it verifies that the observed random bytes, once interpreted
as a private key candidate, reproduce the expected WIF encodings and P2PKH
addresses byte-for-byte.

------------------------------------------------------------------

### Scope

This module validates the final wallet-facing derivation step only. It does
not claim to reconstruct the preceding CryptGenRandom, OpenSSL, or provider
state transitions.
