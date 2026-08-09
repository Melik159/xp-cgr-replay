# Bitcoin Wallet Derivation Sample

Source directory: `wallet/`.

The retained files contain one 32-byte `ssleay_rand_bytes/after` record and the
expected Bitcoin encodings. Validation block 08 independently derives the
secp256k1 public point, both WIF encodings, and both P2PKH addresses.

```bash
python3 validate.py --block 08-bitcoin-wallet
```

The same block requires these 32 bytes to match the retained OpenSSL post-stir
output. The sample is a deterministic consistency artifact, not a historical
key-recovery claim.

