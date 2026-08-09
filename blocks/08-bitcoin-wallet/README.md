# Block 08: Bitcoin Wallet Derivation

This block independently verifies:

```text
retained OpenSSL output
  -> 256-bit private scalar
  -> secp256k1 public keys
  -> compressed and uncompressed WIF
  -> compressed and uncompressed P2PKH addresses
```

```bash
python3 validate.py
```

Unlike the historical wallet script, the block validator performs the
secp256k1 scalar multiplication itself and requires the OpenSSL and wallet
32-byte outputs to be identical.

This is a deterministic consistency proof for the retained synthetic sample,
not evidence of historical key recovery.

