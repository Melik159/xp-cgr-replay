# Claim Boundaries

## Supported statements

The retained artifact supports narrow, execution-specific statements:

- the VLH sample reproduces its retained `seedbase_after` value;
- selected KSecDD and ADVAPI buffers are byte-identical at documented
  observation points;
- selected RC4 KSA and PRGA transitions replay exactly;
- selected `rsaenh` provider transitions replay from captured state and
  auxiliary inputs;
- V29 replays a composed provider initialization/bridge/runtime sequence in one
  execution;
- the OpenSSL trace reproduces the retained 32-byte post-stir output;
- those 32 bytes independently derive the retained secp256k1 public keys, WIFs,
  and P2PKH addresses.

## Unsupported statements

The artifact does not establish:

- a complete implementation of Windows XP SP3 `CryptGenRandom`;
- a single correlated trace from kernel entropy collection to the Bitcoin key;
- the complete provenance of provider `state20` from KSecDD/ADVAPI inputs;
- the complete OpenSSL stirring phase from Windows `RAND_poll` records;
- an entropy estimate for historical Windows XP or Bitcoin executions;
- recovery of an unknown historical private key;
- generalization to other Windows versions, service packs, providers, OpenSSL
  builds, or Bitcoin versions.

## V24 boundary

V24 is intentionally `PARTIAL`. The retained samples are sufficient to replay
16 KSA calls, 16 PRGA calls, and eight after/pre-return KSecDD equalities. The
full ADVAPI output-buffer dump was not captured reliably, so the artifact does
not promote V24 to a full transport closure.

