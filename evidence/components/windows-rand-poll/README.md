# Windows RAND_poll Input Decoder

Source directory: `randwin/`.

This component retains three Windows input-record captures and the structural
decoder used by validation block 01. It checks record parsing, ordering,
source-specific fields, cross-run comparison, and coherence warnings.

Run the normalized validator from the repository root:

```bash
python3 validate.py --block 01-windows-inputs
```

The component does not build an OpenSSL seed stream and does not claim an
entropy measurement.

