# Block 06: Provider Primitives

This block contains three small, independently checkable relations:

- a retained provider-local XOR;
- two standard SHA-1 compression blocks producing a retained 40-byte result;
- one RC4 KSA producing a retained 256-byte S-box.

```bash
python3 validate.py
```

The validator converts the old print-only FIPS comparison into a fail-closed
check. The provider XOR sample and FIPS sample are separate observations and
are not presented as one correlated call.

