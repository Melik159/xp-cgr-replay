# Block 04: ADVAPI RC4 and SystemFunction036

This block validates selected relations downstream of ADVAPI IOCTL buffers:

```text
IOCTL output material -> RC4 KSA state -> useful PRGA output
                     -> SystemFunction036 output -> provider aux20
```

```bash
python3 validate.py
```

The block uses V5, V17.1, and V18.1. V17.1 includes key and state mutation
controls. These results do not establish the upstream derivation of every
IOCTL buffer.

