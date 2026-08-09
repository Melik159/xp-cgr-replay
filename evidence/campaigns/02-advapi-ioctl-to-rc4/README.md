# ADVAPI IOCTL to RC4 State

Original identifier: `seed2state_v17_1_precise_ioctl_outbuf`  
Status: **PASS**  
Capture availability: retained log.

The parser regenerates all retained samples from `capture/sample01.log`.
Validation checks ten direct IOCTL-buffer-to-KSA-state relations, four useful
PRGA calls, and mutation-based negative controls for both KSA and PRGA.

```bash
python3 validate.py
```

This is an ADVAPI-side local relation and does not identify the full upstream
source of the IOCTL material.

