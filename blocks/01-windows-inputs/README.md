# Block 01: Windows Input Captures

This block structurally decodes and validates three retained Windows
`RAND_poll` input collections.

```bash
python3 validate.py
```

The check validates record structure, source-specific coherence, and the three
published runs. Warnings about a process ID missing from a process snapshot are
retained and do not indicate malformed input.

This block does not concatenate the records into an OpenSSL seed stream and
does not reconstruct the OpenSSL stirring procedure.

Evidence: `evidence/components/windows-rand-poll/`.

