# Kernel VLH Replay

Source directory: `vlh/`.

The retained sample contains a captured pool, QSI source fragments, before and
after seed values, and `seedbase_after`. The validator checks the pool mapping
and exact SHA-1-based VLH reconstruction.

```bash
python3 validate.py --block 02-kernel-entropy
```

Evidence level: replay from retained binary samples. Only one public campaign
is included.

