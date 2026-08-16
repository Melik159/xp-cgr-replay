Windows XP SP3 CryptGenRandom
Two-run exhaustive multisource differential validation

Run1:
  240/240 cases PASS
  61,440/61,440 Python == Rust == CUDA bit-for-bit

Run2:
  240/240 cases PASS
  61,440/61,440 Python == Rust == CUDA bit-for-bit

Combined:
  2 independent captured executions
  480/480 cases PASS
  122,880/122,880 outputs matched bit-for-bit
  across Python, Rust and CUDA.

Boundary:
  The deterministic reconstruction begins at the retained pre-call state
  and observed source-return buffers. This is not a claim about the
  complete physical provenance or information-theoretic entropy of all
  Windows XP sources.
