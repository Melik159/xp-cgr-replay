This script replays the final FIPS186-style SHA-1 compression stage from
two captured 64-byte internal blocks and verifies that their concatenated
20-byte compression outputs reproduce the observed 40-byte output buffer.
