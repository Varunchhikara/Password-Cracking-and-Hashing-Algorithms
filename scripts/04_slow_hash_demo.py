#!/usr/bin/env python3
"""
04_slow_hash_demo.py

Objective: Show why real systems use bcrypt/scrypt/argon2 instead of
salted SHA256/MD5 for password storage - the key difference is a
deliberate, tunable WORK FACTOR that makes each guess expensive.

Requires: pip install bcrypt --break-system-packages

Run: python3 04_slow_hash_demo.py
"""

import hashlib
import time

try:
    import bcrypt
except ImportError:
    bcrypt = None


def benchmark_fast_hash(n=500_000):
    start = time.perf_counter()
    for i in range(n):
        hashlib.sha256(str(i).encode()).hexdigest()
    elapsed = time.perf_counter() - start
    rate = n / elapsed
    print(f"  SHA256 (no work factor): {n:,} hashes in {elapsed:.2f}s "
          f"-> {rate:,.0f} hashes/sec (single CPU core)")
    return rate


def benchmark_bcrypt(n=20, cost=12):
    if bcrypt is None:
        print("  bcrypt not installed - skipping. Run: pip install bcrypt --break-system-packages")
        return None
    start = time.perf_counter()
    for i in range(n):
        bcrypt.hashpw(str(i).encode(), bcrypt.gensalt(rounds=cost))
    elapsed = time.perf_counter() - start
    rate = n / elapsed
    print(f"  bcrypt (cost={cost}):      {n} hashes in {elapsed:.2f}s "
          f"-> {rate:.2f} hashes/sec (single CPU core)")
    return rate


def bcrypt_usage_example():
    if bcrypt is None:
        return
    print("\n[bcrypt usage - salt is generated AND stored inside the hash string]")
    password = b"Password123"
    hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=10))
    print(f"  Stored value: {hashed.decode()}")
    print(f"  Verify correct password: {bcrypt.checkpw(b'Password123', hashed)}")
    print(f"  Verify wrong password:   {bcrypt.checkpw(b'wrongpass', hashed)}")


if __name__ == "__main__":
    print("Comparing raw SHA256 vs bcrypt hashing throughput")
    print("-" * 60)
    fast_rate = benchmark_fast_hash()
    bcrypt_rate = benchmark_bcrypt()

    if bcrypt_rate:
        factor = fast_rate / bcrypt_rate
        print(f"\n  SHA256 is ~{factor:,.0f}x faster than bcrypt(cost=12) on this machine.")
        print("  On a cracking rig with GPUs, that gap is what determines whether")
        print("  a leaked password database gets cracked in hours or in decades.")

    bcrypt_usage_example()

    print("""
TAKEAWAY
--------
- SHA256/MD5/SHA1 are designed to be FAST - great for file integrity,
  terrible for password storage, because attackers can also hash fast.
- bcrypt/scrypt/argon2 are designed to be SLOW and tunable (the "cost"
  or "work factor" parameter). Doubling the cost roughly doubles
  attacker effort per guess, with only a small fixed cost to you at
  login time.
- This is precisely why OWASP and NIST recommend bcrypt/scrypt/argon2id
  for password storage, and why a plain 'salted SHA256' scheme (like
  demo 01/02 used for teaching purposes) is NOT acceptable in production.
""")
