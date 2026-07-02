#!/usr/bin/env python3
"""
02_bruteforce_cracker.py

Objective: Implement a brute-force password cracker from scratch to
understand keyspace growth, why length/charset matter, and how salting
defeats naive brute forcing at scale.

This targets hashes generated locally in this script - not real accounts.

Run: python3 02_bruteforce_cracker.py
"""

import hashlib
import itertools
import string
import time


def crack_unsalted(target_hash: str, algo: str, charset: str, max_len: int):
    """
    Try every combination of `charset` up to `max_len` characters.
    Keyspace size = sum(len(charset)**L for L in 1..max_len) - grows
    exponentially, which is the whole reason brute force doesn't scale.
    """
    attempts = 0
    start = time.perf_counter()
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            guess = "".join(combo)
            h = hashlib.new(algo, guess.encode()).hexdigest()
            if h == target_hash:
                elapsed = time.perf_counter() - start
                return guess, attempts, elapsed
    return None, attempts, time.perf_counter() - start


def crack_salted(target_hash: str, salt: bytes, algo: str, charset: str, max_len: int):
    """Same idea, but salt must be known/available (it's stored alongside the hash)."""
    attempts = 0
    start = time.perf_counter()
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            guess = "".join(combo)
            h = hashlib.new(algo, salt + guess.encode()).hexdigest()
            if h == target_hash:
                elapsed = time.perf_counter() - start
                return guess, attempts, elapsed
    return None, attempts, time.perf_counter() - start


def report_keyspace(charset: str, max_len: int):
    total = sum(len(charset) ** L for L in range(1, max_len + 1))
    print(f"  Charset size: {len(charset)}, max length: {max_len}")
    print(f"  Total keyspace to search: {total:,} combinations")


if __name__ == "__main__":
    print("=" * 70)
    print("DEMO 1: Cracking a short unsalted MD5 password (lowercase only)")
    print("=" * 70)
    charset = string.ascii_lowercase
    secret = "abcd"          # deliberately short/weak for a fast demo
    target = hashlib.md5(secret.encode()).hexdigest()
    print(f"Target hash (MD5): {target}  (unknown to the cracker)")
    report_keyspace(charset, 4)

    found, attempts, elapsed = crack_unsalted(target, "md5", charset, max_len=4)
    print(f"\nResult: {'FOUND -> ' + found if found else 'NOT FOUND'}")
    print(f"Attempts: {attempts:,}   Time: {elapsed:.3f}s   "
          f"Rate: {attempts/elapsed:,.0f} guesses/sec")

    print("\n" + "=" * 70)
    print("DEMO 2: Same password, but salted - attacker must redo the")
    print("full search PER TARGET, and cannot reuse precomputed tables")
    print("=" * 70)
    import os
    salt = os.urandom(8)
    target_salted = hashlib.sha256(salt + secret.encode()).hexdigest()
    print(f"Salt: {salt.hex()}")
    print(f"Target hash (salted SHA256): {target_salted}")

    found2, attempts2, elapsed2 = crack_salted(target_salted, salt, "sha256", charset, max_len=4)
    print(f"\nResult: {'FOUND -> ' + found2 if found2 else 'NOT FOUND'}")
    print(f"Attempts: {attempts2:,}   Time: {elapsed2:.3f}s")

    print("\n" + "=" * 70)
    print("TAKEAWAY")
    print("=" * 70)
    print("""
  Brute force cost is identical whether or not the hash is salted -
  salting doesn't make ONE hash harder to crack, it prevents attackers
  from amortizing work ACROSS many hashes (no shared rainbow table, no
  'two users share a password' leakage). Real defense against brute
  force itself comes from length/complexity requirements AND from using
  a deliberately slow KDF (bcrypt/scrypt/argon2) - see 04_slow_hash_demo.py.

  Try increasing max_len or the charset above and watch attempts grow
  exponentially - that's the real-world lesson Hashcat/John exploit
  with GPUs: they don't beat the math, they just brute force it FAST.
""")
