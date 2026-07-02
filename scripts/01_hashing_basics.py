#!/usr/bin/env python3
"""
01_hashing_basics.py

Objective: Understand how cryptographic hash functions work, why plain
hashing of passwords is unsafe, and how salting fixes the biggest weakness.

Run: python3 01_hashing_basics.py
"""

import hashlib
import hmac
import os
import time


def show_basic_hashes(password: str):
    """Hash the same password with several algorithms to compare output."""
    print(f"\nPassword: {password!r}")
    print("-" * 60)
    algos = ["md5", "sha1", "sha256", "sha512"]
    for algo in algos:
        h = hashlib.new(algo)
        h.update(password.encode())
        print(f"{algo.upper():8} ({h.digest_size*8:3} bit): {h.hexdigest()}")


def demonstrate_determinism():
    """Same input -> same hash, always. This is why unsalted hashes are crackable."""
    print("\n[Determinism] Hashing 'Password123' three times:")
    for _ in range(3):
        print("  ", hashlib.sha256(b"Password123").hexdigest())
    print("  -> Identical every time. An attacker can pre-compute hashes")
    print("     for common passwords once (a 'rainbow table') and reuse")
    print("     that table against ANY unsalted hash database.")


def demonstrate_avalanche_effect():
    """Tiny input change -> completely different hash (good crypto property)."""
    print("\n[Avalanche Effect] 'Password123' vs 'Password124':")
    h1 = hashlib.sha256(b"Password123").hexdigest()
    h2 = hashlib.sha256(b"Password124").hexdigest()
    print("  ", h1)
    print("  ", h2)
    diff_bits = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
    print(f"  -> One character changed, hashes are completely different "
          f"(~{diff_bits} differing hex nibble-bits).")


def demonstrate_salting():
    """
    Salting = a random value stored alongside the hash and mixed into it.
    Same password + different salt = different hash, killing rainbow tables
    and preventing 'if two hashes match, two users have the same password'.
    """
    password = b"Password123"
    print("\n[Salting] Same password, two users, two random salts:")
    for user in ("alice", "bob"):
        salt = os.urandom(16)  # 16 random bytes, unique per user
        salted_hash = hashlib.sha256(salt + password).hexdigest()
        print(f"  {user:6} salt={salt.hex()}  hash={salted_hash}")
    print("  -> Hashes differ even though the password is identical.")
    print("     A precomputed rainbow table is now useless: the attacker")
    print("     must brute-force each salted hash individually.")


def demonstrate_hmac_vs_naive_concat():
    """
    Naive salt+password concatenation is fine for demo purposes, but real
    systems use HMAC or a purpose-built KDF (bcrypt/scrypt/argon2) which
    also add configurable *work factor* (slowness), not just randomness.
    """
    password = b"Password123"
    salt = os.urandom(16)
    naive = hashlib.sha256(salt + password).hexdigest()
    hmac_based = hmac.new(salt, password, hashlib.sha256).hexdigest()
    print("\n[Naive concat vs HMAC]")
    print("  naive salt||password:", naive)
    print("  HMAC(salt, password):", hmac_based)
    print("  -> HMAC has a stronger, formally-analyzed security proof than")
    print("     ad-hoc concatenation, but neither is 'slow'. Fast hashes")
    print("     (MD5/SHA*) are BAD for password storage because GPUs can")
    print("     compute billions per second. See 02/03 for why that matters,")
    print("     and 04_slow_hash_demo.py for the fix (bcrypt-style KDFs).")


def speed_comparison():
    """Show why fast hashes are dangerous for password storage."""
    print("\n[Speed] Hashing 200,000 passwords with each algorithm:")
    n = 200_000
    for algo in ("md5", "sha1", "sha256"):
        start = time.perf_counter()
        for i in range(n):
            hashlib.new(algo, str(i).encode()).hexdigest()
        elapsed = time.perf_counter() - start
        rate = n / elapsed
        print(f"  {algo.upper():8}: {elapsed:6.2f}s -> ~{rate:,.0f} hashes/sec (single CPU core, Python)")
    print("  -> A real attacker uses Hashcat on a GPU: MD5/SHA1/SHA256 reach")
    print("     BILLIONS of hashes/sec there. This is why raw hashing is")
    print("     unsuitable for passwords no matter which algorithm you pick.")


if __name__ == "__main__":
    show_basic_hashes("Password123")
    demonstrate_determinism()
    demonstrate_avalanche_effect()
    demonstrate_salting()
    demonstrate_hmac_vs_naive_concat()
    speed_comparison()
