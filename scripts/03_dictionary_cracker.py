#!/usr/bin/env python3
"""
03_dictionary_cracker.py

Objective: Implement a dictionary attack (the technique real tools like
John the Ripper / Hashcat use by default, since most real passwords are
not random - they're reused, patterned, or based on real words).

Also demonstrates simple "mangling rules" (leet-speak, appended digits,
capitalization) since raw wordlists alone miss most real passwords.

Run: python3 03_dictionary_cracker.py
"""

import hashlib
import itertools
import time
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "sample_wordlist.txt"


def load_wordlist(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def mangle(word: str):
    """Yield common password-mangling variants of a base word.
    This mirrors what John the Ripper's rule engine / Hashcat rule files do.
    """
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    leet_map = str.maketrans({"a": "@", "o": "0", "e": "3", "i": "1", "s": "5"})
    base_variants = set(variants)
    for v in base_variants:
        variants.add(v.translate(leet_map))
    # Common suffixes people append
    suffixes = ["", "1", "12", "123", "123!", "!", "1!", "2024", "2025", "2026"]
    final = set()
    for v in variants:
        for suf in suffixes:
            final.add(v + suf)
    return final


def dictionary_attack(target_hash: str, algo: str, wordlist: list[str], use_mangling=True):
    attempts = 0
    start = time.perf_counter()
    for word in wordlist:
        candidates = mangle(word) if use_mangling else {word}
        for guess in candidates:
            attempts += 1
            h = hashlib.new(algo, guess.encode()).hexdigest()
            if h == target_hash:
                elapsed = time.perf_counter() - start
                return guess, attempts, elapsed
    return None, attempts, time.perf_counter() - start


if __name__ == "__main__":
    wordlist = load_wordlist(WORDLIST_PATH)
    print(f"Loaded {len(wordlist)} base words from {WORDLIST_PATH.name}")

    # A password that pure brute force would take forever to find,
    # but that's just a mangled dictionary word - exactly how most
    # real leaked passwords look.
    secret = "Dragon123!"
    target = hashlib.sha256(secret.encode()).hexdigest()
    print(f"\nTarget hash (SHA256): {target}")
    print("(cracker does not know the plaintext, only the hash)")

    print("\n--- Attempt 1: plain wordlist, no mangling ---")
    found, attempts, elapsed = dictionary_attack(target, "sha256", wordlist, use_mangling=False)
    print(f"Result: {found or 'NOT FOUND'}   Attempts: {attempts:,}   Time: {elapsed:.4f}s")

    print("\n--- Attempt 2: wordlist + mangling rules (leet/case/suffixes) ---")
    found, attempts, elapsed = dictionary_attack(target, "sha256", wordlist, use_mangling=True)
    print(f"Result: {found or 'NOT FOUND'}   Attempts: {attempts:,}   Time: {elapsed:.4f}s")

    print("""
TAKEAWAY
--------
Pure brute force struggles once passwords exceed ~8 random characters
(keyspace explosion). But most human passwords aren't random - they're
dictionary words with predictable mutations. That's why John the
Ripper's default mode and Hashcat's "rule-based attack" (-r flag) crack
the vast majority of real-world leaked password dumps in minutes,
despite those passwords looking "complex" (capital letter + digit +
symbol) to a naive complexity checker.
""")
