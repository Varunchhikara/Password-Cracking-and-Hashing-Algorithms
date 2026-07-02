#!/usr/bin/env python3
"""
05_generate_test_hashes.py

Objective: Generate sample hash files in formats John the Ripper and
Hashcat expect, so you can practice with the REAL tools on Kali (this
is where the actual "Tools: Hashcat, John the Ripper" part of the
project happens - the earlier scripts build understanding, this feeds
the real tools).

All passwords here are ones WE chose, purely for local practice.
Never run these tools against hashes/accounts you don't own or have
explicit authorization to test.

Run: python3 05_generate_test_hashes.py
Outputs into ../samples/
"""

import crypt
import hashlib
from pathlib import Path

try:
    import bcrypt
except ImportError:
    bcrypt = None

OUT_DIR = Path(__file__).parent.parent / "samples"
OUT_DIR.mkdir(exist_ok=True)

# username -> password (deliberately a mix of weak/medium/strong for a
# realistic-looking "cracked X of Y" result when you run the tools)
TEST_ACCOUNTS = {
    "alice": "dragon123",
    "bob": "Summer2024!",
    "carol": "P@ssw0rd",
    "dave": "qwerty",
    "erin": "Tr0ub4dor&3",
    "frank": "123456",
}


def write_raw_md5():
    path = OUT_DIR / "hashes_md5.txt"
    with open(path, "w") as f:
        for user, pwd in TEST_ACCOUNTS.items():
            f.write(f"{user}:{hashlib.md5(pwd.encode()).hexdigest()}\n")
    print(f"Wrote {path}  (john: --format=Raw-MD5 | hashcat: -m 0)")


def write_raw_sha256():
    path = OUT_DIR / "hashes_sha256.txt"
    with open(path, "w") as f:
        for user, pwd in TEST_ACCOUNTS.items():
            f.write(f"{user}:{hashlib.sha256(pwd.encode()).hexdigest()}\n")
    print(f"Wrote {path}  (john: --format=Raw-SHA256 | hashcat: -m 1400)")


def write_linux_shadow_style():
    """
    SHA-512 crypt is the default Linux /etc/shadow hash format
    (id '$6$'). This lets you practice with john --format=sha512crypt
    or hashcat -m 1800 against a *realistic* shadow-file-style target.
    """
    path = OUT_DIR / "shadow_style.txt"
    with open(path, "w") as f:
        for user, pwd in TEST_ACCOUNTS.items():
            hashed = crypt.crypt(pwd, crypt.mksalt(crypt.METHOD_SHA512))
            f.write(f"{user}:{hashed}\n")
    print(f"Wrote {path}  (john: --format=sha512crypt | hashcat: -m 1800)")


def write_bcrypt():
    if bcrypt is None:
        print("bcrypt not installed, skipping bcrypt sample "
              "(pip install bcrypt --break-system-packages)")
        return
    path = OUT_DIR / "hashes_bcrypt.txt"
    with open(path, "w") as f:
        for user, pwd in TEST_ACCOUNTS.items():
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=8)).decode()
            f.write(f"{user}:{hashed}\n")
    print(f"Wrote {path}  (john: --format=bcrypt | hashcat: -m 3200)")
    print("  (using cost=8 instead of the usual 12 so cracking demos finish quickly)")


def write_answer_key():
    path = OUT_DIR / "ANSWER_KEY_do_not_peek.txt"
    with open(path, "w") as f:
        for user, pwd in TEST_ACCOUNTS.items():
            f.write(f"{user}:{pwd}\n")
    print(f"Wrote {path}  (ground truth, to check your cracking results)")


if __name__ == "__main__":
    print(f"Generating sample hash files in {OUT_DIR}\n")
    write_raw_md5()
    write_raw_sha256()
    write_linux_shadow_style()
    write_bcrypt()
    write_answer_key()
    print("\nDone. See ../john_hashcat_cheatsheet.sh for the commands to")
    print("actually crack these with John the Ripper / Hashcat on Kali.")
