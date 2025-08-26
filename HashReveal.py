#!/usr/bin/env python3
import re
import sys
import os
import subprocess
import tempfile

# Hash name → Hashcat mode mapping
HASHCANDIDATES = {
    "MD5": 0,
    "NTLM": 1000,
    "LM": 3000,
    "SHA-1": 100,
    "SHA-224": 1300,
    "SHA-256": 1400,
    "SHA-384": 10800,
    "SHA-512": 1700,
    "bcrypt": 3200,
    "scrypt": 8900,
    "yescrypt": 22911,
    "Argon2": 22300,
    "MD5 crypt ($1$)": 500,
    "SHA-256 crypt ($5$)": 7400,
    "SHA-512 crypt ($6$)": 1800,
    "PBKDF2": 10900,
    "DES crypt": 1500,
    "MySQL323": 200,
    "MySQL SHA1": 300,
    "MSSQL2000": 131,
    "MSSQL2005": 132,
    "Oracle 11g/12c": 112,
    "Cisco PIX": 2400,
    "Juniper ($9$)": 15100,
}

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
CRACKED_OUTPUT = "cracked_passwords.txt"

# ---------------- Identification ----------------

def identify_hash(h):
    h = h.strip()
    candidates = []
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        candidates.append("bcrypt")
    elif h.startswith("$scrypt$"):
        candidates.append("scrypt")
    elif h.startswith("$y$"):
        candidates.append("yescrypt")
    elif h.startswith("$argon2"):
        candidates.append("Argon2")
    elif h.startswith("$pbkdf2"):
        candidates.append("PBKDF2")
    elif h.startswith("$1$"):
        candidates.append("MD5 crypt ($1$)")
    elif h.startswith("$5$"):
        candidates.append("SHA-256 crypt ($5$)")
    elif h.startswith("$6$"):
        candidates.append("SHA-512 crypt ($6$)")
    elif h.startswith("$9$"):
        candidates.append("Juniper ($9$)")
    elif re.fullmatch(r"[A-Za-z0-9./]{13}", h):
        candidates.append("DES crypt")
    elif re.fullmatch(r"[0-9A-Fa-f]{16}", h):
        candidates.append("MySQL323")
    elif h.startswith("*") and re.fullmatch(r"\*[0-9A-Fa-f]{40}", h):
        candidates.append("MySQL SHA1")
    elif h.lower().startswith("0x0100") and len(h) in (92, 94):
        candidates.append("MSSQL2000" if len(h) == 92 else "MSSQL2005")
    elif h.startswith(("S:", "H:")) and len(h) in (52, 48):
        candidates.append("Oracle 11g/12c")
    elif h.lower().startswith("pix"):
        candidates.append("Cisco PIX")
    elif re.fullmatch(r"[0-9A-Fa-f]+", h):
        length = len(h)
        if length == 16:
            candidates.append("MySQL323")
        elif length == 32:
            candidates.extend(["MD5", "NTLM", "LM"])
        elif length == 40:
            candidates.append("SHA-1")
        elif length == 56:
            candidates.append("SHA-224")
        elif length == 64:
            candidates.append("SHA-256")
        elif length == 96:
            candidates.append("SHA-384")
        elif length == 128:
            candidates.append("SHA-512")
        else:
            candidates.append("Unknown/Other")
    else:
        candidates.append("Unknown/Other")
    return candidates

def guess_best(h, candidates):
    if len(candidates) == 1:
        return candidates[0]
    if set(candidates) == {"MD5", "NTLM", "LM"}:
        if h.isupper():
            return "NTLM"
        elif h[:16] == h[16:]:
            return "LM"
        else:
            return "MD5"
    return candidates[0]

# ---------------- Hashcat Runner ----------------

def crack_single_hash(h, mode, wordlist):
    """Run hashcat with: hashcat -a 0 -m <mode> hashfile wordlist"""
    cracked = None
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(h + "\n")
        tmp_hashfile = tf.name

    try:
        cmd = ["hashcat", "-a", "0", "-m", str(mode), tmp_hashfile, wordlist,
               "--quiet", "--force", "--show"]
        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout.strip():
            cracked = result.stdout.strip()
    finally:
        try: os.remove(tmp_hashfile)
        except: pass
    return cracked

# ---------------- Main ----------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hashfile> [--wordlist <path>]")
        sys.exit(1)

    hashfile = sys.argv[1]
    if not os.path.exists(hashfile):
        print(f"[-] File not found: {hashfile}")
        sys.exit(1)

    # Check for custom wordlist
    if "--wordlist" in sys.argv:
        idx = sys.argv.index("--wordlist")
        if idx + 1 < len(sys.argv):
            wordlist = sys.argv[idx + 1]
            if not os.path.exists(wordlist):
                print(f"[-] Wordlist not found: {wordlist}")
                sys.exit(1)
        else:
            print("[-] --wordlist requires a path")
            sys.exit(1)
    else:
        wordlist = DEFAULT_WORDLIST

    with open(hashfile, "r") as f:
        hashes = [line.strip() for line in f if line.strip()]

    for h in hashes:
        candidates = identify_hash(h)
        best = guess_best(h, candidates)
        if best not in HASHCANDIDATES:
            print(f"[-] Unsupported hash: {h}")
            continue

        mode = HASHCANDIDATES[best]
        cracked = crack_single_hash(h, mode, wordlist)
        if cracked:
            line = f"{best}(-m {mode}) | {cracked}"
            print(f"[+] Cracked: {line}")
            with open(CRACKED_OUTPUT, "a") as out:
                out.write(line + "\n")
        else:
            print(f"[-] Not cracked: {h}")

if __name__ == "__main__":
    main()
