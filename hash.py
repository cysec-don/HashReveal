#!/usr/bin/env python3
"""
Hash Reveal
-----------------------
Author: CySec Don
Email: cysecdon@proton.me
Version: 1.0

Description:
    Hash Reveal identifies hash types from a given input file.
    It supports many common hash formats and outputs results with 
    best guesses and hashcat mode (-m) values.

Usage:
    python3 hash.py
    → Then enter the path to the hash file when prompted.
"""

import re
import sys

# Version info
VERSION = "Hash Reveal v1.0 by CySec Don"

# Man page content
MAN_PAGE = f"""
HASH REVEAL(1)                 User Commands                HASH REVEAL(1)

NAME
       hash reveal - identify common hash types and provide hashcat modes

SYNOPSIS
       python3 hash.py
       → The script will prompt for the path to an input file containing
         hashes (one per line).

DESCRIPTION
       Hash Reveal is a hash identification utility that analyzes input 
       hashes, determines possible algorithms, and provides recommended 
       hashcat -m mode values for cracking.

       The script supports a wide range of hashing algorithms, including:
         • MD5, NTLM, LM
         • SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
         • bcrypt, scrypt, yescrypt, Argon2
         • PBKDF2, MD5 crypt ($1$), SHA-256 crypt ($5$), SHA-512 crypt ($6$)
         • DES crypt
         • MySQL 3.x/4.0, MySQL 5.x (SHA1)
         • MSSQL 2000, MSSQL 2005+
         • Oracle 11g/12c
         • Cisco PIX
         • Juniper ($9$)

USAGE
       Run the script:

           python3 hash.py

       You will be prompted to enter the path of the file containing
       hashes. Each line of the file should contain one hash.

       Example:

           Enter the path to the hash file (e.g., hashes.txt): my_hashes.txt

       The results will be written to an output file:

           hashes_identified.txt

OUTPUT
       The output file contains a list of candidate algorithms with
       hashcat mode numbers and the best guess for each hash.

       Example output line:

           MD5(-m 0),NTLM(-m 1000),LM(-m 3000) | BestGuess=MD5: 5d41402abc4b2a76b9719d911017c592

OPTIONS
       -h, --help
           Show this manual page and exit.

       -?
           Show a short usage summary.

       -v, --version
           Show version information and exit.

FILES
       Input:
           User-specified file containing one or more hashes.

       Output:
           hashes_identified.txt - file containing identified hash
           algorithms and hashcat modes.

AUTHOR
       Written by CySec Don <cysecdon@proton.me>

COPYRIGHT
       This is free software: you are free to modify and redistribute it.
       There is NO WARRANTY, to the extent permitted by law.

SEE ALSO
       hashcat(1), john(1)
"""

# Short usage info
SHORT_USAGE = """
Usage: python3 hash.py [options]

Options:
   -h, --help       Show full manual page
   -?               Show short usage info
   -v, --version    Show version information

Run without options to start interactive mode.
"""

# Mapping algorithms to hashcat -m values
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

def identify_hash(h):
    h = h.strip()
    candidates = []

    # Prefix-based hashes
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
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
    # Legacy DES crypt (13 chars, [A-Za-z0-9./])
    elif re.fullmatch(r"[A-Za-z0-9./]{13}", h):
        candidates.append("DES crypt")

    # MySQL old (pre-4.1)
    elif re.fullmatch(r"[0-9A-Fa-f]{16}", h):
        candidates.append("MySQL323")

    # MySQL 5.x (SHA1, 41 chars, starts with '*')
    elif h.startswith("*") and re.fullmatch(r"\*[0-9A-Fa-f]{40}", h):
        candidates.append("MySQL SHA1")

    # MSSQL 2000 / 2005+
    elif h.lower().startswith("0x0100") and len(h) == 94:
        candidates.append("MSSQL2005")
    elif h.lower().startswith("0x0100") and len(h) == 92:
        candidates.append("MSSQL2000")

    # Oracle 11g/12c
    elif h.startswith("S:") and len(h) == 52:
        candidates.append("Oracle 11g/12c")
    elif h.startswith("H:") and len(h) == 48:
        candidates.append("Oracle 11g/12c")

    # Cisco PIX
    elif h.lower().startswith("pix"):
        candidates.append("Cisco PIX")

    # Hex-only hashes
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
    """Heuristic to pick best guess among candidates"""
    if len(candidates) == 1:
        return candidates[0]

    h = h.strip()

    # Heuristics for 32 hex chars (MD5/NTLM/LM)
    if set(candidates) == {"MD5", "NTLM", "LM"}:
        if h.isupper():
            return "NTLM"
        elif h[:16] == h[16:]:
            return "LM"
        else:
            return "MD5"

    return candidates[0]  # fallback to first


def main():
    # Handle command-line help/usage/version options
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-h", "--help"):
            print(MAN_PAGE)
            return
        elif sys.argv[1] == "-?":
            print(SHORT_USAGE)
            return
        elif sys.argv[1] in ("-v", "--version"):
            print(VERSION)
            return

    # Print credits at start
    print("="*50)
    print(" Hash Reveal - Hash Identifier Script")
    print(" Author : CySec Don")
    print(" Email  : cysecdon@proton.me")
    print(" Version: 1.0")
    print("="*50)

    # Ask user for input file name
    input_file = input("Enter the path to the hash file (e.g., hashes.txt): ").strip()
    if not input_file:
        print("[-] No file provided, exiting.")
        return

    # Output file name (auto-generated)
    output_file = "hashes_identified.txt"

    try:
        with open(input_file, "r") as f, open(output_file, "w") as out:
            for line in f:
                h = line.strip()
                if not h:
                    continue

                candidates = identify_hash(h)
                best_guess = guess_best(h, candidates)

                expanded = []
                for c in candidates:
                    if c in HASHCANDIDATES:
                        expanded.append(f"{c}(-m {HASHCANDIDATES[c]})")
                    else:
                        expanded.append(c)

                out.write(f"{','.join(expanded)} | BestGuess={best_guess}: {h}\n")

        print(f"[+] Identification complete. Results saved to {output_file}")
    except FileNotFoundError:
        print(f"[-] File '{input_file}' not found.")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
