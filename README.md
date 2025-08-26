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
