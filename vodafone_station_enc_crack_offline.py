#!/usr/bin/env python3

import json
import time
import math
import string
import hashlib
import argparse
import itertools
import multiprocessing as mp
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag

def get_arguments():
	parser = argparse.ArgumentParser()
	
	parser.add_argument("-s", "--salt", required=True)
	parser.add_argument("-iv", required=True)
	parser.add_argument("-w", "--wordlist", required=False, help="If not set the code will generate default passwords by itself.")
	parser.add_argument("-e", "--encrypted", required=True) 

	parser.add_argument("--sjcl-iterations", dest="iterations", required=True, type=int)
	parser.add_argument("--sjcl-key-size", dest="key_size", required=True, type=int, help="in bits")
	parser.add_argument("--sjcl-tag-length", dest="tag_len", required=True, type=int, help="in bits")

	return parser.parse_args()

args = get_arguments()

def pbkdf2(password: str):
	return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(args.salt), args.iterations, args.key_size // 8)

def decrypt(password: str):
	key = pbkdf2(password)
	data = AESCCM(key, tag_length=args.tag_len // 8).decrypt(bytes.fromhex(args.iv), bytes.fromhex(args.encrypted), b"loginPassword")
	return json.loads(data)

if args.wordlist != None:
	fp = open(args.wordlist, "r")
	passwords = fp.read().split("\n")
	fp.close()
else:
	passwords = None

def check(password: str):
	try:
		cracked_password = decrypt(password)["Password"]
	except InvalidTag:
		return None

	return cracked_password



ALPHABET = string.ascii_uppercase + string.digits
CHUNK = 128
WORKERS = mp.cpu_count()

def _worker(pw):
	return pw, check(pw)

def _run(pool, iterable, total):
	start = time.monotonic()
	last_print = 0.0
	n = 0
	for pw, cracked in pool.imap_unordered(_worker, iterable, chunksize=CHUNK):
		n += 1
		now = time.monotonic()
		if now - last_print >= 0.25:
			last_print = now
			rate = n / (now - start)
			pct = 100.0 * n / total
			print(f"\rCracking passphrase ... : {pw}  " + f"[{n:,}/{total:,}  {pct:.2f}%  {rate:,.0f} pw/s]", end="", flush=True)

		if cracked is not None:
			pool.terminate()
			print("\r" + " " * 100 + "\r", end="")
			print(f"[+] Cracked passphrase: {cracked}")
			return True

	print("\r" + " " * 100 + "\r", end="")
	return False

def crack_wordlist(passwords):
	with mp.Pool(WORKERS) as pool:
		if not _run(pool, passwords, len(passwords)):
			print("Key not found.")

def crack_bruteforce():
	total = math.perm(len(ALPHABET), 8)
	gen = ("".join(c) for c in itertools.permutations(ALPHABET, 8))
	with mp.Pool(WORKERS) as pool:
		if not _run(pool, gen, total):
			print("Key not found.")

def main():
	if passwords is not None:
		crack_wordlist(passwords)
	else:
		crack_bruteforce()

if __name__ == "__main__":
	main()
