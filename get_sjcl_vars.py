#!/usr/bin/env python3

import sys
import requests

if len(sys.argv) != 2:
	exit(sys.argv[1] + ": http://192.168.0.1")

url = sys.argv[1]

if not "http://" and not "https://" in url:
	exit("[-] Invalid url.")

if not url.endswith("/"):
	url += "/"

resp = requests.get(url + "scripts/sjclCrypto.js", allow_redirects=False)

for line in resp.text.split("\n"):
	if line.startswith("var "):
		line = line[4:]

		if "DEFAULT_SJCL_" in line:
			line = line.replace(";", "")

			var = line.split(" = ")[0]
			value = line.split(" = ")[1]

			print("[+] " + var + " is " + value)
