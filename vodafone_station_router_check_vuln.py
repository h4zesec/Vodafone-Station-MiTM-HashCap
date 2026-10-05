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

check_uris = [
	"php/ajaxSet_Password.php",
	"scripts/sjclCrypto.js",
	"base_95x.js",
	"base.js"
]

failed = []
for uri in check_uris:
	try:
		resp = requests.get(url + uri, allow_redirects=False, timeout=5)
	except requests.ConnectionError:
		print("[-] Failed to establish connection to router when checking URI /" + uri)
		exit(1)

	if not resp.status_code in [200, 405]:
		failed.append(uri)
		print("[!] " + url + uri + " - " + str(resp.status_code))
	else:
		print("[*] " + url + uri + " - " + str(resp.status_code))

try:
	resp = requests.get(url, allow_redirects=False, timeout=5)
except requests.ConnectionError:
	print("[-] Failed to establish connection to router when requesting webroot!")
	exit(1)

if not "var mySalt = '" in resp.text or not "var myIv = '" in resp.text or not "var currentSessionId = '" in resp.text or not "var encryptflag = '" in resp.text:
	failed.append("fw")

	print("[!] Router does not expose required javascript vars in frontend!")
else:
	print("[*] Router exposes required javascript vars in frontend!")

if failed == []:
	print("[+] Router seems vulnerable to MiTM hash capture.")
else:
	print("[-] Router does not seem vulnerable to the MiTM hash capture.")
