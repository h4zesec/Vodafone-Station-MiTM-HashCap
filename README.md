# VodafoneRouterHTTP-PoC

VodafoneRouterHTTP-PoC is a security research tool for analyzing **Vodafone router web interfaces** and demonstrating potential exposure of authentication-related data through **unencrypted HTTP communication**.

The PoC monitors HTTP traffic in a controlled environment and extracts session-related information, web interface variables, and authentication data used by the router interface.

## Features

- HTTP traffic analysis using Scapy
- Session cookie extraction
- Router web interface variable tracking
- Authentication flow analysis
- Session-related data collection
- Lightweight command-line interface

## Requirements

- Python 3
- Root privileges
- Scapy

Install dependencies:

```bash
pip3 install scapy
```

## Usage

```bash
doas python3 main.py [ interface ] [ router ]
```

Example:

```bash
doas python3 main.py enp7s0 192.168.0.1
```

## Example Output

```
[*] 192.168.0.50 (24:5b:61:30:62:3e) -> 192.168.0.1 HTTP GET /
[+] Sniffed cookie for 192.168.0.50: PHPSESSID=d3ee79b6892091ff87453e999418f3f7
[*] Sniffed var 'encryptflag' for 192.168.0.50: 'true' and added to var cache.
[*] Sniffed var 'currentSessionId' for 192.168.0.50: 'b4080b959db19ac713eecbfcf6eb2415' and added to var cache.
[*] Sniffed var 'myIv' for 192.168.0.50: 'bf27d8c44ed01906' and added to var cache.
[*] Sniffed var 'mySalt' for 192.168.0.50: '619438a07d451d2d' and added to var cache.
[+] 192.168.0.50 (34:5a:60:60:62:3e) -> 192.168.0.1 HTTP POST /php/ajaxSet_Password.php
===========================================================================
[+] Salt: 619438a07d451d2d
[+] IV: bf27d8c44ed01906
[+] Nonce: b4080b959db19ac713eecbfcf6eb2415
[+] EncryptData: 695572fb03df46bf5fadcbde9159.......
[+] Username: admin
===========================================================================
[-] Login for 192.168.0.50 (34:5a:60:60:62:3e) failed!
```

## Technical Overview

The tool analyzes HTTP communication between a client and a Vodafone router web interface.

It can identify:

- Session identifiers transmitted over HTTP
- Router-generated JavaScript variables
- Authentication-related request data
- Potential local network attack vectors caused by unencrypted communication

## Limitations

- Only works with HTTP-based router interfaces
- Requires visibility of the target traffic
- Does not bypass encryption
- Does not exploit vulnerabilities automatically

## Tested Environment

- Vodafone router web interfaces using HTTP
- Linux systems with Scapy support

## Disclaimer

This PoC is for educational purposes only and I assume no liablity if any damaged or harm is caused.
## License

MIT License
