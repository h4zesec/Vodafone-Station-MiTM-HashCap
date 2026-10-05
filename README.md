# Vodafone Station Router MiTM Hash Capture

**Offensive Security Research Tool for Vodafone Station Routers**

A specialized security-testing toolkit focused exclusively on the web authentication behavior of **Vodafone Station routers**.

The project can identify potentially affected routers, extract relevant SJCL configuration, capture authentication material from authorized network traffic, and perform offline password analysis.

> **For authorized security testing and research only. Test only routers and networks you own or have explicit permission to assess.**

---

## Overview

```text
                  +----------------------+
                  |   Vodafone Station   |
                  |       Router         |
                  +----------+-----------+
                             |
                    HTTP Management
                             |
                             v
                  +----------------------+
                  |   MiTM Hash Capture  |
                  |                      |
                  |  Session data        |
                  |  SJCL parameters     |
                  |  Encrypted data      |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  |   Offline Analysis   |
                  |                      |
                  |     PBKDF2-SHA256    |
                  |          |           |
                  |          v           |
                  |       AES-CCM        |
                  |          |           |
                  |          v           |
                  | Password verification|
                  +----------------------+
```

The tooling is deliberately **Vodafone Station specific** and is not intended to be a generic router attack framework.

---

## Features

* Vodafone Station vulnerability/prerequisite check
* Extraction of frontend SJCL parameters
* Network-level authentication traffic analysis
* Optional per-client targeting
* Automatic capture logging
* Offline password analysis
* Multi-core candidate processing

---

## Tools

| Script                                     | Description                                                               |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| `vodafone_station_router_check_vuln.py`    | Checks whether the router exposes the components required by the workflow |
| `vodafone_station_router_get_sjcl_vars.py` | Extracts the router's `DEFAULT_SJCL_*` configuration                      |
| `vodafone_station_router_mitm_hashcap.py`  | Captures Vodafone Station authentication material from network traffic    |
| `vodafone_station_enc_crack_offline.py`    | Performs offline password analysis against captured encrypted data        |

---

## Attack Workflow

```text
   [1] Identify Router
           |
           v
   [2] Check Exposure
           |
           v
   [3] Read SJCL Config
           |
           v
   [4] Capture Authentication
           |
           v
   [5] Save .enc Capture
           |
           v
   [6] Offline Analysis
```

The network capture and password analysis stages are intentionally separated.

---

## Quick Start

### Check the Router

```bash
python3 vodafone_station_router_check_vuln.py http://192.168.0.1
```

### Extract SJCL Configuration

```bash
python3 vodafone_station_router_get_sjcl_vars.py http://192.168.0.1
```

### Start the Capture

```bash
doas python3 vodafone_station_router_mitm_hashcap.py
```

Optional interface, router, and client selection:

```bash
doas python3 vodafone_station_router_mitm_hashcap.py \
    --iface eth0 \
    --router 192.168.0.1 \
    --victim 192.168.0.42
```

### Offline Analysis

Captured parameters can then be supplied to:

```bash
python3 vodafone_station_enc_crack_offline.py \
    --salt <salt> \
    --iv <iv> \
    --encrypted <ciphertext> \
    --sjcl-iterations <iterations> \
    --sjcl-key-size <key-size> \
    --sjcl-tag-length <tag-length> \
    --wordlist <wordlist>
```

---

## Vodafone Station Specific

The project is built around the behavior of the Vodafone Station web interface, including endpoints and frontend values such as:

```text
/php/ajaxSet_Password.php
/scripts/sjclCrypto.js

mySalt
myIv
currentSessionId
encryptflag
```

Because the implementation is closely tied to these components, compatibility with other router vendors is not expected.

Firmware revisions may also change the behavior.

---

## Output

Captured authentication data is stored per client:

```text
192-168-0-42.enc
```

These files contain sensitive security material and should be treated accordingly.

Recommended `.gitignore` entry:

```gitignore
*.enc
```

---

## Requirements

* Python 3
* Scapy
* Requests
* Cryptography
* Linux environment recommended
* Root-equivalent privileges for packet capture

Install dependencies with:

```bash
pip3 install scapy requests cryptography
```

---

## Security Research

This project is useful for studying:

* Router authentication protocols
* Insecure management transport
* Client-side cryptographic implementations
* Password-derived encryption keys
* Offline password resistance
* Vodafone Station firmware behavior

The primary goal is to make the Vodafone Station authentication workflow observable and reproducible for authorized security research.

---

## Disclaimer

This project is provided for **authorized security research, penetration testing, and educational purposes**.

Do not use it against networks, routers, or credentials without explicit authorization.

You are responsible for complying with all applicable laws and obtaining permission before performing security testing.
