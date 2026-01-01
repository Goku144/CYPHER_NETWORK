# CYPHER_NETWORK

A small C project that provides:

- **`cypher` CLI**: a TCP client/server chat-like tool with optional **AES** or **RSA** encryption.
- **`libcypher_*` library**: reusable modules for framed transport, negotiation, AES/RSA, keys, RNG, and math helpers.

> **Platform**: Linux (WSL/Ubuntu works)  
> **Dependency**: GMP (big integers) + standard Linux networking

---

## Features

- TCP **client/server** modes (`-sp` for server, `-i` / `-n` for client)
- **Negotiation handshake** to detect mismatched encryption settings
- Encryption options:
  - **None**: plain framed transport
  - **AES (128/192/256)**: session key exchanged via RSA
  - **RSA (>=1024)**: full duplex using exchanged public keys
- Modular library split into: protocol, IO, keys, algorithms, randomness, math, errors

---

## Repository layout

```text
CYPHER/
├─ .vscode/
├─ CONTEXT/
│  └─ PROTOCOL.drawio
├─ core/
│  ├─ bin/                # built executable output (cypher)
│  ├─ lib/                # built objects / archives (depends on Makefile)
│  └─ src/
├─ inc/
│  ├─ cypher.h
│  ├─ cypher_algo.h
│  ├─ cypher_const.h
│  ├─ cypher_err.h
│  ├─ cypher_io.h
│  ├─ cypher_key.h
│  ├─ cypher_math.h
│  ├─ cypher_prot.h
│  └─ cypher_rand.h
├─ KEY/
│  └─ secret.key
├─ lib/
│  ├─ .old/
│  ├─ libcypher_alg.c
│  ├─ libcypher_err.c
│  ├─ libcypher_io.c
│  ├─ libcypher_key.c
│  ├─ libcypher_math.c
│  ├─ libcypher_prot.c
│  └─ libcypher_rand.c
├─ LICENSES/
│  ├─ Apache-2.0.txt
│  └─ MIT.txt
├─ MATH/                  # reference PDFs
├─ src/
│  └─ cypher.c            # CLI entry point
├─ test/
├─ Makefile
└─ README.md

---

## Build

### Install dependencies (Ubuntu / Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev
```

### Compile

```bash
make
```

### Clean

```bash
make clean
```

> The binary is typically produced in `core/bin/cypher`.

---

## Usage

### Modes

```text
server: cypher -sp <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
client: cypher -i <IPV4> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
        cypher -n <NAME> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
```

### Examples

#### Plain (no encryption)

```bash
# server
cypher -sp 4444

# client
cypher -i 127.0.0.1 -p 4444
```

#### AES (128/192/256)

```bash
# server
cypher -sp 4444 -e aes 256

# client (must match)
cypher -i 127.0.0.1 -p 4444 -e aes 256
```

#### AES + custom RSA exchange bits (`-kx`)

```bash
# server
cypher -sp 4444 -e aes 256 -kx 1024

# client (must match)
cypher -i 127.0.0.1 -p 4444 -e aes 256 -kx 1024
```

#### RSA (>=1024)

```bash
# server
cypher -sp 4444 -e rsa 2048

# client (must match)
cypher -i 127.0.0.1 -p 4444 -e rsa 2048
```

#### Version

```bash
cypher --version
```

---

## Handshake rules (high level)

### No `-e`

0. Negotiate `(enc=NONE, bits=0)` (must match)
1. Run normal framed duplex

### `-e rsa <>=1024>`

0. Negotiate `(enc=RSA, bits=rsa_bits)` (must match)
1. Server generates RSA keypair → sends **server PUBLIC** to client
2. Client generates RSA keypair → sends **client PUBLIC** to server
3. Full duplex:

   * send with **peer public**
   * receive with **own private**

### `-e aes <128|192|256>`

0. Negotiate `(enc=AES, bits=aes_bits)` (must match)
   0b) Negotiate RSA exchange bits:

   * use `-kx` if provided
   * otherwise use default mapping based on AES size
1. Client generates RSA keypair (`kx_bits`) → sends **client PUBLIC**
2. Server generates AES session key (`aes_bits`) → RSA-encrypt with client PUBLIC → sends back
3. Client RSA-decrypts → imports AES key → both run AES full duplex

---

## Modules (library)

* `libcypher_prot.c` → header/padding + inet client/server
* `libcypher_io.c` → framed `cy_send/cy_recv` + duplex (plain/AES/RSA)
* `libcypher_key.c` → AES/RSA key generation + import/export
* `libcypher_alg.c` → AES rounds + RSA byte-level helpers
* `libcypher_rand.c` → randomness helpers (bytes + mpz)
* `libcypher_math.c` → gcd/EEA + probable prime generation
* `libcypher_err.c` → common fatal error handler

---

## Licensing

### MIT — CLI only

* `src/cypher.c` is **MIT**
* keep at the top of `src/cypher.c`:

```c
/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Jebbari Marouane
 */
```

### Apache-2.0 — all library `.c`

All files in `lib/` are **Apache-2.0**:

* `lib/libcypher_alg.c`
* `lib/libcypher_err.c`
* `lib/libcypher_io.c`
* `lib/libcypher_key.c`
* `lib/libcypher_math.c`
* `lib/libcypher_prot.c`
* `lib/libcypher_rand.c`

License texts are stored in:

* `LICENSES/MIT.txt`
* `LICENSES/Apache-2.0.txt`

---

## Notes

* `KEY/secret.key` may contain sensitive data — don’t commit real secrets.
* This project is educational/experimental crypto: review before any real-world use.

---

## Author

**Jebbari Marouane** (2025)

```

SPDX short identifiers like `MIT` and `Apache-2.0` are standardized by SPDX. :contentReference[oaicite:0]{index=0}  
On Ubuntu/Debian, the GMP headers (`gmp.h`) are provided by `libgmp-dev`. :contentReference[oaicite:1]{index=1}
::contentReference[oaicite:2]{index=2}
```
