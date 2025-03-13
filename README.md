# Bitcoinkey-to-address
This C language tool can generate public keys from Bitcoin private keys and generate multiple address formats including P2PKH, P2SH and SegWit. It uses efficient and secure cryptography and encoding algorithms and supports hexadecimal and WIF format private keys.

## 📌 Project Overview

This tool provides functionality for:

- Generating public keys from private keys (in hexadecimal or WIF format).
- Generating various types of Bitcoin addresses from public keys.

## 🔑 Private Key Handling

-   **WIF Generation:** Supports generating WIF format private keys from hexadecimal private keys.
-   **WIF Decoding:** Supports decoding WIF format private keys into hexadecimal private keys, and determining if it is in compressed format.
-   **Automatic Format Detection:** Automatically identifies the input private key format (hexadecimal or WIF).

## 🔓 Public Key Generation

-   **Elliptic Curve:** Generates public keys from private keys based on the secp256k1 elliptic curve algorithm.
-   **Compressed & Uncompressed:** Supports generating both compressed and uncompressed format public keys.

## 📮 Address Generation

Supports generating the following types of Bitcoin addresses:

-   **P2PKH (Pay-to-Public-Key-Hash):** Traditional address, starts with `1`.
-   **P2SH (Pay-to-Script-Hash):** Multi-signature or script address, starts with `3`.
-  **P2SH-P2WPKH (P2SH wrapped P2WPKH):** P2SH wrapped Segregated Witness address, starts with `3`
-   **Bech32 (SegWit):** Segregated Witness address, starts with `bc1`.
-   **Bech32m (Taproot):** Taproot address, starts with `bc1p`.
-   **P2WSH (Pay-to-Witness-Script-Hash):** Segregated Witness script address, starts with `bc1`.
-  **P2WSH-P2WPKH (P2WSH wrapped P2WPKH):** P2WSH wrapped Segregated Witness address, starts with `bc1`.

-   **Compressed/Uncompressed Support:** Supports generating addresses from both compressed and uncompressed public keys.

## 🛠️ Dependencies

-   **GMP (GNU Multiple Precision Arithmetic Library):** Used for large number arithmetic.

### Custom Modules:

-  ** `ripemd160`
-  ** `base58`
-  ** `bech32`
-  ** `ecc`
-  ** `customutil`
-  ** `sha256`

## 🔨 Compilation and Installation

**1. Install dependencies on Ubuntu/Debian:**
-
```sh
sudo apt-get install libgmp-dev libssl-dev
```

Markdown
2. Compile the code:
```sh
gcc -O3 -o key key.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c ecc/ecc.c customutil/customutil.c -lgmp
```

or
```sh
make
```

###🚀 Usage
After successful compilation, you can run the tool from the command line, passing the private key (hexadecimal or WIF format) as an argument:
-
```sh

./key <Private Key (Hex or WIF)>

```
### Example
Input hexadecimal private key
```sh

./key 0000000000000000000000000000000000000000000000000000000000000001

```
Output:
```sh
**Raw Private Key (Hex): 0000000000000000000000000000000000000000000000000000000000000001
**WIF Private Key: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

**Compressed Public Key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
**Uncompressed Public Key: 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

**=== Addresses Generated from Compressed Public Key ===
**-P2PKH (Starts with 1) Address (Compressed): 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
**-P2SH (Starts with 3) Address (Compressed): 3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw (P2SH => P2PKH)
**-P2SH (Starts with 3) Address (Compressed): 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN (P2SH => P2WPKH)
**-Bech32 (Starts with bc1) Address (Compressed): bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
**-Bech32m (Starts with bc1p) Address (Compressed): bc1pw508d6qejxtdg4y5r3zarvary0c5xw7k8e76x7
**-P2WSH (Starts with bc1) Address (Compressed): bc1qpac4ht6afshdx2tctnhjnetz7u6g3j9zhwwmc4cqkdsa2jumq42qd3drf7 (P2WSH => P2PKH)
**-P2WSH (Starts with bc1) Address (Compressed): bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc (P2WSH => P2WPKH)

**=== Addresses Generated from Uncompressed Public Key ===
**-P2PKH (Starts with 1) Address (Uncompressed): 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
**-P2SH (Starts with 3) Address (Uncompressed): 3EyPVdtVrtMJ1XwPT9oiBrQysGpRY8LE9K (P2SH => P2PKH)
**-P2SH (Starts with 3) Address (Uncompressed): 33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (P2SH => P2WPKH)
**-Bech32 (Starts with bc1) Address (Uncompressed): bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h
**-Bech32m (Starts with bc1p) Address (Uncompressed): bc1pjxeyh7049zzn99s2c6r6hvp4zfa362994nkhzu
**-P2WSH (Starts with bc1) Address (Uncompressed): bc1q2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqqym7502 (P2WSH => P2PKH)
**-P2WSH (Starts with bc1) Address (Uncompressed): bc1qdrvr7pa25ayvpxt7yymdkktur98exqj59ydpcvs2sszxqks957vqqrrv3q (P2WSH => P2WPKH)
```
### Input WIF format private key
```sh
./key 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf

-
Output:
**-WIF Private Key: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
**-Raw Private Key (Hex): 0000000000000000000000000000000000000000000000000000000000000001
**-Compressed Public Key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
**-Uncompressed Public Key: 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

**=== Addresses Generated from Compressed Public Key ===
**-P2PKH (Starts with 1) Address (Compressed): 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
**-P2SH (Starts with 3) Address (Compressed): 3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw (P2SH => P2PKH)
**-P2SH (Starts with 3) Address (Compressed): 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN (P2SH => P2WPKH)
**-Bech32 (Starts with bc1) Address (Compressed): bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
**-Bech32m (Starts with bc1p) Address (Compressed): bc1pw508d6qejxtdg4y5r3zarvary0c5xw7k8e76x7
**-P2WSH (Starts with bc1) Address (Compressed): bc1qpac4ht6afshdx2tctnhjnetz7u6g3j9zhwwmc4cqkdsa2jumq42qd3drf7 (P2WSH => P2PKH)
**-P2WSH (Starts with bc1) Address (Compressed): bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc (P2WSH => P2WPKH)

=== Addresses Generated from Uncompressed Public Key ===
**-P2PKH (Starts with 1) Address (Uncompressed): 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
**-P2SH (Starts with 3) Address (Uncompressed): 3EyPVdtVrtMJ1XwPT9oiBrQysGpRY8LE9K (P2SH => P2PKH)
**-P2SH (Starts with 3) Address (Uncompressed): 33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (P2SH => P2WPKH)
**-Bech32 (Starts with bc1) Address (Uncompressed): bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h
**-Bech32m (Starts with bc1p) Address (Uncompressed): bc1pjxeyh7049zzn99s2c6r6hvp4zfa362994nkhzu
**-P2WSH (Starts with bc1) Address (Uncompressed): bc1q2zffkaxp5py4fdutfdsrt6t6tcrc5ks09rkfd428hlhf4n5q8tqqym7502 (P2WSH => P2PKH)
**-P2WSH (Starts with bc1) Address (Uncompressed): bc1qdrvr7pa25ayvpxt7yymdkktur98exqj59ydpcvs2sszxqks957vqqrrv3q (P2WSH => P2WPKH)
```
If you need the main address or simple output, please replace the simple C file, or cancel the redundant address output.
```sh
./key 1
WIF Private Key (Compressed): KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
WIF Private Key (Uncompressed): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
Compressed Public Key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Uncompressed Public Key: 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
=== Addresses Generated from Compressed Public Key ===
P2PKH (Starts with 1) Address (Compressed): 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
P2SH (Starts with 3) Address (Compressed): 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Compressed): bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
=== Addresses Generated from Uncompressed Public Key ===
P2PKH (Starts with 1) Address (Uncompressed): 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
P2SH (Starts with 3) Address (Uncompressed): 33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Uncompressed): bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h

```


### 📂 Code Structure

File Description

**-key.c: Main program, handles input, output, and calls other modules.
-
**-ecc/ecc.c & ecc/ecc.h: Elliptic Curve Cryptography related functions, including scalar multiplication.
-
**-sha256/sha256.c & sha256/sha256.h: SHA256 hash algorithm.
-
**-ripemd160/ripemd160.c & ripemd160/ripemd160.h: RIPEMD160 hash algorithm.
-
**-base58/base58.c & base58/base58.h: Base58 encoding/decoding implementation.
-
**-bech32/bech32.c & bech32/bech32.h: Bech32 encoding/decoding implementation.
-
**customutil/customutil.c & customutil/customutil.h: Custom functions for generating public key strings.
-
### ⚠️ Security
Please use this tool with caution, especially with private key generation and handling. Please run it in an offline or secure environment and avoid disclosing your private keys!

Private key disclosure will lead to loss of funds! Please store and manage your keys securely.

### ⚙️ Dependencies
** Before running this tool, please make sure your system has installed GMP and OpenSSL related libraries.

** Thanks to: gemini2.0, ChatGPT-o3mini, Luis Alberto, albertobsd, Bosselaers, Kent "ethereal" Williams-King, and Luke Dashjr.

### Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

-BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
-
-ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
-
-DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
-
-TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
-
-
### ⚠️ Reminder: Do not input real private keys on connected devices!
-
-This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.
-
