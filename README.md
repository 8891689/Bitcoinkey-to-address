# Bitcoinkey-to-address
This C language tool converts Bitcoin private key or public key or public key hash 160, calculates various addresses, including P2PKH, P2SH, SegWit and other formats, and supports conversion between hexadecimal and WIF formats of private keys.

## 📌 Project Overview

This tool provides functionality for:

- Generating public keys from private keys (in hexadecimal or WIF format).
- Generating various types of Bitcoin addresses from public keys.
- Generate various types of Bitcoin addresses from public key hash160.

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

1. No dependencies are required, just download the compiler and compile directly.




2. Compile the code:
```
gcc -O3 -o key key.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
gcc -O3 -o skey simple.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
gcc -O3 -o p public.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
gcc -O3 -o h hash160.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c
```
3. or
```sh
make

```
4. Clean Rebuild
```
make clean
```
### 🚀Usage
After successful compilation, you can run the tool from the command line, passing the private key (hexadecimal or WIF format) as an argument:
-
```sh

./key <Private Key (Hex or WIF)>

```
### Example
Input hexadecimal private key
```sh

./key 0000000000000000000000000000000000000000000000000000000000000005
./key 5
./key 0x5
./key 0X5
./key 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBF8or94
./key KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU75s2EPgZf
```
Output:
```sh
./key 5
Input Private Key (Hex): 5
Private Key (Hex, 32 bytes): 0000000000000000000000000000000000000000000000000000000000000005
WIF (Uncompressed): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBF8or94
WIF (Compressed):   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU75s2EPgZf

Public Key (Compressed,   33 bytes): 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
Public Key (Uncompressed, 65 bytes): 042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6

=== Addresses Generated from Compressed Public Key ===
P2PKH:        17Vu7st1U1KwymUKU4jJheHHGRVNqrcfLD
P2SH:         38Bv3RNT1ueL4wAkbAPu8GeDQwn6UhR8gi
P2SH-P2WPKH:  36UVqWe99RXE1aT6K7hVJ6jHqkw2iRCA4h
BECH32:       bc1qgar7sarvmkenkrmljk5slz0cn7ec0jakk4qa7y
BECH32M:      bc1pgar7sarvmkenkrmljk5slz0cn7ec0jakathkn0
P2WSH:        bc1pmlp9eeyk0uhvcu3zmr9d2j5sqxa5h0dsprzrydx3geu0mv0gpu0sydc2ar
P2WSH-P2WPKH: bc1qfun78sap7gw9hsx5e49t6hnxylmcr2atxparm79t7cqasg3jsryq2vpt6l

=== Addresses Generated from Uncompressed Public Key ===
P2PKH:        1E1NUNmYw1G5c3FKNPd435QmDvuNG3auYk
P2SH:         3EhPPvFzUuaThCwkVVHeThmhNTC5qSpr4z
P2SH-P2WPKH:  3Jff9V5Mn3swwYYjzTXPA8Dp5Zz9CnZvdf (Note: Non-standard)
BECH32:       bc1q364c7g23mgjqga9l0nwjmyr97lwdxcpwvdpnnn (Note: Non-standard)
BECH32M:      bc1p364c7g23mgjqga9l0nwjmyr97lwdxcpw8nkc7c (Note: Non-standard)
P2WSH:        bc1p29s4ht7pula0qwu8s26vth9nhnm0qj9s5aj3sj64k0ud3802wdmss9w2vc
P2WSH-P2WPKH: bc1qt3yh3pvnx53xa3flf86eszaju4mku7tf9qg94j6w0pmc7lvr7z8qvmfe4k (Note: Non-standard)

.
.
.
.
.
Input WIF format private key

./key 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBF8or94
Input Private Key (WIF): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBF8or94
Private Key (Hex, 32 bytes): 0000000000000000000000000000000000000000000000000000000000000005
WIF (Compressed):   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU75s2EPgZf

Public Key (Compressed,   33 bytes): 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
Public Key (Uncompressed, 65 bytes): 042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6

=== Addresses Generated from Compressed Public Key ===
P2PKH:        17Vu7st1U1KwymUKU4jJheHHGRVNqrcfLD
P2SH:         38Bv3RNT1ueL4wAkbAPu8GeDQwn6UhR8gi
P2SH-P2WPKH:  36UVqWe99RXE1aT6K7hVJ6jHqkw2iRCA4h
BECH32:       bc1qgar7sarvmkenkrmljk5slz0cn7ec0jakk4qa7y
BECH32M:      bc1pgar7sarvmkenkrmljk5slz0cn7ec0jakathkn0
P2WSH:        bc1pmlp9eeyk0uhvcu3zmr9d2j5sqxa5h0dsprzrydx3geu0mv0gpu0sydc2ar
P2WSH-P2WPKH: bc1qfun78sap7gw9hsx5e49t6hnxylmcr2atxparm79t7cqasg3jsryq2vpt6l

=== Addresses Generated from Uncompressed Public Key ===
P2PKH:        1E1NUNmYw1G5c3FKNPd435QmDvuNG3auYk
P2SH:         3EhPPvFzUuaThCwkVVHeThmhNTC5qSpr4z
P2SH-P2WPKH:  3Jff9V5Mn3swwYYjzTXPA8Dp5Zz9CnZvdf (Note: Non-standard)
BECH32:       bc1q364c7g23mgjqga9l0nwjmyr97lwdxcpwvdpnnn (Note: Non-standard)
BECH32M:      bc1p364c7g23mgjqga9l0nwjmyr97lwdxcpw8nkc7c (Note: Non-standard)
P2WSH:        bc1p29s4ht7pula0qwu8s26vth9nhnm0qj9s5aj3sj64k0ud3802wdmss9w2vc
P2WSH-P2WPKH: bc1qt3yh3pvnx53xa3flf86eszaju4mku7tf9qg94j6w0pmc7lvr7z8qvmfe4k (Note: Non-standard)
```

###  If primary address or simple output is required, use the simple output procedure, or cancel redundant address output.
```sh
./skey 5
./skey 0X5
./skey 0x5
./skey 0000000000000000000000000000000000000000000000000000000000000005
./skey 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
./skey KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

.
.
.
.
.

Input Private Key (Hex): 1
Private Key (Hex, 32 bytes): 0000000000000000000000000000000000000000000000000000000000000001
WIF (Uncompressed): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
WIF (Compressed):   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

Public Key (Compressed,   33 bytes): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Public Key (Uncompressed, 65 bytes): 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

=== Addresses Generated from Compressed Public Key ===
P2PKH:        1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
P2SH-P2WPKH:  3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
BECH32:       bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
P2WSH-P2WPKH: bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc

=== Addresses Generated from Uncompressed Public Key ===
P2PKH:        1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
P2SH-P2WPKH:  33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (Note: Non-standard)
BECH32:       bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h (Note: Non-standard)
P2WSH-P2WPKH: bc1qdrvr7pa25ayvpxt7yymdkktur98exqj59ydpcvs2sszxqks957vqqrrv3q (Note: Non-standard)

```
###  BTC public key calculates various addresses.
```sh

Compressed Public

./p 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Derived Compressed Public Key:   0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Derived Uncompressed Public Key: 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
HASH160 (Compressed PubKey):   751e76e8199196d454941c45d1b3a323f1433bd6
HASH160 (Uncompressed PubKey): 91b24bf9f5288532960ac687abb035127b1d28a5

=== Addresses Generated from Compressed Public Key (Input) ===
P2PKH:        1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
P2SH-P2WPKH:  3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
BECH32:       bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
P2WSH-P2WPKH: bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc

=== Addresses Generated from Uncompressed Public Key (Derived) ===
P2PKH:        1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
P2SH-P2WPKH:  33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (Note: Non-standard)
BECH32:       bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h (Note: Non-standard)
P2WSH-P2WPKH: bc1qdrvr7pa25ayvpxt7yymdkktur98exqj59ydpcvs2sszxqks957vqqrrv3q (Note: Non-standard)


Uncompressed Public

./p 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
Derived Compressed Public Key:   0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Derived Uncompressed Public Key: 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
HASH160 (Compressed PubKey):   751e76e8199196d454941c45d1b3a323f1433bd6
HASH160 (Uncompressed PubKey): 91b24bf9f5288532960ac687abb035127b1d28a5

=== Addresses Generated from Compressed Public Key (Derived) ===
P2PKH:        1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
P2SH-P2WPKH:  3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
BECH32:       bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
P2WSH-P2WPKH: bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc

=== Addresses Generated from Uncompressed Public Key (Input) ===
P2PKH:        1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
P2SH-P2WPKH:  33q2i3GDkpHFAXnD3UdBsKhxzg7pvwAqtN (Note: Non-standard)
BECH32:       bc1qjxeyh7049zzn99s2c6r6hvp4zfa362997dpu0h (Note: Non-standard)
P2WSH-P2WPKH: bc1qdrvr7pa25ayvpxt7yymdkktur98exqj59ydpcvs2sszxqks957vqqrrv3q (Note: Non-standard)

```

### The public key hash 160 calculates various addresses.
```sh
./h 751e76e8199196d454941c45d1b3a323f1433bd6
Input Hash160: 751e76e8199196d454941c45d1b3a323f1433bd6

=== Generated Addresses ===
P2PKH:                    1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
P2SH-P2WPKH:              3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
Bech32 (P2WPKH):          bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
P2WSH (from P2WPKH script):bc1q3qu0094lf9ctzjrhnszmwjuvf9g4kv3dqsp47la2tkdjxawlywtqs5vvrc

```

### ⚙️ Dependencies

Thanks to: gemini, ChatGPT.

### Sponsorship

If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

```sh
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k

ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1

DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky

TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

```
### ⚠️ Reminder: Do not input real private keys on connected devices!
-
-This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.
-
