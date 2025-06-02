default:
	gcc -O3 -o key key.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
	gcc -O3 -o skey simple.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
	gcc -O3 -o p public.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c secp256k1/secp256k1.c
	gcc -O3 -o h hash160.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c

clean:
	rm -rf key
	rm -rf skey
	rm -rf p
	rm -rf h
