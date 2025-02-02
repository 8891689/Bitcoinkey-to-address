default:
	gcc -O3 -o key key.c sha256/sha256.c base58/base58.c bech32/bech32.c ripemd160/ripemd160.c ecc/ecc.c customutil/customutil.c -lgmp

clean:
	rm -f key

