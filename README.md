# TestOpenSSL & libgcrypt:

1. Test AES256 with modes: ECB, CBC, OFB
2. Test hash functions: MD5, SHA512
3. Test Blowfish with modes: CBC, ECB, OFB
4. Test stream cipher Alleged RC4
5. Test DES with CBC mode
6. Test 3DES with CFB mode
7. Test ARC4 with libgcrypt and MD5
8. Test Salsa20R12 with libgcrypt and GOST R 34.11-2012 256 bits
9. Test GOST28147-89 with libcrypt and RIPEMD-160
10. DigestCipher - Calculations file hash

For `GOST` engine:
1. git clone https://github.com/gost-engine/engine
2. cd engine
3. git checkout openssl_1_1_1
4. mkdir build && cd build/
5. cmake -DCMAKE_BUILD_TYPE=Release ..
6. cmake --build . --config Release
7. sudo cmake --build . --target install --config Release
8. sudo make install
9. sudo nano /usr/lib/ssl/openssl.cnf

	`# OpenSSL example configuration file.`
	
	`# This is mostly being used for generation of certificate requests.`

	`openssl_conf=openssl_def`

	`[openssl_def]`
	
	`engines = engine_section`
	
	`# Engine section`
	
	`[engine_section]`
	
	`gost = gost_section`

	`# Engine gost section`
	
	`[gost_section]`
	
	`engine_id = gost`
	
	`dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/gost.so`
	
	`default_algorithms = ALL`
	
	`CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet`

Check engine:

	`openssl  engine gost -c`
	
	`(gost) Reference implementation of GOST engine`
	[gost89, gost89-cnt, gost89-cnt-12, gost89-cbc, grasshopper-ecb, grasshopper-cbc, grasshopper-cfb, grasshopper-ofb, grasshopper-ctr, magma-cbc, magma-ctr, 		id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm, md_gost94, gost-mac, md_gost12_256, md_gost12_512, gost-mac-12, magma-mac, grasshopper-mac, id-tc26-	cipher-gostr3412-2015-kuznyechik-ctracpkm-omac, gost2001, id-GostR3410-2001DH, gost-mac, gost2012_256, gost2012_512, gost-mac-12, magma-mac, grasshopper-mac, id-tc26-cipher-gostr3412-2015-magma-ctracpkm-omac, id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac]`
	
Get hash file:

	`openssl dgst -engine gost -md_gost12_256 <filename>`

	`openssl dgst -engine gost -md_gost12_512 <filename>`
	
#Note: The libgcrypt library has GOST 34.11-2012 hashing functions (256 and 512 bits), but they do not correctly calculate hash values.
