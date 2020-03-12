#include <iostream>
#include <gcrypt.h>
#include <cstring>

int main(int argc, char *argv[])
{
    //Key size 256 bits
    const int SIZE_KEY  = 32;
    unsigned char key[SIZE_KEY];

    char plaintext[] = "The GOST block cipher (Magma), defined in the standard GOST 28147-89 (RFC 5830), is a Soviet and Russian government standard symmetric key block cipher with a block size of 64 bits. The original standard, published in 1989, did not give the cipher any name, but the most recent revision of the standard, GOST R 34.12-2015, specifies that it may be referred to as Magma. The GOST hash function is based on this cipher. The new standard also specifies a new 128-bit block cipher called Kuznyechik. Developed in the 1970s, the standard had been marked Top Secret and then downgraded to Secret in 1990. Shortly after the dissolution of the USSR, it was declassified and it was released to the public in 1994. GOST 28147 was a Soviet alternative to the United States standard algorithm, DES. Thus, the two are very similar in structure..";
//    char plaintext[] = "01234567";
    size_t lenText = strlen(plaintext);
    std::cout << "size: " << lenText << std::endl;

    unsigned char *encrypted_text = (unsigned char *)gcry_malloc(lenText);
    unsigned char *decrypted_text = (unsigned char *)gcry_malloc(lenText+1);

    gcry_randomize(key, SIZE_KEY, GCRY_VERY_STRONG_RANDOM);

    std::cout << "Stream algo: " << gcry_cipher_algo_name(GCRY_CIPHER_GOST28147) << std::endl;
    std::cout << "Generated key:" << std::endl;
    for (int i=0; i<SIZE_KEY; i++) {
        std::cout << std::hex << static_cast<int>(key[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    gcry_cipher_hd_t handle;
    gcry_error_t error = 0;

    error = gcry_cipher_open(&handle, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

    error = gcry_cipher_setkey(handle, key, SIZE_KEY);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

    std::cout << "Message:" << std::endl;
    std::cout << plaintext << std::endl << std::endl;

    error = gcry_cipher_encrypt(handle, encrypted_text, lenText, (unsigned char *)plaintext, lenText);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

    std::cout << "Encrypted message:" << std::endl;
    for (size_t i=0; i<lenText; i++) {
        std::cout << std::hex << static_cast<int>(encrypted_text[i]) << " ";
    }
    std::cout << std::endl << std::endl;

//    error = gcry_cipher_setkey(handle, key, SIZE_KEY);
//    if (error)
//    {
//        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
//    }

    error = gcry_cipher_decrypt(handle, decrypted_text, lenText, encrypted_text, lenText);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }
    decrypted_text[lenText] = '\0';

    std::cout << "Decrypted message:" << std::endl;
    for (size_t i=0; i<lenText; i++) {
        std::cout << decrypted_text[i];
    }
    std::cout << std::endl << std::endl;

    gcry_cipher_close(handle);


    gcry_md_hd_t md_handle;

    const int MD_RIPEMD160 = 20;
    unsigned char ripemd_plaintext[MD_RIPEMD160];
    unsigned char ripemd_decrypted[MD_RIPEMD160];

    std::cout << "MD algo: " << gcry_md_algo_name(GCRY_MD_RMD160) << std::endl;
    error = gcry_md_open(&md_handle, GCRY_MD_RMD160, GCRY_MD_FLAG_SECURE);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }
    gcry_md_write(md_handle, plaintext, lenText);

    std::cout << "Calculated RIPEMD-160 from plain text:" << std::endl;
    memcpy(ripemd_plaintext, gcry_md_read(md_handle, GCRY_MD_RMD160), MD_RIPEMD160);
    for (int i=0; i<MD_RIPEMD160; i++) {
        std::cout << std::hex << static_cast<int>(ripemd_plaintext[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    gcry_md_reset(md_handle);

    gcry_md_write(md_handle, decrypted_text, lenText);

    std::cout << "Calculated RIPEMD-160 from decrypted text:" << std::endl;
    memcpy(ripemd_decrypted, gcry_md_read(md_handle, GCRY_MD_RMD160), MD_RIPEMD160);
    for (int i=0; i<MD_RIPEMD160; i++) {
        std::cout << std::hex << static_cast<int>(ripemd_decrypted[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    if (strncmp((const char *)ripemd_plaintext, (const char *)ripemd_decrypted, MD_RIPEMD160) == 0) {
        std::cout << "Success!" << std::endl;
    } else {
        std::cout << "Data is not matched!" << std::endl;
    }

    gcry_md_close(md_handle);

    gcry_free(encrypted_text);
    gcry_free(decrypted_text);

    return 0;
}
