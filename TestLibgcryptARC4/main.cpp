#include <gcrypt.h>
#include <iostream>
#include <cstring>

int main()
{
    //Key sizes	40–2048 bits (5 - 256 bytes)
    const int SIZE_KEY = 128;
    unsigned char key[SIZE_KEY];

    gcry_cipher_hd_t handle;
    gcry_error_t error = 0;

    char plaintext[] = "In cryptography, RC4 (Rivest Cipher 4 also known as ARC4 or ARCFOUR meaning Alleged RC4) is a stream cipher. While it is remarkable for its simplicity and speed in software, multiple vulnerabilities have been discovered in RC4, rendering it insecure. It is especially vulnerable when the beginning of the output keystream is not discarded, or when nonrandom or related keys are used.";
    size_t lenText = strlen(plaintext);

    unsigned char *encrypted_text = (unsigned char *)gcry_malloc(lenText);
    unsigned char *decrypted_text = (unsigned char *)gcry_malloc(lenText+1);

    gcry_randomize(key, SIZE_KEY, GCRY_VERY_STRONG_RANDOM);

    std::cout << "Stream algo: " << gcry_cipher_algo_name(GCRY_CIPHER_ARCFOUR) << std::endl;
    std::cout << "Generated key:" << std::endl;
    for (int i=0; i<SIZE_KEY; i++) {
        std::cout << std::hex << static_cast<int>(key[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    error = gcry_cipher_open(&handle, GCRY_CIPHER_ARCFOUR,GCRY_CIPHER_MODE_STREAM, GCRY_CIPHER_SECURE);
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

    error = gcry_cipher_setkey(handle, key, SIZE_KEY);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

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


    const int MD5_SIZE = 16;
    unsigned char md5_plaintext[MD5_SIZE];
    unsigned char md5_decrypted[MD5_SIZE];

    gcry_md_hd_t md_handle;

    std::cout << "MD algo: " << gcry_md_algo_name(GCRY_MD_MD5) << std::endl;
    error = gcry_md_open(&md_handle, GCRY_MD_MD5, GCRY_MD_FLAG_SECURE);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }
    gcry_md_write(md_handle, plaintext, lenText);

    std::cout << "Calculated MD5 from plain text:" << std::endl;
    memcpy(md5_plaintext, gcry_md_read(md_handle, GCRY_MD_MD5), MD5_SIZE);
    for (int i=0; i<MD5_SIZE; i++) {
        std::cout << std::hex << (int)md5_plaintext[i] << " ";
    }
    std::cout << std::endl << std::endl;

    gcry_md_reset(md_handle);

    gcry_md_write(md_handle, decrypted_text, lenText);

    std::cout << "Calculated MD5 from decrypted text:" << std::endl;
    memcpy(md5_decrypted, gcry_md_read(md_handle, GCRY_MD_MD5), MD5_SIZE);
    for (int i=0; i<MD5_SIZE; i++) {
        std::cout << std::hex << static_cast<int>(md5_decrypted[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    if (strncmp((const char *)md5_plaintext, (const char *)md5_decrypted, MD5_SIZE) == 0) {
        std::cout << "Success!" << std::endl;
    } else {
        std::cout << "Data is not matched!" << std::endl;
    }

    gcry_free(encrypted_text);
    gcry_free(decrypted_text);

    gcry_md_close(md_handle);

    return 0;
}
