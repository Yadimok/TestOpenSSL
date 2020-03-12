#include <iostream>
#include <gcrypt.h>
#include <cstring>

int main(int argc, char *argv[])
{
    //Key size 256 bits
    const int SIZE_KEY  = 32;
    const int SIZE_IV   = 8;
    unsigned char key[SIZE_KEY];
    unsigned char iv[SIZE_IV];

    char plaintext[] = "Salsa20 and the closely related ChaCha are stream ciphers developed by Daniel J. Bernstein. Because the two ciphers are very similar, this article will describe both together. Salsa20, the original cipher, was designed in 2005, then later submitted to eSTREAM by Bernstein. ChaCha is a modification of Salsa20 published in 2008. It uses a new round function that increases diffusion and increases performance on some architectures.";
    size_t lenText = strlen(plaintext);

    unsigned char *encrypted_text = (unsigned char *)gcry_malloc(lenText);
    unsigned char *decrypted_text = (unsigned char *)gcry_malloc(lenText+1);

    gcry_randomize(key, SIZE_KEY, GCRY_VERY_STRONG_RANDOM);
    gcry_randomize(iv, SIZE_IV, GCRY_WEAK_RANDOM);

    std::cout << "Stream algo: " << gcry_cipher_algo_name(GCRY_CIPHER_SALSA20R12) << std::endl;
    std::cout << "Generated key:" << std::endl;
    for (int i=0; i<SIZE_KEY; i++) {
        std::cout << std::hex << static_cast<int>(key[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    std::cout << "Generated iv:" << std::endl;
    for (int i=0; i<SIZE_IV; i++) {
        std::cout << std::hex << static_cast<int>(iv[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    gcry_cipher_hd_t handle;
    gcry_error_t error = 0;

    error = gcry_cipher_open(&handle, GCRY_CIPHER_SALSA20R12, GCRY_CIPHER_MODE_STREAM, GCRY_CIPHER_SECURE);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

    error = gcry_cipher_setkey(handle, key, SIZE_KEY);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }

    error = gcry_cipher_setiv(handle, iv, SIZE_IV);
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

    error = gcry_cipher_setiv(handle, iv, SIZE_IV);
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


    gcry_md_hd_t md_handle;

    const int MD_STRIBOG = 32;
    unsigned char stribog_plaintext[MD_STRIBOG];
    unsigned char stribog_decrypted[MD_STRIBOG];

    std::cout << "MD algo: " << gcry_md_algo_name(GCRY_MD_STRIBOG256) << std::endl;
    error = gcry_md_open(&md_handle, GCRY_MD_STRIBOG256, GCRY_MD_FLAG_SECURE);
    if (error)
    {
        std::cout << gcry_strerror(error) << "\t" << gcry_strsource(error) << std::endl;
    }
    gcry_md_write(md_handle, plaintext, lenText);

    std::cout << "Calculated STRIBOG256 from plain text:" << std::endl;
    memcpy(stribog_plaintext, gcry_md_read(md_handle, GCRY_MD_STRIBOG256), MD_STRIBOG);
    for (int i=0; i<MD_STRIBOG; i++) {
        std::cout << std::hex << static_cast<int>(stribog_plaintext[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    gcry_md_reset(md_handle);

    gcry_md_write(md_handle, decrypted_text, lenText);

    std::cout << "Calculated STRIBOG256 from decrypted text:" << std::endl;
    memcpy(stribog_decrypted, gcry_md_read(md_handle, GCRY_MD_STRIBOG256), MD_STRIBOG);
    for (int i=0; i<MD_STRIBOG; i++) {
        std::cout << std::hex << static_cast<int>(stribog_decrypted[i]) << " ";
    }
    std::cout << std::endl << std::endl;

    if (strncmp((const char *)stribog_plaintext, (const char *)stribog_decrypted, MD_STRIBOG) == 0) {
        std::cout << "Success!" << std::endl;
    } else {
        std::cout << "Data is not matched!" << std::endl;
    }

    gcry_md_close(md_handle);

    gcry_free(encrypted_text);
    gcry_free(decrypted_text);

    return 0;
}
