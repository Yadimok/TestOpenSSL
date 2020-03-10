#include "common_bf.h"

int main(int argc, char *argv[])
{
    const int SIZE_KEY = 24; //(8 - 56 bytes)
    const int SIZE_IV = 9;

    unsigned char key[SIZE_KEY] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x10, 0x20, 0x30, 0x40, 0x05};

    unsigned char iv[SIZE_IV] = {0x06, 0x07, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();


    std::cout << "Key:" << std::endl;
    for (int idx=0; idx<SIZE_KEY; ++idx)
    {
        std::cout << std::hex << (int)(key[idx]);

    }
    std::cout << std::endl << std::endl;

    std::cout << "IV:" << std::endl;
    for (int idx=0; idx<SIZE_IV; ++idx)
    {
        std::cout << std::hex << (int)(iv[idx]);
    }
    std::cout << std::endl << std::endl;

    char text[] = "Schneier designed Blowfish as a general-purpose algorithm, intended as an alternative to the aging DES and free of the problems and constraints associated with other algorithms. At the time Blowfish was released, many other designs were proprietary, encumbered by patents or were commercial or government secrets. Schneier has stated that, Blowfish is unpatented, and will remain so in all countries. The algorithm is hereby placed in the public domain, and can be freely used by anyone.";
    size_t lenText = strlen((char *)text);

    std::cout << "Text message:\n";
    std::cout << text << std::endl;
    std::cout << std::endl << std::endl;


    unsigned char *cipher_text = new unsigned char[lenText+1]();
    unsigned char *decipher_text = new unsigned char[lenText+1]();

    size_t decryptedtext_len, ciphertext_len;

    // modes
//    encrypt_BF_CBC(e_ctx, (unsigned char *)text, lenText, key, SIZE_KEY, iv, cipher_text, ciphertext_len);
//    decrypt_BF_CBC(d_ctx, cipher_text, ciphertext_len, key, SIZE_KEY, iv, decipher_text, decryptedtext_len);

//    encrypt_BF_ECB(e_ctx, (unsigned char *)text, lenText, key, SIZE_KEY, iv, cipher_text, ciphertext_len);
//    decrypt_BF_ECB(d_ctx, cipher_text, ciphertext_len, key, SIZE_KEY, iv, decipher_text, decryptedtext_len);

    encrypt_BF_OFB(e_ctx, (unsigned char *)text, lenText, key, SIZE_KEY, iv, cipher_text, ciphertext_len);
    decrypt_BF_OFB(d_ctx, cipher_text, ciphertext_len, key, SIZE_KEY, iv, decipher_text, decryptedtext_len);


    decipher_text[decryptedtext_len] = '\0';

    std::cout << "Decrypted message:\n";
    std::cout << decipher_text << std::endl;
    std::cout << std::endl << std::endl;


    EVP_CIPHER_CTX_free(e_ctx);
    EVP_CIPHER_CTX_free(d_ctx);

    delete [] cipher_text;
    delete [] decipher_text;

    return 0;
}
