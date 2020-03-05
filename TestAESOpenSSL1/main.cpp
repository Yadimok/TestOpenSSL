#include "common.h"

int main(int argc, char *argv[])
{
    const int SIZE_KEY = 32;
    const int SIZE_IV = 16;

    unsigned char key[SIZE_KEY];
    unsigned char iv[SIZE_IV];

    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();

    generateKey(uc_vector_key, SIZE_KEY);
    generateIV(uc_vector_iv, SIZE_IV);

    std::cout << "Key:" << std::endl;
    for (int idx=0; idx<SIZE_KEY; ++idx)
    {
        std::cout << (key[idx] = uc_vector_key.at(idx));

    }
    std::cout << std::endl << std::endl;

    std::cout << "IV:" << std::endl;
    for (int idx=0; idx<SIZE_IV; ++idx)
    {
        std::cout << (iv[idx] = uc_vector_iv.at(idx));
    }
    std::cout << std::endl << std::endl;

    char text[] = "The code below sets up the program. In this example we are going to take a simple message (The quick brown fox jumps over the lazy dog), and then encrypt it using a predefined key and IV. In this example the key and IV have been hard coded in - in a real situation you would never do this! Following encryption we will then decrypt the resulting ciphertext, and (hopefully!) end up with the message we first started with. This program expects two functions to be defined: encrypt and decrypt. We will define those further down the page. Note that this uses the auto-init facility in 1.1.0.";
    size_t lenText = strlen((char *)text);

    std::cout << "Text message:\n";
    std::cout << text << std::endl;
    std::cout << std::endl << std::endl;


    unsigned char *cipher_text = new unsigned char[lenText+1]();
    unsigned char *decipher_text = new unsigned char[lenText+1]();

    size_t decryptedtext_len, ciphertext_len;

    // modes
//    encryptAes256CBC(e_ctx, (unsigned char *)text, lenText, key, iv, cipher_text, ciphertext_len);
//    decryptAes256CBC(d_ctx, cipher_text, ciphertext_len, key, iv, decipher_text, decryptedtext_len);

//    encryptAes256ECB(e_ctx, (unsigned char *)text, lenText, key, iv, cipher_text, ciphertext_len);
//    decryptAes256ECB(d_ctx, cipher_text, ciphertext_len, key, iv, decipher_text, decryptedtext_len);

    encryptAes256OFB(e_ctx, (unsigned char *)text, lenText, key, iv, cipher_text, ciphertext_len);
    decryptAes256OFB(d_ctx, cipher_text, ciphertext_len, key, iv, decipher_text, decryptedtext_len);

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
