#ifndef COMMON_BF_H
#define COMMON_BF_H


#include <iostream>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>

///<< cbc
void encrypt_BF_CBC(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decrypt_BF_CBC(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}


///<< ecb
void encrypt_BF_ECB(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_bf_ecb(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decrypt_BF_ECB(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_bf_ecb(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}

///<< ofb
void encrypt_BF_OFB(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_bf_ofb(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decrypt_BF_OFB(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned int sizeKey,
                    unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_bf_ofb(), NULL, NULL, NULL)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, sizeKey)) {
        std::cerr << "Set key error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(4);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(5);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}


#endif // COMMON_BF_H
