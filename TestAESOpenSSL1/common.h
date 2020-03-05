#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <sstream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <vector>
#include <cstring>
#include <ctime>

std::vector<unsigned char> uc_vector_key;
std::vector<unsigned char> uc_vector_iv;

void generateKey(std::vector<unsigned char> &v, int size)
{
    std::srand(std::time(0));

    unsigned char r;

    for (int i=0; i<size; ++i) {
        r = std::rand() % 101 + 26;
        v.push_back(r);
    }
}

void generateIV(std::vector<unsigned char> &v, int size)
{
    std::srand(std::time(0));

    unsigned char r;

    for (int j=0; j<size; ++j) {
        r = std::rand() % 83 + 44;
        v.push_back(r);
    }
}

///<< cbc
void encryptAes256CBC(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;


    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decryptAes256CBC(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}

///<< ecb
void encryptAes256ECB(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;


    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decryptAes256ECB(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}

///<< ofb
void encryptAes256OFB(EVP_CIPHER_CTX *ctx, unsigned char *text, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *cipherText, size_t &resLen)
{
    int len;
    int ciphertext_len;


    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, text, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal(ctx, cipherText + len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    ciphertext_len += len;
    resLen = ciphertext_len;
}

void decryptAes256OFB(EVP_CIPHER_CTX *ctx, unsigned char *cipherText, size_t textLen, unsigned char *key, unsigned char *iv, unsigned char *decipherText, size_t &resLen)
{
    int len;
    int deciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv)) {
        std::cerr << "Init error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, decipherText, &len, cipherText, textLen)) {
        std::cerr << "Update error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(2);
    }
    deciphertext_len = len;

    if (1 != EVP_DecryptFinal(ctx, decipherText+len, &len)) {
        std::cerr << "Final error: " << __FILE__ << '\t' << __LINE__ << std::endl;
        std::exit(3);
    }
    deciphertext_len += len;

    resLen = deciphertext_len;
}

#endif // COMMON_H
