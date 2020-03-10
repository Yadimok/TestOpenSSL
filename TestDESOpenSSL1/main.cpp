#include <openssl/des.h>

#include <iostream>
#include <cstring>

int main()
{
    DES_cblock des_key, des_iv = {0x00};
    DES_key_schedule des_schedule;
    DES_random_key(&des_key);

    std::cout << "Random key: " << std::endl;
    for (int idx=0; idx<DES_KEY_SZ; idx++) {
        std::cout << std::hex << (int)des_key[idx] << " ";
    }
    std::cout << std::endl << std::endl;

    DES_set_key(&des_key, &des_schedule);

    char text[] = "Here is simple DES CBC mode encryption\\decription example in C++ programming with OpenSSL.";
    const int SIZE_TEXT = strlen(text);

    std::cout << "Text message:" << std::endl;
    std::cout << text << std::endl << std::endl;

    unsigned char *cipher_text = new unsigned char [SIZE_TEXT]();
    unsigned char *decipher_text = new unsigned char[SIZE_TEXT+1]();

    DES_cbc_encrypt((unsigned char *)text, cipher_text, SIZE_TEXT, &des_schedule, &des_iv, DES_ENCRYPT);

    std::cout << "Cipher text:" << std::endl;
    for (int idx=0; idx<SIZE_TEXT; idx++) {
        std::cout << std::hex << (int)cipher_text[idx] << " ";
    }
    std::cout << std::endl << std::endl;

    DES_cbc_encrypt(cipher_text, decipher_text, SIZE_TEXT, &des_schedule, &des_iv, DES_DECRYPT);
    decipher_text[SIZE_TEXT] = '\0';

    std::cout << "Decipher text:" << std::endl;
    for (int idx=0; idx<SIZE_TEXT; idx++) {
        std::cout << decipher_text[idx];
    }
    std::cout << std::endl << std::endl;

    delete [] cipher_text;
    delete [] decipher_text;

  return 0;
}
