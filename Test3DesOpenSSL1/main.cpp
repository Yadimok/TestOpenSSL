#include <openssl/rand.h>
#include <openssl/des.h>

#include <iostream>
#include <cstring>

int main()
{
    DES_cblock des_key1, des_key2, des_key3, des_iv = {0x00};
    DES_key_schedule des_schedule1, des_schedule2, des_schedule3;

    const int NUM_BITS = 4;

    DES_random_key(&des_key1);
    DES_random_key(&des_key2);
    DES_random_key(&des_key3);

    DES_set_odd_parity(&des_iv);

    std::cout << "Random keys:" << std::endl;
    std::cout << "Random key #1:" << std::endl;
    for (int idx=0; idx<DES_KEY_SZ; idx++) {
        std::cout << std::hex << (int)des_key1[idx] << " ";
    }
    std::cout << std::endl;

    std::cout << "Random key #2:" << std::endl;
    for (int idx=0; idx<DES_KEY_SZ; idx++) {
        std::cout << std::hex << (int)des_key2[idx] << " ";
    }
    std::cout << std::endl;

    std::cout << "Random key #3:" << std::endl;
    for (int idx=0; idx<DES_KEY_SZ; idx++) {
        std::cout << std::hex << (int)des_key3[idx] << " ";
    }
    std::cout << std::endl << std::endl;

    DES_set_key_checked(&des_key1, &des_schedule1);
    DES_set_key_checked(&des_key2, &des_schedule2);
    DES_set_key_checked(&des_key3, &des_schedule3);

    char text[] = "Example Triple DES with CFB mode.";
    const int SIZE_TEXT = strlen(text);

    std::cout << "Text message:" << std::endl;
    std::cout << text << std::endl << std::endl;

    unsigned char *cipher_text = new unsigned char [SIZE_TEXT]();
    unsigned char *decipher_text = new unsigned char[SIZE_TEXT+1]();

    DES_ede3_cfb_encrypt((unsigned char *)text, cipher_text, NUM_BITS, SIZE_TEXT, &des_schedule1, &des_schedule2, &des_schedule3, &des_iv, DES_ENCRYPT);

    std::cout << "Cipher text:" << std::endl;
    for (int idx=0; idx<SIZE_TEXT; idx++) {
        std::cout << std::hex << (int)cipher_text[idx] << " ";
    }
    std::cout << std::endl << std::endl;

    memset(des_iv, 0, sizeof(des_iv));
    DES_set_odd_parity(&des_iv);

    DES_ede3_cfb_encrypt(cipher_text, decipher_text, NUM_BITS, SIZE_TEXT, &des_schedule1, &des_schedule2, &des_schedule3, &des_iv, DES_DECRYPT);
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
