#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>

int main()
{
    RC4_KEY rc4_key;

    const int SIZE_KEY = 56;
    unsigned char key[SIZE_KEY];

    char data[] = "RC4 is a symmetric stream cipher and is fairly fast. It allows keys up to 2048 bits in length. It uses an internal table of 256 bytes which is seeded with your key, so you can use smaller key sizes too. Since the source has been available cryptographers have been studying the RC4 cipher with interest.";
    int size_data = strlen(data);

    std::cout << "Message:" << std::endl;
    std::cout << data << std::endl << std::endl;

    RAND_bytes(key, SIZE_KEY);
    std::cout << "Key:" << std::endl;
    for (int idx=0; idx<SIZE_KEY; idx++) {
        std::cout << std::hex << (int)key[idx] << " ";
    }
    std::cout << std::endl << std::endl;

    unsigned char *enc_data = new unsigned char[size_data]();
    unsigned char *dec_data = new unsigned char[size_data+1]();

    RC4_set_key(&rc4_key, SIZE_KEY, key);
    RC4(&rc4_key, size_data, (unsigned char *)data, enc_data);

    RC4_set_key(&rc4_key, SIZE_KEY, key);
    RC4(&rc4_key, size_data, enc_data, dec_data);
    dec_data[size_data] = '\0';

    std::cout << "Decrypted message:" << std::endl;
    for (int idx=0; idx<size_data; idx++)
        std::cout << dec_data[idx];
    std::cout << std::endl << std::endl;

    delete [] dec_data;
    delete [] enc_data;

    return 0;
}
