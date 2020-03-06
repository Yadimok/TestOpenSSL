#include <iostream>
#include <cstring>
#include <openssl/md5.h>
#include <openssl/sha.h>

int main(int argc, char *argv[])
{
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    char md5_test_message[] = "Test message from Qt!";

    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, md5_test_message, strlen(md5_test_message));
    MD5_Final(md5_digest, &md5_ctx);

    std::cout << "MD5:" << std::endl;
    for (int idx=0; idx<MD5_DIGEST_LENGTH; idx++) {
        std::cout << std::hex << (short)md5_digest[idx] << " ";
    }
    std::cout << std::endl;

    unsigned char sha512_digest[SHA512_DIGEST_LENGTH];
    char sha512_test_message[] = "TestHashOpenSSL1";

    SHA512_CTX sha512_ctx;
    SHA512_Init(&sha512_ctx);
    SHA512_Update(&sha512_ctx, sha512_test_message, strlen(sha512_test_message));
    SHA512_Final(sha512_digest, &sha512_ctx);

    std::cout << "SHA512:" << std::endl;
    for (int idx=0; idx<SHA512_DIGEST_LENGTH; idx++) {
        std::cout << std::hex << (short)sha512_digest[idx] << " ";
    }
    std::cout << std::endl;

    return 0;
}
