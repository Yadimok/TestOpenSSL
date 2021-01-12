/*
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "objectmessagedigest.h"
#include <fstream>

#include <QDebug>

ObjectMessageDigest::ObjectMessageDigest(QObject *parent) : QObject(parent)
{
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_algorithms();

    mHashLenth = 0;
    memset(mBuffer, 0x00, sizeof(mBuffer));
    memset(mBufferStreebog, 0x00, sizeof(mBufferStreebog));
    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
}

ObjectMessageDigest::~ObjectMessageDigest()
{
    emit Finish();

    EVP_cleanup();
}

void ObjectMessageDigest::SetMessageDigest(const QString filename, MD_ALGO md_algo)
{
    switch (md_algo) {
    case MD_NONE:
        break;

    case MD_MD4:
        MessageDigestMD4(filename.toStdString());
        break;

    case MD_MD5:
        MessageDigestMD5(filename.toStdString());
        break;

    case MD_RMD160:
        MessageDigestRMD160(filename.toStdString());
        break;

    case MD_SHA1:
        MessageDigestSha1(filename.toStdString());
        break;

    case MD_SHA224:
        MessageDigestSha224(filename.toStdString());
        break;

    case MD_SHA256:
        MessageDigestSha256(filename.toStdString());
        break;

    case MD_SHA384:
        MessageDigestSha384(filename.toStdString());
        break;

    case MD_SHA512:
        MessageDigestSha512(filename.toStdString());
        break;

    case MD_SHA512_224:
        MessageDigestSha512_224(filename.toStdString());
        break;

    case MD_SHA512_256:
        MessageDigestSha512_256(filename.toStdString());
        break;

    case MD_SHA3_224:
        MessageDigestSha3_224(filename.toStdString());
        break;

    case MD_SHA3_256:
        MessageDigestSha3_256(filename.toStdString());
        break;

    case MD_SHA3_384:
        MessageDigestSha3_384(filename.toStdString());
        break;

    case MD_SHA3_512:
        MessageDigestSha3_512(filename.toStdString());
        break;

    case MD_SHAKE128:
        MessageDigestShake128(filename.toStdString());
        break;

    case MD_SHAKE256:
        MessageDigestShake256(filename.toStdString());
        break;

    case MD_STREEBOG256:
        MessageDigestStreebog256(filename.toStdString());
        break;

    case MD_STREEBOG512:
        MessageDigestStreebog512(filename.toStdString());
        break;
    }
}

void ObjectMessageDigest::MessageDigestMD4(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_md4(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof (mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, static_cast<size_t>(src_file.gcount())))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestMD5(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_md5(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestRMD160(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha1(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha224(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha256(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha384(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha512(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha512_224(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha512_224(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha512_256(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha512_256(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha3_224(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha3_224(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha3_256(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha3_384(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha3_384(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestSha3_512(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestShake128(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestShake256(const std::string _filename)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return;

    std::ifstream src_file(_filename, std::ifstream::binary);

    if (!EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr))
        return;

    while (src_file.good()) {
        src_file.read(mBuffer, sizeof(mBuffer));
        if (!EVP_DigestUpdate(ctx, mBuffer, src_file.gcount()))
            return;
    }

    if (!EVP_DigestFinal_ex(ctx, mMessageDigest, &mHashLenth))
        return;

    EVP_MD_CTX_free(ctx);

    QByteArray ba((char *)mMessageDigest, mHashLenth);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBuffer, 0x00, sizeof(mBuffer));

}

void ObjectMessageDigest::MessageDigestStreebog256(const std::string _filename)
{
    TGOSTHashContext *ctx;
    ctx = (TGOSTHashContext *)(malloc(sizeof (TGOSTHashContext)));
    uint16_t hash_size = 256;
    const int N = 4096;
    char buffer[N];

    std::ifstream src_file(_filename, std::ifstream::binary);
    GOSTHashInit(ctx, hash_size);

    while (src_file.good()) {
        src_file.read(buffer, sizeof (buffer));
        GOSTHashUpdate(ctx, (uint8_t *)buffer, src_file.gcount());
    }

    GOSTHashFinal(ctx);

    memcpy(mMessageDigest, &ctx->hash[32], 32);

    free(ctx);

    QByteArray ba((char *)mMessageDigest, hash_size/8);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBufferStreebog, 0x00, sizeof(mBufferStreebog));
}

void ObjectMessageDigest::MessageDigestStreebog512(const std::string _filename)
{
    TGOSTHashContext *ctx;
    ctx = (TGOSTHashContext *)(malloc(sizeof (TGOSTHashContext)));
    uint16_t hash_size = 512;
    const int N = 4096;
    char buffer[N];

    std::ifstream src_file(_filename, std::ifstream::binary);
    GOSTHashInit(ctx, hash_size);

    while (src_file.good()) {
        src_file.read(buffer, sizeof (buffer));
        GOSTHashUpdate(ctx, (uint8_t *)buffer, src_file.gcount());
    }

    GOSTHashFinal(ctx);

    memcpy(mMessageDigest, ctx->hash, 64);

    free(ctx);

    QByteArray ba((char *)mMessageDigest, hash_size/8);
    emit SendHashResult(ba);

    memset(mMessageDigest, 0x00, sizeof(mMessageDigest));
    memset(mBufferStreebog, 0x00, sizeof(mBufferStreebog));
}
