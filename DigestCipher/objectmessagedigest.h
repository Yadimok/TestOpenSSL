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


#ifndef OBJECTMESSAGEDIGEST_H
#define OBJECTMESSAGEDIGEST_H

#include <QObject>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include "common.h"
#include "gost3411_2012/gost_3411_2012_calc.h"

class ObjectMessageDigest : public QObject
{
    Q_OBJECT

    enum {
        SIZE_BUFFER_64KB = 1024 * 64,
        SIZE_BUFFER_16KB = 1024 * 16,
        MD_SIZE_STREEBOG_256 = 256,
        MD_SIZE_STREEBOG_512 = 512
    };

    unsigned int    mHashLenth;
    char            mBuffer[SIZE_BUFFER_16KB];
    char            mBufferStreebog[SIZE_BUFFER_64KB];
    unsigned char   mMessageDigest[EVP_MAX_MD_SIZE];

public:
    explicit ObjectMessageDigest(QObject *parent = nullptr);
    virtual ~ObjectMessageDigest();

    void SetMessageDigest(const QString filename, MD_ALGO md_algo);

signals:
    void SendHashResult(QByteArray barray);
    void Finish();

private:
    void MessageDigestMD4(const std::string _filename);
    void MessageDigestMD5(const std::string _fileName);
    void MessageDigestRMD160(const std::string _filename);
    void MessageDigestSha1(const std::string _filename);
    void MessageDigestSha224(const std::string _filename);
    void MessageDigestSha256(const std::string _filename);
    void MessageDigestSha384(const std::string _filename);
    void MessageDigestSha512(const std::string _filename);
    void MessageDigestSha512_224(const std::string _filename);
    void MessageDigestSha512_256(const std::string _filename);
    void MessageDigestSha3_224(const std::string _filename);
    void MessageDigestSha3_256(const std::string _filename);
    void MessageDigestSha3_384(const std::string _filename);
    void MessageDigestSha3_512(const std::string _filename);
    void MessageDigestShake128(const std::string _filename);
    void MessageDigestShake256(const std::string _filename);
    void MessageDigestStreebog256(const std::string _filename);
    void MessageDigestStreebog512(const std::string _filename);


public slots:
};

#endif // OBJECTMESSAGEDIGEST_H
