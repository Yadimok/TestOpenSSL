#include <iostream>
#include <gcrypt.h>

void DumpSexp (const char *prefix, gcry_sexp_t a);
void GenerateKey(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key);
void DoEncrypt(gcry_sexp_t pkey, gcry_sexp_t skey);

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);

    gcry_sexp_t public_key, private_key;

    GenerateKey(&public_key, &private_key);
    DoEncrypt(public_key, private_key);

    gcry_sexp_release(public_key);
    gcry_sexp_release(private_key);

    std::cout << std::endl;

    return 0;
}

void GenerateKey(gcry_sexp_t *pub_key, gcry_sexp_t *priv_key)
{
    gcry_sexp_t pubkey, privkey, key_param, key;
    gpg_error_t error;

    std::cout << "Create S-expression:" << std::endl;
    error = gcry_sexp_new(&key_param,
                       "(genkey\n"
                       " (elg\n"
                       "  (nbits 4:2048)\n"
                       " ))", 0, 1);
    if (error) {
        std::cerr << "Error creating S-expression: " << gpg_strerror(error) << std::endl;
        return;
    }

    error = gcry_pk_genkey(&key, key_param);
    gcry_sexp_release(key_param);
    if (error) {
        std::cerr << "Error generating El Gamal key: " << gpg_strerror(error) << std::endl;
        return;
    }

    pubkey = gcry_sexp_find_token(key, "public-key", 0);
    if (!pubkey) {
        std::cerr << "Could not find public key" << std::endl;
        return;
    }
    DumpSexp("\n\nGenerated El Gamal public key:\n", pubkey);

    privkey = gcry_sexp_find_token(key, "private-key", 0);
    if (!privkey) {
        std::cerr << "Could not find private key" << std::endl;
        return;
    }
    DumpSexp("\n\nGenerated El Gamal private key:\n", privkey);

    gcry_sexp_release(key);

    *pub_key = pubkey;
    *priv_key = privkey;

//    gcry_sexp_release(pubkey);
//    gcry_sexp_release(privkey);
}

void DoEncrypt(gcry_sexp_t pkey, gcry_sexp_t skey)
{
    gcry_sexp_t plaintext, decipher, ciphertext, tmp;
    gpg_error_t error;

    char data[] = "Test message!";

    error = gcry_sexp_build(&plaintext, nullptr, "(data (value %s))", data);
    if (error) {
        std::cerr << "Converting data for encryption failed: " << gcry_strerror(error);
        return;
    }

    ///
    tmp = gcry_sexp_find_token(plaintext, "value", 0);
    gcry_sexp_release(tmp);

    std::cout << "\n\nPlain text:" << std::endl;
    gcry_sexp_dump(plaintext);

    error = gcry_pk_encrypt(&ciphertext, plaintext, pkey);
    if (error) {
        std::cerr << "Encryption failed: " << gcry_strerror(error);
        return;
    }
    std::cout << "\n\nCipher text:" << std::endl;
    DumpSexp("Ciphertext data:", ciphertext);
    ///
    error = gcry_pk_decrypt(&decipher, ciphertext, skey);
    gcry_sexp_release(ciphertext);
    if (error) {
        std::cerr << "Decryption failed: " << gcry_strerror(error);
        return;
    }

    std::cout << "\n\nDecipher text:" << std::endl;
    gcry_sexp_dump(decipher);

    tmp = gcry_sexp_find_token(decipher, "value", 0);
    if (tmp) {
        gcry_sexp_release(tmp);
    }
    ///

    gcry_sexp_release(plaintext);
    gcry_sexp_release(decipher);
}

void DumpSexp (const char *prefix, gcry_sexp_t a)
{
    char *buf;
    size_t size;

    if (prefix)
        fputs (prefix, stderr);
    size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, nullptr, 0);
    buf = (char *)gcry_xmalloc (size);

    gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
    fprintf (stderr, "%.*s", size, buf);
    gcry_free (buf);
}
