#include "rsa_oaep.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>

#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

static EVP_PKEY* loadPublicKey(const std::string& file)
{
    FILE* fp = fopen(file.c_str(), "rb");

    if (!fp)
        throw std::runtime_error("Cannot open public key");

    EVP_PKEY* key =
        PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    if (!key)
        throw std::runtime_error("Invalid public key");

    return key;
}

static EVP_PKEY* loadPrivateKey(const std::string& file)
{
    FILE* fp = fopen(file.c_str(), "rb");

    if (!fp)
        throw std::runtime_error("Cannot open private key");

    EVP_PKEY* key =
        PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    if (!key)
        throw std::runtime_error("Invalid private key");

    return key;
}

static size_t getMaxOaepMessageSize(EVP_PKEY* key)
{
    int bits = EVP_PKEY_bits(key);

    size_t k = static_cast<size_t>(bits) / 8;

    constexpr size_t hashLen = 32; // SHA256

    return k - (2 * hashLen) - 2;
}

std::vector<unsigned char> rsaEncryptOAEP(
    const std::vector<unsigned char>& plaintext,
    const std::string& publicKeyFile,
    const std::string& label)
{
    EVP_PKEY* key = loadPublicKey(publicKeyFile);

    size_t maxSize =
        getMaxOaepMessageSize(key);

    if (plaintext.size() > maxSize)
    {
        EVP_PKEY_free(key);

        throw std::runtime_error(
            "Plaintext exceeds RSA-OAEP limit. Use hybrid encryption.");
    }

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(key, nullptr);

    if (!ctx)
    {
        EVP_PKEY_free(key);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        throw std::runtime_error("encrypt init failed");
    }

    EVP_PKEY_CTX_set_rsa_padding(
        ctx,
        RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_CTX_set_rsa_oaep_md(
        ctx,
        EVP_sha256());

    EVP_PKEY_CTX_set_rsa_mgf1_md(
        ctx,
        EVP_sha256());

    if (!label.empty())
    {
        unsigned char* oaepLabel =
            static_cast<unsigned char*>(
                OPENSSL_malloc(label.size()));

        memcpy(
            oaepLabel,
            label.data(),
            label.size());

        EVP_PKEY_CTX_set0_rsa_oaep_label(
            ctx,
            oaepLabel,
            static_cast<int>(label.size()));
    }

    size_t outLen = 0;

    if (EVP_PKEY_encrypt(
            ctx,
            nullptr,
            &outLen,
            plaintext.data(),
            plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);

        throw std::runtime_error(
            "RSA encrypt size calculation failed");
    }

    std::vector<unsigned char> ciphertext(outLen);

    if (EVP_PKEY_encrypt(
            ctx,
            ciphertext.data(),
            &outLen,
            plaintext.data(),
            plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);

        throw std::runtime_error(
            "RSA encrypt failed");
    }

    ciphertext.resize(outLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return ciphertext;
}

std::vector<unsigned char> rsaDecryptOAEP(
    const std::vector<unsigned char>& ciphertext,
    const std::string& privateKeyFile,
    const std::string& label)
{
    EVP_PKEY* key = loadPrivateKey(privateKeyFile);

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(key, nullptr);

    if (!ctx)
    {
        EVP_PKEY_free(key);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        throw std::runtime_error("decrypt init failed");
    }

    EVP_PKEY_CTX_set_rsa_padding(
        ctx,
        RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_CTX_set_rsa_oaep_md(
        ctx,
        EVP_sha256());

    EVP_PKEY_CTX_set_rsa_mgf1_md(
        ctx,
        EVP_sha256());

    if (!label.empty())
    {
        unsigned char* oaepLabel =
            static_cast<unsigned char*>(
                OPENSSL_malloc(label.size()));

        memcpy(
            oaepLabel,
            label.data(),
            label.size());

        EVP_PKEY_CTX_set0_rsa_oaep_label(
            ctx,
            oaepLabel,
            static_cast<int>(label.size()));
    }

    size_t outLen = 0;

    if (EVP_PKEY_decrypt(
            ctx,
            nullptr,
            &outLen,
            ciphertext.data(),
            ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);

        throw std::runtime_error(
            "RSA decrypt size calculation failed");
    }

    std::vector<unsigned char> plaintext(outLen);

    if (EVP_PKEY_decrypt(
            ctx,
            plaintext.data(),
            &outLen,
            ciphertext.data(),
            ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);

        throw std::runtime_error(
            "RSA decrypt failed");
    }

    plaintext.resize(outLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return plaintext;
}