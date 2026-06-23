#include "hybrid.h"
#include "rsa_oaep.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <sstream>
#include <iomanip>

static std::vector<unsigned char> readBinary(
    const std::string& path)
{
    std::ifstream in(path, std::ios::binary);

    if (!in)
        throw std::runtime_error("Cannot open input file");

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        {});
}

static void writeBinary(
    const std::string& path,
    const std::vector<unsigned char>& data)
{
    std::ofstream out(path, std::ios::binary);

    if (!out)
        throw std::runtime_error("Cannot write output file");

    out.write(
        reinterpret_cast<const char*>(data.data()),
        data.size());
}

static std::string toHex(
    const std::vector<unsigned char>& data)
{
    std::ostringstream oss;

    for (unsigned char b : data)
    {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << (int)b;
    }

    return oss.str();
}

static std::vector<unsigned char> fromHex(
    const std::string& hex)
{
    std::vector<unsigned char> out;

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        std::string byte =
            hex.substr(i, 2);

        out.push_back(
            static_cast<unsigned char>(
                std::stoi(byte, nullptr, 16)));
    }

    return out;
}

static std::string extractJson(
    const std::string& json,
    const std::string& key)
{
    std::string target =
        "\"" + key + "\"";

    size_t pos =
        json.find(target);

    if (pos == std::string::npos)
        throw std::runtime_error("JSON parse error");

    pos = json.find(':', pos);
    pos = json.find('"', pos);
    size_t end =
        json.find('"', pos + 1);

    return json.substr(
        pos + 1,
        end - pos - 1);
}

void hybridEncrypt(
    const std::string& inputFile,
    const std::string& publicKeyFile,
    const std::string& envelopeFile,
    const std::string& cipherFile)
{
    auto plaintext =
        readBinary(inputFile);

    std::vector<unsigned char> aesKey(32);
    std::vector<unsigned char> iv(12);

    RAND_bytes(aesKey.data(), aesKey.size());
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr);

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        iv.size(),
        nullptr);

    EVP_EncryptInit_ex(
        ctx,
        nullptr,
        nullptr,
        aesKey.data(),
        iv.data());

    std::vector<unsigned char> ciphertext(
        plaintext.size());

    int len = 0;
    int total = 0;

    EVP_EncryptUpdate(
        ctx,
        ciphertext.data(),
        &len,
        plaintext.data(),
        plaintext.size());

    total += len;

    EVP_EncryptFinal_ex(
        ctx,
        ciphertext.data() + total,
        &len);

    total += len;

    ciphertext.resize(total);

    std::vector<unsigned char> tag(16);

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_GET_TAG,
        16,
        tag.data());

    EVP_CIPHER_CTX_free(ctx);

    auto wrappedKey =
        rsaEncryptOAEP(
            aesKey,
            publicKeyFile);

    std::ofstream env(envelopeFile);

    env
        << "{\n"
        << "  \"alg\":\"AES-256-GCM\",\n"
        << "  \"iv\":\"" << toHex(iv) << "\",\n"
        << "  \"tag\":\"" << toHex(tag) << "\",\n"
        << "  \"wrapped_key\":\""
        << toHex(wrappedKey)
        << "\"\n"
        << "}\n";

    env.close();

    writeBinary(
        cipherFile,
        ciphertext);
}

void hybridDecrypt(
    const std::string& envelopeFile,
    const std::string& cipherFile,
    const std::string& privateKeyFile,
    const std::string& outputFile)
{
    std::ifstream env(envelopeFile);

    std::stringstream buffer;

    buffer << env.rdbuf();

    std::string json =
        buffer.str();

    auto iv =
        fromHex(
            extractJson(json, "iv"));

    auto tag =
        fromHex(
            extractJson(json, "tag"));

    auto wrappedKey =
        fromHex(
            extractJson(json, "wrapped_key"));

    auto aesKey =
        rsaDecryptOAEP(
            wrappedKey,
            privateKeyFile);

    auto ciphertext =
        readBinary(cipherFile);

    EVP_CIPHER_CTX* ctx =
        EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        nullptr,
        nullptr,
        nullptr);

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        iv.size(),
        nullptr);

    EVP_DecryptInit_ex(
        ctx,
        nullptr,
        nullptr,
        aesKey.data(),
        iv.data());

    std::vector<unsigned char> plaintext(
        ciphertext.size());

    int len = 0;
    int total = 0;

    EVP_DecryptUpdate(
        ctx,
        plaintext.data(),
        &len,
        ciphertext.data(),
        ciphertext.size());

    total += len;

    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_TAG,
        tag.size(),
        tag.data());

    int ret =
        EVP_DecryptFinal_ex(
            ctx,
            plaintext.data() + total,
            &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
    {
        throw std::runtime_error(
            "AES-GCM authentication failed");
    }

    total += len;

    plaintext.resize(total);

    writeBinary(
        outputFile,
        plaintext);
}