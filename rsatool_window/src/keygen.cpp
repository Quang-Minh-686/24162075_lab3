#include "keygen.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

#include <stdexcept>
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>

static std::string opensslLastError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

static std::vector<unsigned char> bioToVec(BIO* bio) {
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::vector<unsigned char>(bptr->data, bptr->data + bptr->length);
}

static std::string isoTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

RsaKeyPair generateRsaKeyPair(int bits) {
    if (bits != 3072 && bits != 4096)
        throw std::runtime_error("Unsupported key size: must be 3072 or 4096");

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS,
                                         const_cast<int*>(&bits));
    params[1] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed: " + opensslLastError());

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed: " + opensslLastError());
    }

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_params failed: " + opensslLastError());
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed: " + opensslLastError());
    }
    EVP_PKEY_CTX_free(ctx);

    RsaKeyPair kp;
    kp.modulusBits = bits;

    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PUBKEY(bio, pkey)) {
            EVP_PKEY_free(pkey); BIO_free(bio);
            throw std::runtime_error("PEM_write_bio_PUBKEY failed");
        }
        kp.pubPem = bioToVec(bio);
        BIO_free(bio);
    }

    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PrivateKey(bio, pkey,
                nullptr, nullptr, 0, nullptr, nullptr)) {
            EVP_PKEY_free(pkey); BIO_free(bio);
            throw std::runtime_error("PEM_write_bio_PrivateKey failed");
        }
        kp.privPem = bioToVec(bio);
        BIO_free(bio);
    }

    {
        int len = i2d_PUBKEY(pkey, nullptr);
        if (len < 0) { EVP_PKEY_free(pkey); throw std::runtime_error("i2d_PUBKEY failed"); }
        kp.pubDer.resize(static_cast<size_t>(len));
        unsigned char* p = kp.pubDer.data();
        i2d_PUBKEY(pkey, &p);
    }

    {
        int len = i2d_PrivateKey(pkey, nullptr);
        if (len < 0) { EVP_PKEY_free(pkey); throw std::runtime_error("i2d_PrivateKey failed"); }
        kp.privDer.resize(static_cast<size_t>(len));
        unsigned char* p = kp.privDer.data();
        i2d_PrivateKey(pkey, &p);
    }

    {
        std::ostringstream js;
        js << "{\n"
           << "  \"creation_time\": \"" << isoTimestamp() << "\",\n"
           << "  \"modulus_bits\": " << bits << ",\n"
           << "  \"hash\": \"SHA-256\",\n"
           << "  \"public_exponent\": 65537,\n"
           << "  \"padding\": \"OAEP\"\n"
           << "}\n";
        kp.metadataJson = js.str();
    }

    EVP_PKEY_free(pkey);
    return kp;
}

void saveToFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open for writing: " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

void saveToFile(const std::string& path, const std::string& data) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot open for writing: " + path);
    f << data;
}

std::vector<unsigned char> loadFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open for reading: " + path);
    auto sz = f.tellg(); f.seekg(0);
    std::vector<unsigned char> buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

void* loadPublicKeyPem(const std::string& path) {
    auto bytes = loadFileBytes(path);
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey)
        throw std::runtime_error("Failed to load public key: " + path
                                 + " — " + opensslLastError());
    return pkey;
}

void* loadPrivateKeyPem(const std::string& path) {
    auto bytes = loadFileBytes(path);
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey)
        throw std::runtime_error("Failed to load private key: " + path
                                 + " — " + opensslLastError());
    return pkey;
}