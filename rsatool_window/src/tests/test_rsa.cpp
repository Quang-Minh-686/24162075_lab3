#include <catch2/catch_test_macros.hpp>

#include "rsa_oaep.h"
#include "hybrid.h"

#include <fstream>
#include <vector>
#include <string>

static std::vector<unsigned char> strToVec(
    const std::string& s)
{
    return std::vector<unsigned char>(
        s.begin(),
        s.end());
}

static void writeFile(
    const std::string& path,
    const std::string& data)
{
    std::ofstream out(
        path,
        std::ios::binary);

    out << data;
}

static std::string readFile(
    const std::string& path)
{
    std::ifstream in(
        path,
        std::ios::binary);

    return std::string(
        std::istreambuf_iterator<char>(in),
        {});
}

TEST_CASE("RSA-OAEP Encrypt/Decrypt")
{
    auto plaintext =
        strToVec("hello world");

    auto cipher =
        rsaEncryptOAEP(
            plaintext,
            "pub.pem");

    auto recovered =
        rsaDecryptOAEP(
            cipher,
            "priv.pem");

    REQUIRE(
        plaintext == recovered);
}

TEST_CASE("RSA-OAEP Label Success")
{
    auto plaintext =
        strToVec("label test");

    auto cipher =
        rsaEncryptOAEP(
            plaintext,
            "pub.pem",
            "mylabel");

    auto recovered =
        rsaDecryptOAEP(
            cipher,
            "priv.pem",
            "mylabel");

    REQUIRE(
        plaintext == recovered);
}

TEST_CASE("RSA-OAEP Wrong Label")
{
    auto plaintext =
        strToVec("wrong label");

    auto cipher =
        rsaEncryptOAEP(
            plaintext,
            "pub.pem",
            "correct");

    REQUIRE_THROWS(
        rsaDecryptOAEP(
            cipher,
            "priv.pem",
            "wrong"));
}

TEST_CASE("RSA Oversized Plaintext")
{
    std::vector<unsigned char> big(
        500,
        'A');

    REQUIRE_THROWS(
        rsaEncryptOAEP(
            big,
            "pub.pem"));
}

TEST_CASE("Hybrid Encrypt/Decrypt")
{
    writeFile(
        "hybrid_input.txt",
        std::string(5000, 'B'));

    hybridEncrypt(
        "hybrid_input.txt",
        "pub.pem",
        "test_env.json",
        "test_cipher.bin");

    hybridDecrypt(
        "test_env.json",
        "test_cipher.bin",
        "priv.pem",
        "hybrid_output.txt");

    auto original =
        readFile("hybrid_input.txt");

    auto recovered =
        readFile("hybrid_output.txt");

    REQUIRE(
        original == recovered);
}

TEST_CASE("Hybrid Tamper Detection")
{
    writeFile(
        "tamper.txt",
        std::string(5000, 'X'));

    hybridEncrypt(
        "tamper.txt",
        "pub.pem",
        "tamper_env.json",
        "tamper_cipher.bin");

    std::fstream f(
        "tamper_cipher.bin",
        std::ios::in |
        std::ios::out |
        std::ios::binary);

    char c;

    f.seekg(10);

    f.get(c);

    c ^= 1;

    f.seekp(10);

    f.put(c);

    f.close();

    REQUIRE_THROWS(
        hybridDecrypt(
            "tamper_env.json",
            "tamper_cipher.bin",
            "priv.pem",
            "tamper_out.txt"));
}