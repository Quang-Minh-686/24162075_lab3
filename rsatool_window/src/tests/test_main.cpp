#include <catch2/catch_test_macros.hpp>
#include <openssl/evp.h>
#include "keygen.h"
#include <cstdio>

TEST_CASE("RSA-3072 keygen produces non-empty keys", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    REQUIRE(!kp.pubPem.empty());
    REQUIRE(!kp.privPem.empty());
    REQUIRE(!kp.pubDer.empty());
    REQUIRE(!kp.privDer.empty());
    REQUIRE(!kp.metadataJson.empty());
    REQUIRE(kp.modulusBits == 3072);
}

TEST_CASE("RSA-4096 keygen produces non-empty keys", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(4096);
    REQUIRE(!kp.pubPem.empty());
    REQUIRE(kp.modulusBits == 4096);
}

TEST_CASE("RSA-3072 PEM starts with correct header", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    std::string pub(kp.pubPem.begin(),  kp.pubPem.end());
    std::string priv(kp.privPem.begin(), kp.privPem.end());
    REQUIRE(pub.find("-----BEGIN PUBLIC KEY-----")  != std::string::npos);
    REQUIRE(priv.find("-----BEGIN")                 != std::string::npos);
}

TEST_CASE("Metadata JSON contains required fields", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    REQUIRE(kp.metadataJson.find("creation_time") != std::string::npos);
    REQUIRE(kp.metadataJson.find("3072")          != std::string::npos);
    REQUIRE(kp.metadataJson.find("SHA-256")       != std::string::npos);
}

TEST_CASE("DER public key starts with SEQUENCE tag 0x30", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    REQUIRE(!kp.pubDer.empty());
    REQUIRE(kp.pubDer[0] == 0x30);
}

TEST_CASE("Two keygens produce different keys", "[keygen]") {
    RsaKeyPair kp1 = generateRsaKeyPair(3072);
    RsaKeyPair kp2 = generateRsaKeyPair(3072);
    REQUIRE(kp1.pubDer != kp2.pubDer);
}

TEST_CASE("Unsupported key size throws", "[keygen][negative]") {
    REQUIRE_THROWS_AS(generateRsaKeyPair(1024), std::runtime_error);
    REQUIRE_THROWS_AS(generateRsaKeyPair(2048), std::runtime_error);
}

TEST_CASE("saveToFile and loadFileBytes round-trip", "[fileio]") {
    std::vector<unsigned char> data = {0x01, 0x02, 0x03, 0xAA, 0xFF};
    saveToFile("_test_tmp.bin", data);
    auto loaded = loadFileBytes("_test_tmp.bin");
    REQUIRE(data == loaded);
    std::remove("_test_tmp.bin");
}

TEST_CASE("loadPublicKeyPem round-trip via file", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    saveToFile("_test_pub.pem", kp.pubPem);
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(loadPublicKeyPem("_test_pub.pem"));
    REQUIRE(pkey != nullptr);
    EVP_PKEY_free(pkey);
    std::remove("_test_pub.pem");
}

TEST_CASE("loadPrivateKeyPem round-trip via file", "[keygen]") {
    RsaKeyPair kp = generateRsaKeyPair(3072);
    saveToFile("_test_priv.pem", kp.privPem);
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(loadPrivateKeyPem("_test_priv.pem"));
    REQUIRE(pkey != nullptr);
    EVP_PKEY_free(pkey);
    std::remove("_test_priv.pem");
}