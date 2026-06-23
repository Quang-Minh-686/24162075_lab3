#pragma once
#include <string>
#include <vector>

#ifdef _WIN32
  #ifdef RSALIB_EXPORTS
    #define RSALIB_API __declspec(dllexport)
  #else
    #define RSALIB_API __declspec(dllimport)
  #endif
#else
  #define RSALIB_API
#endif

struct RsaKeyPair {
    std::vector<unsigned char> pubPem;
    std::vector<unsigned char> privPem;
    std::vector<unsigned char> pubDer;
    std::vector<unsigned char> privDer;
    std::string metadataJson;
    int modulusBits;
};

RSALIB_API RsaKeyPair generateRsaKeyPair(int bits = 3072);
RSALIB_API void saveToFile(const std::string& path, const std::vector<unsigned char>& data);
RSALIB_API void saveToFile(const std::string& path, const std::string& data);
RSALIB_API std::vector<unsigned char> loadFileBytes(const std::string& path);
RSALIB_API void* loadPublicKeyPem(const std::string& path);
RSALIB_API void* loadPrivateKeyPem(const std::string& path);