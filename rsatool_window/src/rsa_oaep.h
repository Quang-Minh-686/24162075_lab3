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

RSALIB_API std::vector<unsigned char> rsaEncryptOAEP(
    const std::vector<unsigned char>& plaintext,
    const std::string& publicKeyFile,
    const std::string& label = "");

RSALIB_API std::vector<unsigned char> rsaDecryptOAEP(
    const std::vector<unsigned char>& ciphertext,
    const std::string& privateKeyFile,
    const std::string& label = "");