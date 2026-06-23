#pragma once
#include <string>

#ifdef _WIN32
  #ifdef RSALIB_EXPORTS
    #define RSALIB_API __declspec(dllexport)
  #else
    #define RSALIB_API __declspec(dllimport)
  #endif
#else
  #define RSALIB_API
#endif

RSALIB_API void hybridEncrypt(
    const std::string& inputFile,
    const std::string& publicKeyFile,
    const std::string& envelopeFile,
    const std::string& cipherFile);

RSALIB_API void hybridDecrypt(
    const std::string& envelopeFile,
    const std::string& cipherFile,
    const std::string& privateKeyFile,
    const std::string& outputFile);