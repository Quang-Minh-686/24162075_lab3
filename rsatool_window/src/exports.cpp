#ifdef _WIN32
  #define DLL_EXPORT __declspec(dllexport)
#else
  #define DLL_EXPORT
#endif

#include "exports.h"
#include "rsa_oaep.h"

#include <fstream>
#include <vector>

static std::vector<unsigned char> readFile(
    const std::string& path)
{
    std::ifstream in(path, std::ios::binary);

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        {});
}

static void writeFile(
    const std::string& path,
    const std::vector<unsigned char>& data)
{
    std::ofstream out(path, std::ios::binary);

    out.write(
        reinterpret_cast<const char*>(data.data()),
        data.size());
}

DLL_EXPORT int rsa_encrypt_file(
    const char* inFile,
    const char* pubKey,
    const char* outFile)
{
    try
    {
        auto plain =
            readFile(inFile);

        auto cipher =
            rsaEncryptOAEP(
                plain,
                pubKey);

        writeFile(
            outFile,
            cipher);

        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

DLL_EXPORT int rsa_decrypt_file(
    const char* inFile,
    const char* privKey,
    const char* outFile)
{
    try
    {
        auto cipher =
            readFile(inFile);

        auto plain =
            rsaDecryptOAEP(
                cipher,
                privKey);

        writeFile(
            outFile,
            plain);

        return 0;
    }
    catch (...)
    {
        return -1;
    }
}