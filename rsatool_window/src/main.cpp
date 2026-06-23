#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>

#include "keygen.h"
#include "rsa_oaep.h"
#include "hybrid.h"
#include "benchmark.h"

static std::string getArg(
    const std::vector<std::string>& args,
    const std::string& flag,
    const std::string& def = "")
{
    for (size_t i = 0; i + 1 < args.size(); ++i)
    {
        if (args[i] == flag)
            return args[i + 1];
    }

    return def;
}

static bool hasFlag(
    const std::vector<std::string>& args,
    const std::string& flag)
{
    return std::find(
               args.begin(),
               args.end(),
               flag)
           != args.end();
}

static std::vector<unsigned char> readBinary(
    const std::string& path)
{
    std::ifstream in(
        path,
        std::ios::binary);

    if (!in)
        throw std::runtime_error(
            "Cannot open file: " + path);

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}

static void writeBinary(
    const std::string& path,
    const std::vector<unsigned char>& data)
{
    std::ofstream out(
        path,
        std::ios::binary);

    if (!out)
        throw std::runtime_error(
            "Cannot write file: " + path);

    out.write(
        reinterpret_cast<const char*>(data.data()),
        data.size());
}

static void printUsage()
{
    std::cout
        << "rsatool v1.0\n"
        << "\n"
        << "Commands:\n"
        << "  keygen\n"
        << "  encrypt\n"
        << "  decrypt\n"
        << "\n"
        << "Examples:\n"
        << "  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem\n"
        << "  rsatool encrypt --in plain.txt --pub pub.pem --out cipher.bin\n"
        << "  rsatool decrypt --in cipher.bin --priv priv.pem --out recovered.txt\n";
}

static int cmdKeygen(
    const std::vector<std::string>& args)
{
    int bits =
        std::stoi(
            getArg(args,
                   "--bits",
                   "3072"));

    std::string pubPath =
        getArg(args,
               "--pub",
               "pub.pem");

    std::string privPath =
        getArg(args,
               "--priv",
               "priv.pem");

    bool verbose =
        hasFlag(args,
                "--verbose");

    if (bits != 3072 &&
        bits != 4096)
    {
        std::cerr
            << "[ERROR] bits must be 3072 or 4096\n";

        return 1;
    }

    try
    {
        std::cout
            << "[*] Generating RSA-"
            << bits
            << " key pair...\n";

        RsaKeyPair kp =
            generateRsaKeyPair(bits);

        saveToFile(
            pubPath,
            kp.pubPem);

        saveToFile(
            privPath,
            kp.privPem);

        std::string derPub =
            pubPath.substr(
                0,
                pubPath.rfind('.'))
            + ".der";

        std::string derPriv =
            privPath.substr(
                0,
                privPath.rfind('.'))
            + "_priv.der";

        saveToFile(
            derPub,
            kp.pubDer);

        saveToFile(
            derPriv,
            kp.privDer);

        std::string metaPath =
            privPath.substr(
                0,
                privPath.rfind('.'))
            + "_meta.json";

        saveToFile(
            metaPath,
            kp.metadataJson);

        std::cout
            << "[+] Public PEM  : "
            << pubPath
            << "\n";

        std::cout
            << "[+] Private PEM : "
            << privPath
            << "\n";

        std::cout
            << "[+] Public DER  : "
            << derPub
            << "\n";

        std::cout
            << "[+] Private DER : "
            << derPriv
            << "\n";

        std::cout
            << "[+] Metadata    : "
            << metaPath
            << "\n";

        if (verbose)
        {
            std::cout
                << "\n"
                << kp.metadataJson
                << "\n";
        }

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "[ERROR] "
            << e.what()
            << "\n";

        return 1;
    }
}

static int cmdEncrypt(
    const std::vector<std::string>& args)
{
    try
    {
        std::string inFile =
            getArg(args,
                   "--in");

        std::string outFile =
            getArg(args,
                   "--out",
                   "cipher.bin");

        std::string pubFile =
            getArg(args,
                   "--pub");

        if (inFile.empty() ||
            pubFile.empty())
        {
            throw std::runtime_error(
                "--in and --pub are required");
        }

        auto plaintext =
            readBinary(inFile);

        std::string label =
            getArg(args, "--label", "");

        if (plaintext.size() <= 318)
        {
            auto ciphertext =
                rsaEncryptOAEP(
                    plaintext,
                    pubFile,
                    label);

            writeBinary(
                outFile,
                ciphertext);

            std::cout
                << "[+] RSA-OAEP encryption\n";
        }
        else
        {
            hybridEncrypt(
                inFile,
                pubFile,
                "envelope.json",
                outFile);

            std::cout
                << "[+] Hybrid AES-256-GCM encryption\n";
        }

        std::cout
            << "[+] Encryption OK\n";

        std::cout
            << "[+] Output: "
            << outFile
            << "\n";

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "[ERROR] "
            << e.what()
            << "\n";

        return 1;
    }
}

static int cmdDecrypt(
    const std::vector<std::string>& args)
{
    try
    {
        std::string inFile =
            getArg(args,
                   "--in");

        std::string outFile =
            getArg(args,
                   "--out",
                   "recovered.txt");

        std::string privFile =
            getArg(args,
                   "--priv");

        if (inFile.empty() ||
            privFile.empty())
        {
            throw std::runtime_error(
                "--in and --priv are required");
        }

        auto ciphertext =
            readBinary(inFile);

        std::string label =
            getArg(args, "--label", "");

        try
        {
            auto plaintext =
                rsaDecryptOAEP(
                    ciphertext,
                    privFile,
                    label);

            writeBinary(
                outFile,
                plaintext);

            std::cout
                << "[+] RSA-OAEP decryption\n";
        }
        catch (...)
        {
            hybridDecrypt(
                "envelope.json",
                inFile,
                privFile,
                outFile);

            std::cout
                << "[+] Hybrid AES-256-GCM decryption\n";
        }

        std::cout
            << "[+] Decryption OK\n";

        std::cout
            << "[+] Output: "
            << outFile
            << "\n";

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "[ERROR] "
            << e.what()
            << "\n";

        return 1;
    }
}

int main(
    int argc,
    char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return 0;
    }

    std::vector<std::string> args(
        argv + 1,
        argv + argc);

    std::string cmd =
        args[0];

    if (cmd == "keygen")
        return cmdKeygen(args);

    if (cmd == "encrypt")
        return cmdEncrypt(args);

    if (cmd == "decrypt")
        return cmdDecrypt(args);
    
    if (cmd == "bench")
    {
        runBenchmarks();
        return 0;
    }

    if (cmd == "--help" ||
        cmd == "-h")
    {
        printUsage();
        return 0;
    }

    std::cerr
        << "[ERROR] Unknown command: "
        << cmd
        << "\n";

    return 1;
}