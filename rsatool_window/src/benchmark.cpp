#include "benchmark.h"
#include "rsa_oaep.h"
#include "hybrid.h"

#include <chrono>
#include <iostream>
#include <vector>
#include <fstream>
#include <functional>

static std::vector<unsigned char> makeData(
    size_t size)
{
    return std::vector<unsigned char>(
        size,
        'A');
}

static void writeFile(
    const std::string& path,
    const std::vector<unsigned char>& data)
{
    std::ofstream out(
        path,
        std::ios::binary);

    out.write(
        reinterpret_cast<const char*>(data.data()),
        data.size());
}

static double measureMs(
    const std::function<void()>& fn)
{
    auto start =
        std::chrono::high_resolution_clock::now();

    fn();

    auto end =
        std::chrono::high_resolution_clock::now();

    return std::chrono::duration<double, std::milli>(
               end - start)
        .count();
}

void runBenchmarks()
{
    std::cout
        << "\n========== BENCHMARK ==========\n";

    auto small =
        makeData(100);

    auto large =
        makeData(1024 * 1024);

    writeFile(
        "bench_large.bin",
        large);

    double rsa3072Enc =
        measureMs([&]()
                  {
                      rsaEncryptOAEP(
                          small,
                          "pub.pem");
                  });

    auto cipher3072 =
        rsaEncryptOAEP(
            small,
            "pub.pem");

    double rsa3072Dec =
        measureMs([&]()
                  {
                      rsaDecryptOAEP(
                          cipher3072,
                          "priv.pem");
                  });

    std::cout
        << "\n[ RSA-3072 ]\n";

    std::cout
        << "Encrypt : "
        << rsa3072Enc
        << " ms\n";

    std::cout
        << "Decrypt : "
        << rsa3072Dec
        << " ms\n";

    double hybridEnc =
        measureMs([&]()
                  {
                      hybridEncrypt(
                          "bench_large.bin",
                          "pub.pem",
                          "bench_env.json",
                          "bench_cipher.bin");
                  });

    double hybridDec =
        measureMs([&]()
                  {
                      hybridDecrypt(
                          "bench_env.json",
                          "bench_cipher.bin",
                          "priv.pem",
                          "bench_out.bin");
                  });

    std::cout
        << "\n[ HYBRID AES-256-GCM + RSA ]\n";

    std::cout
        << "Encrypt 1MB : "
        << hybridEnc
        << " ms\n";

    std::cout
        << "Decrypt 1MB : "
        << hybridDec
        << " ms\n";

    std::cout
        << "\n===============================\n";
}