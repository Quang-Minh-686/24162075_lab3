#pragma once

#ifdef _WIN32
  #ifdef RSALIB_EXPORTS
    #define RSALIB_API __declspec(dllexport)
  #else
    #define RSALIB_API __declspec(dllimport)
  #endif
#else
  #define RSALIB_API
#endif

RSALIB_API void runBenchmarks();