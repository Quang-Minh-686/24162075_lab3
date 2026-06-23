cmake_minimum_required(VERSION 3.20)
project(
    rsatool
    VERSION 1.0.0
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Static linking MinGW runtime (fix lỗi 0xc0000139) ---
if(MINGW)
    add_link_options(-static-libgcc -static-libstdc++ -static -lpthread)
endif()

# --- OpenSSL từ MSYS2 (UCRT64 hoặc MinGW64, tự dò) ---
if(NOT DEFINED OPENSSL_ROOT_DIR)
    if(EXISTS "C:/msys64/ucrt64/include/openssl/rsa.h")
        set(OPENSSL_ROOT_DIR "C:/msys64/ucrt64")
    elseif(EXISTS "C:/msys64/mingw64/include/openssl/rsa.h")
        set(OPENSSL_ROOT_DIR "C:/msys64/mingw64")
    endif()
endif()
find_package(OpenSSL REQUIRED)
message(STATUS "[rsatool] OpenSSL root    : ${OPENSSL_ROOT_DIR}")
message(STATUS "[rsatool] OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "[rsatool] OpenSSL libs    : ${OPENSSL_LIBRARIES}")

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY
        https://github.com/catchorg/Catch2.git
    GIT_TAG
        v3.5.4
)
FetchContent_MakeAvailable(Catch2)

set(LIB_SOURCES
    src/keygen.cpp
    src/rsa_oaep.cpp
    src/hybrid.cpp
    src/encoding.cpp
    src/benchmark.cpp
    src/exports.cpp
)
set(LIB_HEADERS
    src/keygen.h
    src/rsa_oaep.h
    src/hybrid.h
    src/encoding.h
    src/benchmark.h
    src/exports.h
)

add_library(
    rsalib
    SHARED
    ${LIB_SOURCES}
    ${LIB_HEADERS}
)
target_compile_definitions(rsalib PRIVATE
    RSALIB_EXPORTS
)
set_target_properties(rsalib PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)
target_include_directories(rsalib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(rsalib PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL
)
if(WIN32)
    target_link_libraries(rsalib PUBLIC
        ws2_32
        crypt32
    )
endif()

add_executable(
    rsatool
    src/main.cpp
)
target_link_libraries(
    rsatool
    PRIVATE
    rsalib
)

# --- Copy OpenSSL DLLs (Chỉ chạy trên Windows) ---
if(WIN32)
    file(GLOB OPENSSL_RUNTIME_DLLS
        "${OPENSSL_ROOT_DIR}/bin/libcrypto-*.dll"
        "${OPENSSL_ROOT_DIR}/bin/libssl-*.dll"
    )

    add_custom_command(TARGET rsatool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OPENSSL_RUNTIME_DLLS}
            $<TARGET_FILE_DIR:rsatool>
    )
    add_custom_command(TARGET rsalib POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OPENSSL_RUNTIME_DLLS}
            $<TARGET_FILE_DIR:rsalib>
    )
endif()

# --- Test executable ---
enable_testing()
add_executable(
    rsatool_tests
    src/tests/test_main.cpp
    src/tests/test_rsa.cpp
)
target_link_libraries(
    rsatool_tests
    PRIVATE
    rsalib
    Catch2::Catch2WithMain
)

if(WIN32)
    add_custom_command(TARGET rsatool_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OPENSSL_RUNTIME_DLLS}
            $<TARGET_FILE_DIR:rsatool_tests>
        COMMENT "Copying OpenSSL DLLs for tests"
    )

    add_custom_command(TARGET rsatool_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:rsalib>
            $<TARGET_FILE_DIR:rsatool_tests>
        COMMENT "Copying rsalib.dll for tests"
    )
else()
    # Trên Linux, sinh lệnh copy file thư viện .so để test tìm thấy
    add_custom_command(TARGET rsatool_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:rsalib>
            $<TARGET_FILE_DIR:rsatool_tests>
        COMMENT "Copying librsalib.so for tests"
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(rsatool_tests
    WORKING_DIRECTORY $<TARGET_FILE_DIR:rsatool_tests>
)

if(MSVC)
    target_compile_options(rsalib PRIVATE
        /W4
        /WX
        /permissive-
    )
    target_compile_options(rsatool PRIVATE
        /W4
        /WX
        /permissive-
    )
else()
    # Đã LOẠI BỎ cờ -Werror để tránh dừng build khi gặp Warning trên Linux
    target_compile_options(rsalib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
    target_compile_options(rsatool PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
endif()

message(STATUS "")
message(STATUS "==========================================")
message(STATUS " rsatool build configuration")
message(STATUS "==========================================")
message(STATUS " Generator   : ${CMAKE_GENERATOR}")
message(STATUS " Compiler    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS " Version     : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS " OpenSSL     : ${OPENSSL_VERSION}")
message(STATUS "==========================================")
message(STATUS "")
