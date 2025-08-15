# Minimum CMake version required
cmake_minimum_required(VERSION 3.14)

# Project name and language
project(CryptoProject LANGUAGES CXX)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === OpenSSL Paths ===
# Manually set OpenSSL include and library paths (adjust according to your system)
# Example below is for MSYS2 on Windows
set(OPENSSL_INCLUDE_DIR "C:/msys64/mingw64/include")
set(OPENSSL_CRYPTO_LIBRARY "C:/msys64/mingw64/lib/libcrypto.a")
set(OPENSSL_SSL_LIBRARY "C:/msys64/mingw64/lib/libssl.a")

# === Additional Include Directories ===
# Path to the folder containing json.hpp
include_directories(${CMAKE_SOURCE_DIR}/include)  # json.hpp should be placed here

# === Qt Modules ===
# Search for Qt6 first, fallback to Qt5 if not found
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network Widgets)

# === Application Source Files ===
add_executable(CryptoProject
    main.cpp
    licensegenerator.cpp
    licensegenerator.h
)

# === Include Paths for Targets ===
target_include_directories(CryptoProject PRIVATE ${OPENSSL_INCLUDE_DIR})

# === Link Libraries ===
target_link_libraries(CryptoProject
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Widgets
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    crypt32    # Windows Crypto API
    ws2_32     # Windows Sockets API
)
