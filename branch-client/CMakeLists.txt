# Minimum required CMake version
cmake_minimum_required(VERSION 3.14)

# Project name and language
project(CryptoBranch LANGUAGES CXX)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === OpenSSL Paths ===
# These paths should be updated according to your OpenSSL installation location.
# Example below is for MSYS2 on Windows.
set(OPENSSL_INCLUDE_DIR "C:/msys64/mingw64/include")
set(OPENSSL_CRYPTO_LIBRARY "C:/msys64/mingw64/lib/libcrypto.a")
set(OPENSSL_SSL_LIBRARY "C:/msys64/mingw64/lib/libssl.a")

# === Qt Modules ===
# Look for Qt6 first, fallback to Qt5 if not found.
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network Widgets)

# === Additional Include Directories ===
# Add path for JSON header file (e.g., json.hpp) if it exists in "include" folder.
include_directories(${CMAKE_SOURCE_DIR}/include)

# === Source Files ===
# List of all source and header files for the application.
add_executable(CryptoBranch
    main.cpp
    hardwarelock.cpp
    hardwarelock.h
)

# === Linking Libraries ===
# Include OpenSSL headers
target_include_directories(CryptoBranch PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link against Qt and OpenSSL libraries, plus Windows-specific libraries.
target_link_libraries(CryptoBranch
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Widgets
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    crypt32    # Windows crypto API
    ws2_32     # Windows sockets API
)
