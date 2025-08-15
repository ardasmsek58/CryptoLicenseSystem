#include "hardwarelock.h"
#include <QNetworkInterface>
#include <QCryptographicHash>
#include <QProcess>
#include <QStandardPaths>
#include <sstream>
#include <iomanip>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#elif defined(__linux__)
#include <fstream>
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

/**
 * @brief Retrieves the MAC address of the primary active network interface.
 *
 * Iterates through all available network interfaces, skipping loopback and empty addresses.
 *
 * @return MAC address string in the format "XX:XX:XX:XX:XX:XX".
 */
std::string HardwareLock::getMacAddress() {
    foreach (const QNetworkInterface &netInterface, QNetworkInterface::allInterfaces()) {
        qDebug() << "Interface Name:" << netInterface.humanReadableName();
        qDebug() << "Hardware Address:" << netInterface.hardwareAddress();
        qDebug() << "Type:" << netInterface.type();
        qDebug() << "IsUp:" << netInterface.flags().testFlag(QNetworkInterface::IsUp);
        qDebug() << "IsRunning:" << netInterface.flags().testFlag(QNetworkInterface::IsRunning);
        qDebug() << "------";

        if (!(netInterface.flags() & QNetworkInterface::IsLoopBack) &&
            netInterface.hardwareAddress() != "00:00:00:00:00:00" &&
            !netInterface.hardwareAddress().isEmpty()) {
            return netInterface.hardwareAddress().toStdString();
        }
    }
    return "00:00:00:00:00:00";
}

/**
 * @brief Executes a shell/system command and returns its output.
 *
 * @param command Command string to execute.
 * @return Command output as std::string.
 */
std::string HardwareLock::executeCommand(const std::string &command) {
    QProcess process;
    process.start(QString::fromStdString(command));
    process.waitForFinished(5000); // 5 seconds timeout

    if (process.exitCode() == 0) {
        QByteArray output = process.readAllStandardOutput();
        return output.trimmed().toStdString();
    }

    return "";
}

/**
 * @brief Retrieves the serial number of the main system disk.
 *
 * Uses platform-specific commands to obtain the disk serial number:
 * - Windows: `wmic` or `vol C:`
 * - Linux: `lsblk`, `udevadm`, or `/sys/block/...`
 * - macOS: `system_profiler` or `diskutil`
 *
 * @return Disk serial number or "UNKNOWN_DISK" if not found.
 */
std::string HardwareLock::getDiskSerialNumber() {
    std::string serialNumber;

#ifdef _WIN32
    // Try using WMIC
    std::string output = executeCommand("wmic diskdrive get serialnumber");
    if (!output.empty()) {
        std::istringstream iss(output);
        std::string line;
        std::getline(iss, line); // Skip header
        while (std::getline(iss, line)) {
            if (!line.empty()) {
                serialNumber = line;
                break;
            }
        }
    }
    // Fallback: "vol C:"
    if (serialNumber.empty()) {
        output = executeCommand("vol C:");
        size_t pos = output.find("Volume Serial Number is ");
        if (pos != std::string::npos) {
            pos += 24;
            serialNumber = output.substr(pos, 9);
        }
    }

#elif defined(__linux__)
    serialNumber = executeCommand("lsblk -d -n -o serial | head -1");
    if (serialNumber.empty()) {
        serialNumber = executeCommand("udevadm info --query=property --name=sda | grep ID_SERIAL= | cut -d'=' -f2");
    }
    if (serialNumber.empty()) {
        std::ifstream file("/sys/block/sda/device/serial");
        if (file.is_open()) {
            std::getline(file, serialNumber);
            file.close();
        }
    }

#elif defined(__APPLE__)
    serialNumber = executeCommand("system_profiler SPSerialATADataType | grep 'Serial Number' | head -1 | awk '{print $3}'");
    if (serialNumber.empty()) {
        serialNumber = executeCommand("diskutil info disk0 | grep 'Device / Media UUID' | awk '{print $5}'");
    }
#endif

    // Clean spaces and special characters
    serialNumber.erase(std::remove_if(serialNumber.begin(), serialNumber.end(),
                                      [](char c) { return std::isspace(c) || c == '\r' || c == '\n'; }), serialNumber.end());

    return serialNumber.empty() ? "UNKNOWN_DISK" : serialNumber;
}

/**
 * @brief Retrieves the CPU identifier.
 *
 * Uses platform-specific methods:
 * - Windows: CPUID instruction
 * - Linux: /proc/cpuinfo
 * - macOS: sysctl or system_profiler
 *
 * @return CPU identifier string or "UNKNOWN_CPU" if not found.
 */
std::string HardwareLock::getCpuId() {
    std::string cpuId;

#ifdef _WIN32
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    *reinterpret_cast<int*>(vendor) = cpuInfo[1];
    *reinterpret_cast<int*>(vendor + 4) = cpuInfo[3];
    *reinterpret_cast<int*>(vendor + 8) = cpuInfo[2];
    __cpuid(cpuInfo, 1);
    std::ostringstream oss;
    oss << vendor << "_" << std::hex << cpuInfo[0];
    cpuId = oss.str();

#elif defined(__linux__)
    std::ifstream file("/proc/cpuinfo");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("processor") == 0) {
                size_t pos = line.find(":");
                if (pos != std::string::npos) {
                    cpuId = line.substr(pos + 1);
                    break;
                }
            }
        }
        file.close();
    }
    if (cpuId.empty()) {
        cpuId = executeCommand("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2");
    }

#elif defined(__APPLE__)
    cpuId = executeCommand("sysctl -n machdep.cpu.brand_string");
    if (cpuId.empty()) {
        cpuId = executeCommand("system_profiler SPHardwareDataType | grep 'Processor Name' | cut -d':' -f2");
    }
#endif

    cpuId.erase(std::remove_if(cpuId.begin(), cpuId.end(),
                               [](char c) { return std::isspace(c) || c == '\r' || c == '\n'; }), cpuId.end());

    return cpuId.empty() ? "UNKNOWN_CPU" : cpuId;
}

/**
 * @brief Generates a SHA256 hardware fingerprint based on MAC, disk serial, and CPU ID.
 *
 * @return Hexadecimal string of the SHA256 hash.
 */
std::string HardwareLock::getHardwareFingerprint() {
    std::string mac = getMacAddress();
    std::string disk = getDiskSerialNumber();
    std::string cpu = getCpuId();

    qDebug() << "MAC Address:" << QString::fromStdString(mac);
    qDebug() << "Disk Serial:" << QString::fromStdString(disk);
    qDebug() << "CPU ID:" << QString::fromStdString(cpu);

    std::string combined = mac + "|" + disk + "|" + cpu;

    QByteArray hash = QCryptographicHash::hash(QByteArray::fromStdString(combined), QCryptographicHash::Sha256);
    std::ostringstream oss;
    for (unsigned char byte : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;

    return oss.str();
}

/**
 * @brief Verifies a license using the provided hardware hash, digital signature, and public key.
 *
 * Supports both HEX and Base64-encoded signatures.
 *
 * @param hash Hardware fingerprint hash.
 * @param signatureBase64 Digital signature (HEX or Base64 encoded).
 * @param publicKeyPath Path to the public key file.
 * @return true if license is valid, false otherwise.
 */
bool HardwareLock::verifyLicense(const std::string &hash, const std::string &signatureBase64, const std::string &publicKeyPath) {
    qDebug() << "=== Signature Verification Started ===";
    qDebug() << "Hash length:" << hash.length();
    qDebug() << "Signature length:" << signatureBase64.length();
    qDebug() << "Public key file:" << QString::fromStdString(publicKeyPath);

    bool isHex = true;
    for (char c : signatureBase64) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            isHex = false;
            break;
        }
    }

    qDebug() << "Signature format:" << (isHex ? "HEX" : "BASE64");

    std::vector<unsigned char> signature;
    if (isHex && signatureBase64.length() == 512) {
        signature.resize(256);
        for (size_t i = 0; i < signatureBase64.length(); i += 2) {
            std::string byteString = signatureBase64.substr(i, 2);
            signature[i / 2] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        }
    } else {
        BIO *bio = nullptr;
        BIO *b64 = nullptr;
        try {
            b64 = BIO_new(BIO_f_base64());
            if (!b64) return false;

            bio = BIO_new_mem_buf(signatureBase64.c_str(), signatureBase64.length());
            if (!bio) {
                BIO_free(b64);
                return false;
            }
            bio = BIO_push(b64, bio);
            BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

            std::vector<unsigned char> tempSignature(signatureBase64.length());
            int actualLen = BIO_read(bio, tempSignature.data(), tempSignature.size());
            if (actualLen <= 0) {
                BIO_free_all(bio);
                return false;
            }
            signature.resize(actualLen);
            std::copy(tempSignature.begin(), tempSignature.begin() + actualLen, signature.begin());
            BIO_free_all(bio);
        } catch (...) {
            if (bio) BIO_free_all(bio);
            return false;
        }
    }

    FILE *pubKeyFile = fopen(publicKeyPath.c_str(), "r");
    if (!pubKeyFile) return false;

    EVP_PKEY *pubKey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);
    if (!pubKey) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubKey);
        return false;
    }

    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_VerifyUpdate(ctx, hash.c_str(), hash.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    int result = EVP_VerifyFinal(ctx, signature.data(), signature.size(), pubKey);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubKey);

    return (result == 1);
}
