#ifndef HARDWARELOCK_H
#define HARDWARELOCK_H

#include <QString>
#include <string>
#include <QDebug>

class HardwareLock {
public:
    /**
     * @brief Retrieves the MAC address of the primary network adapter.
     * @return MAC address as a string.
     */
    static std::string getMacAddress();

    /**
     * @brief Retrieves the serial number of the main disk.
     * @return Disk serial number as a string.
     */
    static std::string getDiskSerialNumber();

    /**
     * @brief Retrieves the CPU ID of the system.
     * @return CPU ID as a string.
     */
    static std::string getCpuId();

    /**
     * @brief Generates a unique hardware fingerprint based on multiple identifiers.
     * @return A combined unique hardware identifier string.
     */
    static std::string getHardwareFingerprint();

    /**
     * @brief Verifies the license by checking the hash and digital signature using the given public key.
     * @param hash The hardware fingerprint hash.
     * @param signatureBase64 The license signature encoded in Base64.
     * @param publicKeyPath Path to the public key file.
     * @return True if the license is valid, false otherwise.
     */
    static bool verifyLicense(const std::string &hash, const std::string &signatureBase64, const std::string &publicKeyPath);

private:
    /**
     * @brief Executes a system command and returns its output as a string.
     * @param command The system command to execute.
     * @return Output of the command as a string.
     */
    static std::string executeCommand(const std::string &command);
};

#endif // HARDWARELOCK_H
