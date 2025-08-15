#ifndef LICENSEGENERATOR_H
#define LICENSEGENERATOR_H

#include <string>

/**
 * @brief The LicenseGenerator class
 *
 * Provides functionality to generate a license file for a specific hardware ID.
 * The license file includes the hardware ID and a digital signature generated using
 * the provided RSA private key. The output is saved in JSON format.
 */
class LicenseGenerator
{
public:
    /**
     * @brief Generates a license file for the given hardware ID.
     *
     * This function creates a JSON license file containing:
     * - The hardware ID of the target machine
     * - A digital signature (SHA256 with RSA) of the hardware ID
     *
     * @param hardwareId The hardware fingerprint or ID to license.
     * @param privateKeyPath Path to the RSA private key file (`private_key.pem`) used for signing.
     * @param outputFile Path to save the generated license file (`license.lic`).
     * @return true if license generation is successful, false otherwise.
     */
    static bool generateLicense(const std::string &hardwareId,
                                const std::string &privateKeyPath,
                                const std::string &outputFile);
};

#endif // LICENSEGENERATOR_H
