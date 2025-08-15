#include "licensegenerator.h"
#include <fstream>
#include <iostream>

/**
 * @brief Application entry point for license generation.
 *
 * This program:
 * 1. Reads the hardware ID from `hardware_id.txt`
 * 2. Generates a license file (`license.lic`) by signing the hardware ID
 *    using a provided RSA private key (`private_key.pem`)
 *
 * Expected files in the same directory:
 * - hardware_id.txt : Contains the target machine's hardware fingerprint
 * - private_key.pem : RSA private key for signing
 *
 * Output:
 * - license.lic : Generated JSON license file containing hardware ID and signature
 *
 * @return int Application exit code (0 for success, 1 for error)
 */
int main() {
    // Open hardware ID file
    std::ifstream file("hardware_id.txt");
    if (!file.is_open()) {
        std::cerr << "❌ hardware_id.txt not found.\n";
        return 1;
    }

    // Read hardware ID
    std::string hardwareId;
    std::getline(file, hardwareId);
    file.close();

    // Generate license
    if (!LicenseGenerator::generateLicense(hardwareId, "private_key.pem", "license.lic")) {
        return 1;
    }

    return 0;
}
