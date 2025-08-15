#include "licensegenerator.h"
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <json.hpp>

using json = nlohmann::json;

/**
 * @brief Generates a license file for a given hardware ID using RSA private key signing.
 *
 * The function:
 * 1. Creates a JSON object containing the hardware ID
 * 2. Signs the hardware ID using SHA256 with RSA private key
 * 3. Saves the license as a `.lic` file containing both hardware ID and signature
 *
 * @param hardwareId The hardware fingerprint or ID for the target machine.
 * @param privateKeyPath Path to the RSA private key (`private_key.pem`) used for signing.
 * @param outputFile Path to save the generated license file (`license.lic`).
 * @return true if license generation succeeds, false otherwise.
 */
bool LicenseGenerator::generateLicense(const std::string &hardwareId, const std::string &privateKeyPath, const std::string &outputFile)
{
    // Create JSON object
    json licenseJson;
    licenseJson["hardwareId"] = hardwareId;

    // Data to sign
    std::string dataToSign = hardwareId;

    // Open private key file
    FILE* privKeyFile = fopen(privateKeyPath.c_str(), "r");
    if (!privKeyFile) {
        std::cerr << "❌ Could not open private_key.pem.\n";
        return false;
    }

    // Read private key
    EVP_PKEY* privateKey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);
    if (!privateKey) {
        std::cerr << "❌ Could not read private_key.pem.\n";
        return false;
    }

    // Initialize signing context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, dataToSign.c_str(), dataToSign.length());

    unsigned char sig[256];
    unsigned int sigLen = 0;

    // Sign data
    if (!EVP_SignFinal(ctx, sig, &sigLen, privateKey)) {
        std::cerr << "❌ Signing failed.\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Clean up
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    // Convert signature to HEX string
    std::ostringstream oss;
    for (unsigned int i = 0; i < sigLen; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)sig[i];
    }
    licenseJson["signature"] = oss.str();

    // Save as JSON license file
    std::ofstream out(outputFile);
    out << licenseJson.dump(4); // pretty-print with indentation
    out.close();

    std::cout << "✅ License successfully generated: " << outputFile << "\n";
    return true;
}
