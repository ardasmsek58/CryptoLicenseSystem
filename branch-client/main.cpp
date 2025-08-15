#include <QApplication>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include "hardwarelock.h"

/**
 * @brief Starts the main licensed application interface.
 *
 * Displays a simple window with a counter that can be incremented via a button.
 * This function is only called if the license verification process is successful.
 */
void startMainApplication() {
    QWidget *window = new QWidget;
    window->setWindowTitle("CryptoBranch | Licensed Application");

    QVBoxLayout *layout = new QVBoxLayout(window);

    QLabel *label = new QLabel("License is valid. Welcome!");
    label->setAlignment(Qt::AlignCenter);
    label->setStyleSheet("QLabel { color: green; font-weight: bold; font-size: 14px; }");

    QPushButton *button = new QPushButton("Increment Counter");
    QLabel *counterLabel = new QLabel("Counter: 0");
    counterLabel->setAlignment(Qt::AlignCenter);

    int *counter = new int(0);  // Counter variable

    QObject::connect(button, &QPushButton::clicked, [=]() mutable {
        (*counter)++;
        counterLabel->setText("Counter: " + QString::number(*counter));
    });

    layout->addWidget(label);
    layout->addWidget(button);
    layout->addWidget(counterLabel);

    window->setLayout(layout);
    window->resize(400, 200);
    window->show();
}

/**
 * @brief Application entry point.
 *
 * This function:
 * - Retrieves the local hardware fingerprint
 * - Checks for the presence of a license file
 * - If license is missing, creates `hardware_id.txt` for license request
 * - Reads and validates the license file
 * - Compares hardware fingerprints
 * - Verifies digital signature using the public key
 * - Launches the main application if verification passes
 *
 * @param argc Argument count
 * @param argv Argument values
 * @return int Application exit code
 */
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Debug file existence check
    qDebug() << "Hardware ID file exists:" << QFile::exists("hardware_id.txt");
    qDebug() << "Public key file exists:" << QFile::exists("public_key.pem");
    qDebug() << "License file exists:" << QFile::exists("license.lic");

    // Get the current machine's hardware fingerprint
    QString localFingerprint = QString::fromStdString(HardwareLock::getHardwareFingerprint());
    qDebug() << "Local Hardware Fingerprint:" << localFingerprint;

    // License file check
    QFile licenseFile("license.lic");
    if (!licenseFile.exists()) {
        // Create hardware ID file for license request
        QFile out("hardware_id.txt");
        if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QTextStream stream(&out);
            stream << localFingerprint << "\n";
            out.close();
            qDebug() << "Hardware ID file created:" << localFingerprint;
        }

        QMessageBox::information(nullptr, "License Required",
                                 QString("license.lic file not found.\n\n"
                                         "hardware_id.txt file has been created.\n"
                                         "Send this file to technical support to request a license.\n\n"
                                         "Hardware Fingerprint:\n%1").arg(localFingerprint));
        return 1;
    }

    // Read license file
    QFile file("license.lic");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(nullptr, "Error", "Could not open license file.");
        return 1;
    }

    QByteArray jsonData = file.readAll();
    file.close();

    // Parse JSON
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        QMessageBox::critical(nullptr, "Invalid License",
                              QString("License file is not valid JSON.\nError: %1").arg(parseError.errorString()));
        return 1;
    }

    QJsonObject obj = doc.object();
    QString licenseFingerprint = obj["hardwareFingerprint"].toString();
    QString signature = obj["signature"].toString();

    // Backward compatibility with older "hardwareId" field
    if (licenseFingerprint.isEmpty()) {
        licenseFingerprint = obj["hardwareId"].toString();
    }

    qDebug() << "License Hardware Fingerprint:" << licenseFingerprint;
    qDebug() << "Signature length:" << signature.length();

    // Missing value check
    if (licenseFingerprint.isEmpty() || signature.isEmpty()) {
        QMessageBox::critical(nullptr, "Invalid License",
                              "License file is missing hardwareFingerprint or signature.\n\n"
                              "Required fields:\n"
                              "- hardwareFingerprint\n"
                              "- signature");
        return 1;
    }

    // Hardware fingerprint match check
    if (localFingerprint != licenseFingerprint) {
        QMessageBox::critical(nullptr, "Hardware Fingerprint Mismatch",
                              QString("This license is not valid for this machine.\n\n"
                                      "Local Hardware Fingerprint:\n%1\n\n"
                                      "License Hardware Fingerprint:\n%2\n\n"
                                      "Please use the correct license file or request a new license.")
                                  .arg(localFingerprint, licenseFingerprint));
        return 1;
    }

    qDebug() << "Hardware fingerprint matched, verifying signature...";

    // Public key existence check
    if (!QFile::exists("public_key.pem")) {
        QMessageBox::critical(nullptr, "Error", "public_key.pem file not found.");
        return 1;
    }

    // Signature verification
    if (HardwareLock::verifyLicense(localFingerprint.toStdString(), signature.toStdString(), "public_key.pem")) {
        qDebug() << "License verification successful!";
        startMainApplication();
        return app.exec();
    } else {
        qDebug() << "Signature verification failed!";
        QMessageBox::critical(nullptr, "Invalid License",
                              "Signature could not be verified.\n\n"
                              "Possible reasons:\n"
                              "- Corrupted license file\n"
                              "- Incorrect public key\n"
                              "- License not valid for this machine\n"
                              "- License expired\n\n"
                              "Please use a valid license file.");
        return 1;
    }
}
