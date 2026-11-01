#include "license.hpp"
#include "config_manager.hpp"
#include "common.hpp"
#include <windows.h>
#include <sstream>
#include <iostream>

namespace XIII {

    LicenseManager& LicenseManager::Instance() {
        static LicenseManager instance;
        return instance;
    }

    LicenseManager::LicenseManager() {}

    void LicenseManager::Initialize() {
        // Ensure machine ID is computed and check existing license
        std::string currentKey = ConfigManager::Instance().GetLicenseKey();
        if (currentKey.empty()) {
            // First time setup: Generate and configure a valid machine-bound evaluation Enterprise license
            std::string autoKey = GenerateEvaluationKey(LicenseTier::Enterprise, "Authorized Local Analyst");
            ConfigManager::Instance().SetLicenseKey(autoKey);
        }
    }

    std::string LicenseManager::ComputeMachineHash() {
        // Read MachineGuid from registry
        char guidBuffer[256] = {0};
        DWORD bufferSize = sizeof(guidBuffer);
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)guidBuffer, &bufferSize);
            RegCloseKey(hKey);
        }

        std::string rawId = guidBuffer;
        if (rawId.empty()) {
            // Fallback to computer name
            char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
            DWORD compSize = sizeof(compName);
            GetComputerNameA(compName, &compSize);
            rawId = compName;
        }

        std::string hash = Utils::CalculateSHA256("XIII_HWID_" + rawId);
        return hash.substr(0, 16);
    }

    std::string LicenseManager::GetHardwareId() {
        return ComputeMachineHash();
    }

    std::string LicenseManager::CalculateKeySignature(const std::string& prefix, const std::string& machineId, const std::string& expDate) {
        std::string seed = "XIII_SEC_TRAVMA_FINDHOST_" + prefix + "_" + machineId + "_" + expDate;
        std::string hash = Utils::CalculateSHA256(seed);
        return Utils::ToUpper(hash.substr(0, 12));
    }

    std::string LicenseManager::GenerateEvaluationKey(LicenseTier tier, const std::string& /*user*/) {
        std::string hwid = GetHardwareId();
        std::string tierStr = "ENT";
        if (tier == LicenseTier::Professional) tierStr = "PRO";
        else if (tier == LicenseTier::Community) tierStr = "COM";

        std::string expDate = "20291231";
        std::string sig = CalculateKeySignature(tierStr, hwid, expDate);

        // Format: XIII-ENT-20291231-SIG1-SIG2
        std::ostringstream ss;
        ss << "XIII-" << tierStr << "-" << expDate.substr(0, 4) << "-" << sig.substr(0, 4) << "-" << sig.substr(4, 4) << "-" << sig.substr(8, 4);
        return ss.str();
    }

    LicenseInfo LicenseManager::ValidateKey(const std::string& key) {
        LicenseInfo info;
        info.licenseKey = key;
        info.hardwareId = GetHardwareId();

        // Basic format check: XIII-TIER-YYYY-XXXX-XXXX-XXXX
        if (key.length() < 24 || key.rfind("XIII-", 0) != 0) {
            info.isValid = false;
            info.statusMessage = "Invalid license key structure.";
            return info;
        }

        std::string sub = key.substr(5);
        size_t dash1 = sub.find('-');
        if (dash1 == std::string::npos) {
            info.isValid = false;
            info.statusMessage = "Malformed license tier segment.";
            return info;
        }

        std::string tierCode = sub.substr(0, dash1);
        if (tierCode == "ENT") info.tier = LicenseTier::Enterprise;
        else if (tierCode == "PRO") info.tier = LicenseTier::Professional;
        else if (tierCode == "COM") info.tier = LicenseTier::Community;
        else {
            info.isValid = false;
            info.statusMessage = "Unrecognized tier code.";
            return info;
        }

        std::string expYear = sub.substr(dash1 + 1, 4);
        std::string sigPart = key.substr(key.length() - 14); // XXXX-XXXX-XXXX
        std::string cleanSig;
        for (char c : sigPart) {
            if (c != '-') cleanSig += c;
        }

        std::string expectedExp = expYear + "1231";
        std::string expectedSig = CalculateKeySignature(tierCode, info.hardwareId, expectedExp);

        if (cleanSig == expectedSig) {
            info.isValid = true;
            info.licensedTo = "Authorized Security Operator";
            info.organization = "Findhost $ Travma Labs";
            info.expirationDate = expYear + "-12-31";
            info.statusMessage = "License authorized and bound to host.";
        } else {
            // Check universal developer key signature
            std::string universalSig = CalculateKeySignature(tierCode, "UNIVERSAL", expectedExp);
            if (cleanSig == universalSig) {
                info.isValid = true;
                info.licensedTo = "Universal Master Analyst";
                info.organization = "Findhost $ Travma Labs";
                info.expirationDate = expYear + "-12-31";
                info.statusMessage = "Master enterprise license active.";
            } else {
                info.isValid = false;
                info.statusMessage = "Cryptographic signature mismatch for this host.";
            }
        }

        return info;
    }

    LicenseInfo LicenseManager::ValidateCurrentLicense() {
        std::string key = ConfigManager::Instance().GetLicenseKey();
        if (key.empty()) {
            Initialize();
            key = ConfigManager::Instance().GetLicenseKey();
        }
        return ValidateKey(key);
    }

    void LicenseManager::InstallLicense(const std::string& key) {
        ConfigManager::Instance().SetLicenseKey(key);
    }

} // namespace XIII
