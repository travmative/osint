#pragma once

#include <string>

namespace XIII {

    enum class LicenseTier {
        Invalid,
        Community,
        Professional,
        Enterprise
    };

    struct LicenseInfo {
        bool isValid{false};
        LicenseTier tier{LicenseTier::Invalid};
        std::string licenseKey;
        std::string licensedTo;
        std::string organization;
        std::string expirationDate;
        std::string hardwareId;
        std::string statusMessage;
    };

    class LicenseManager {
    public:
        static LicenseManager& Instance();

        void Initialize();
        LicenseInfo ValidateCurrentLicense();
        LicenseInfo ValidateKey(const std::string& key);
        std::string GetHardwareId();
        std::string GenerateEvaluationKey(LicenseTier tier = LicenseTier::Enterprise, const std::string& user = "Authorized Operator");
        void InstallLicense(const std::string& key);

    private:
        LicenseManager();
        ~LicenseManager() = default;

        std::string ComputeMachineHash();
        std::string CalculateKeySignature(const std::string& prefix, const std::string& machineId, const std::string& expDate);
    };

} // namespace XIII
