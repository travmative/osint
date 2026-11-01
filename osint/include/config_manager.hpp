#pragma once

#include <string>
#include <map>
#include <mutex>
#include <vector>

namespace XIII {

    class ConfigManager {
    public:
        static ConfigManager& Instance();

        void Initialize();
        void Save();

        // API Keys (Encrypted with Windows DPAPI)
        std::string GetApiKey(const std::string& provider) const;
        void SetApiKey(const std::string& provider, const std::string& key);
        bool HasApiKey(const std::string& provider) const;
        std::vector<std::string> GetConfiguredProviders() const;

        // Settings
        int GetTimeoutSeconds() const;
        void SetTimeoutSeconds(int seconds);

        int GetConcurrencyLimit() const;
        void SetConcurrencyLimit(int limit);

        std::string GetProxy() const;
        void SetProxy(const std::string& proxy);

        bool IsAnsiEnabled() const;
        void SetAnsiEnabled(bool enabled);

        std::string GetReportsDirectory() const;
        void SetReportsDirectory(const std::string& path);

        std::string GetLicenseKey() const;
        void SetLicenseKey(const std::string& key);

    private:
        ConfigManager();
        ~ConfigManager();

        std::string GetAppDataFolder() const;
        std::string GetConfigFilePath() const;
        std::string GetVaultFilePath() const;

        std::vector<uint8_t> EncryptDpapi(const std::string& plaintext) const;
        std::string DecryptDpapi(const std::vector<uint8_t>& ciphertext) const;

        void LoadSettings();
        void SaveSettings();
        void LoadVault();
        void SaveVault();

        mutable std::mutex m_mutex;
        std::map<std::string, std::string> m_apiKeys;
        int m_timeoutSeconds{12};
        int m_concurrencyLimit{10};
        std::string m_proxy;
        bool m_ansiEnabled{true};
        std::string m_reportsDir{"XIII_Reports"};
        std::string m_licenseKey;
    };

} // namespace XIII
