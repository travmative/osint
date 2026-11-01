#include "config_manager.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace XIII {

    ConfigManager& ConfigManager::Instance() {
        static ConfigManager instance;
        return instance;
    }

    ConfigManager::ConfigManager() {
        Initialize();
    }

    ConfigManager::~ConfigManager() {
        Save();
    }

    std::string ConfigManager::GetAppDataFolder() const {
        char appDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
            fs::path dir = fs::path(appDataPath) / "XIII_0S1nt";
            if (!fs::exists(dir)) {
                fs::create_directories(dir);
            }
            return dir.string();
        }
        return ".";
    }

    std::string ConfigManager::GetConfigFilePath() const {
        return (fs::path(GetAppDataFolder()) / "config.json").string();
    }

    std::string ConfigManager::GetVaultFilePath() const {
        return (fs::path(GetAppDataFolder()) / "vault.bin").string();
    }

    std::vector<uint8_t> ConfigManager::EncryptDpapi(const std::string& plaintext) const {
        if (plaintext.empty()) return {};

        DATA_BLOB dataIn;
        dataIn.pbData = (BYTE*)plaintext.data();
        dataIn.cbData = (DWORD)plaintext.length();

        DATA_BLOB dataOut;
        if (CryptProtectData(&dataIn, L"XIII_0S1nt_Vault", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dataOut)) {
            std::vector<uint8_t> result(dataOut.pbData, dataOut.pbData + dataOut.cbData);
            LocalFree(dataOut.pbData);
            return result;
        }
        return {};
    }

    std::string ConfigManager::DecryptDpapi(const std::vector<uint8_t>& ciphertext) const {
        if (ciphertext.empty()) return "";

        DATA_BLOB dataIn;
        dataIn.pbData = (BYTE*)ciphertext.data();
        dataIn.cbData = (DWORD)ciphertext.size();

        DATA_BLOB dataOut;
        if (CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dataOut)) {
            std::string result((char*)dataOut.pbData, dataOut.cbData);
            LocalFree(dataOut.pbData);
            return result;
        }
        return "";
    }

    void ConfigManager::Initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        LoadSettings();
        LoadVault();
    }

    void ConfigManager::Save() {
        std::lock_guard<std::mutex> lock(m_mutex);
        SaveSettings();
        SaveVault();
    }

    void ConfigManager::LoadSettings() {
        std::string cfgPath = GetConfigFilePath();
        if (!fs::exists(cfgPath)) return;

        try {
            std::ifstream file(cfgPath);
            if (!file.is_open()) return;

            nlohmann::json j;
            file >> j;

            if (j.contains("timeoutSeconds")) m_timeoutSeconds = j["timeoutSeconds"].get<int>();
            if (j.contains("concurrencyLimit")) m_concurrencyLimit = j["concurrencyLimit"].get<int>();
            if (j.contains("proxy")) m_proxy = j["proxy"].get<std::string>();
            if (j.contains("ansiEnabled")) m_ansiEnabled = j["ansiEnabled"].get<bool>();
            if (j.contains("reportsDir")) m_reportsDir = j["reportsDir"].get<std::string>();
            if (j.contains("licenseKey")) m_licenseKey = j["licenseKey"].get<std::string>();
        } catch (...) {}
    }

    void ConfigManager::SaveSettings() {
        try {
            nlohmann::json j;
            j["timeoutSeconds"] = m_timeoutSeconds;
            j["concurrencyLimit"] = m_concurrencyLimit;
            j["proxy"] = m_proxy;
            j["ansiEnabled"] = m_ansiEnabled;
            j["reportsDir"] = m_reportsDir;
            j["licenseKey"] = m_licenseKey;

            std::ofstream file(GetConfigFilePath());
            if (file.is_open()) {
                file << j.dump(4);
            }
        } catch (...) {}
    }

    void ConfigManager::LoadVault() {
        std::string vaultPath = GetVaultFilePath();
        if (!fs::exists(vaultPath)) return;

        try {
            std::ifstream file(vaultPath, std::ios::binary);
            if (!file.is_open()) return;

            std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (buffer.empty()) return;

            std::string decrypted = DecryptDpapi(buffer);
            if (decrypted.empty()) return;

            nlohmann::json j = nlohmann::json::parse(decrypted);
            for (auto& [k, v] : j.items()) {
                m_apiKeys[k] = v.get<std::string>();
            }
        } catch (...) {}
    }

    void ConfigManager::SaveVault() {
        try {
            nlohmann::json j;
            for (const auto& [k, v] : m_apiKeys) {
                if (!v.empty()) {
                    j[k] = v;
                }
            }
            std::string serialized = j.dump();
            std::vector<uint8_t> encrypted = EncryptDpapi(serialized);

            std::ofstream file(GetVaultFilePath(), std::ios::binary);
            if (file.is_open() && !encrypted.empty()) {
                file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
            }
        } catch (...) {}
    }

    std::string ConfigManager::GetApiKey(const std::string& provider) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_apiKeys.find(provider);
        if (it != m_apiKeys.end()) {
            return it->second;
        }
        return "";
    }

    void ConfigManager::SetApiKey(const std::string& provider, const std::string& key) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (key.empty()) {
                m_apiKeys.erase(provider);
            } else {
                m_apiKeys[provider] = key;
            }
        }
        SaveVault();
    }

    bool ConfigManager::HasApiKey(const std::string& provider) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_apiKeys.find(provider);
        return (it != m_apiKeys.end() && !it->second.empty());
    }

    std::vector<std::string> ConfigManager::GetConfiguredProviders() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::string> list;
        for (const auto& [k, v] : m_apiKeys) {
            if (!v.empty()) {
                list.push_back(k);
            }
        }
        return list;
    }

    int ConfigManager::GetTimeoutSeconds() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_timeoutSeconds;
    }

    void ConfigManager::SetTimeoutSeconds(int seconds) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_timeoutSeconds = seconds;
        }
        SaveSettings();
    }

    int ConfigManager::GetConcurrencyLimit() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_concurrencyLimit;
    }

    void ConfigManager::SetConcurrencyLimit(int limit) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_concurrencyLimit = limit;
        }
        SaveSettings();
    }

    std::string ConfigManager::GetProxy() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_proxy;
    }

    void ConfigManager::SetProxy(const std::string& proxy) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_proxy = proxy;
        }
        SaveSettings();
    }

    bool ConfigManager::IsAnsiEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_ansiEnabled;
    }

    void ConfigManager::SetAnsiEnabled(bool enabled) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_ansiEnabled = enabled;
        }
        SaveSettings();
    }

    std::string ConfigManager::GetReportsDirectory() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_reportsDir;
    }

    void ConfigManager::SetReportsDirectory(const std::string& path) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_reportsDir = path;
        }
        SaveSettings();
    }

    std::string ConfigManager::GetLicenseKey() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_licenseKey;
    }

    void ConfigManager::SetLicenseKey(const std::string& key) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_licenseKey = key;
        }
        SaveSettings();
    }

} // namespace XIII
