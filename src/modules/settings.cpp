#include "modules.hpp"
#include "console.hpp"
#include "config_manager.hpp"
#include "license.hpp"
#include <iostream>

namespace XIII {

    void SettingsModule::RunInteractive() {
        while (true) {
            Console::Clear();
            Console::PrintHeader("APPLICATION SETTINGS & CREDENTIAL VAULT [22]");

            std::cout << "\nSecure Configuration Subsystem (Protected with Windows DPAPI):\n\n";
            std::cout << "[1] Configure API Keys (VirusTotal, HIBP, AbuseIPDB, GitHub, Discord)\n";
            std::cout << "[2] Network Timeout (Current: " << ConfigManager::Instance().GetTimeoutSeconds() << "s)\n";
            std::cout << "[3] Thread Pool Concurrency (Current: " << ConfigManager::Instance().GetConcurrencyLimit() << " workers)\n";
            std::cout << "[4] Global HTTP / SOCKS Proxy (Current: " << (ConfigManager::Instance().GetProxy().empty() ? "Direct / None" : ConfigManager::Instance().GetProxy()) << ")\n";
            std::cout << "[5] License & Hardware Authorization Status\n";
            std::cout << "[6] Return to Main Menu\n";

            int choice = Console::ReadInt("\nSelect setting (1-6): ", 1, 6);
            if (choice == 6) return;

            if (choice == 1) {
                Console::Clear();
                Console::PrintHeader("API KEY VAULT");
                std::cout << "\nSelect API provider to configure:\n";
                std::cout << "[1] VIRUSTOTAL_API_KEY (Status: " << (ConfigManager::Instance().HasApiKey("VIRUSTOTAL_API_KEY") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[2] HIBP_API_KEY       (Status: " << (ConfigManager::Instance().HasApiKey("HIBP_API_KEY") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[3] ABUSEIPDB_API_KEY  (Status: " << (ConfigManager::Instance().HasApiKey("ABUSEIPDB_API_KEY") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[4] GREYNOISE_API_KEY  (Status: " << (ConfigManager::Instance().HasApiKey("GREYNOISE_API_KEY") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[5] GITHUB_TOKEN       (Status: " << (ConfigManager::Instance().HasApiKey("GITHUB_TOKEN") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[6] DISCORD_BOT_TOKEN  (Status: " << (ConfigManager::Instance().HasApiKey("DISCORD_BOT_TOKEN") ? "Configured [SECURE]" : "Not Set") << ")\n";
                std::cout << "[7] Back\n";

                int keyChoice = Console::ReadInt("\nSelect provider (1-7): ", 1, 7);
                if (keyChoice >= 1 && keyChoice <= 6) {
                    std::string prov;
                    switch (keyChoice) {
                        case 1: prov = "VIRUSTOTAL_API_KEY"; break;
                        case 2: prov = "HIBP_API_KEY"; break;
                        case 3: prov = "ABUSEIPDB_API_KEY"; break;
                        case 4: prov = "GREYNOISE_API_KEY"; break;
                        case 5: prov = "GITHUB_TOKEN"; break;
                        case 6: prov = "DISCORD_BOT_TOKEN"; break;
                    }

                    std::string keyInput = Console::ReadPassword("Enter key for " + prov + " (masked, leave blank to remove): ");
                    ConfigManager::Instance().SetApiKey(prov, keyInput);
                    if (keyInput.empty()) {
                        Console::Warning("Removed key for " + prov + ".");
                    } else {
                        Console::Success("Key securely encrypted using DPAPI and saved to vault.");
                    }
                    Console::Pause();
                }
            } else if (choice == 2) {
                int sec = Console::ReadInt("Enter new request timeout in seconds (3-60): ", 3, 60);
                ConfigManager::Instance().SetTimeoutSeconds(sec);
                Console::Success("Timeout updated.");
                Console::Pause();
            } else if (choice == 3) {
                int workers = Console::ReadInt("Enter max thread pool workers (2-32): ", 2, 32);
                ConfigManager::Instance().SetConcurrencyLimit(workers);
                Console::Success("Concurrency worker pool updated.");
                Console::Pause();
            } else if (choice == 4) {
                std::string proxy = Console::ReadLine("Enter proxy address (e.g. http://127.0.0.1:8080 or leave blank for Direct): ");
                ConfigManager::Instance().SetProxy(proxy);
                Console::Success("Proxy configuration updated.");
                Console::Pause();
            } else if (choice == 5) {
                Console::Clear();
                Console::PrintHeader("LICENSE & HOST AUTHORIZATION");
                auto lic = LicenseManager::Instance().ValidateCurrentLicense();
                std::cout << "\n";
                std::cout << "Hardware ID (HWID): " << lic.hardwareId << "\n";
                std::cout << "License Key:        " << lic.licenseKey << "\n";
                std::cout << "License Tier:       " << (lic.tier == LicenseTier::Enterprise ? "ENTERPRISE [ACTIVE]" : (lic.tier == LicenseTier::Professional ? "PROFESSIONAL" : "COMMUNITY")) << "\n";
                std::cout << "Licensed To:        " << lic.licensedTo << "\n";
                std::cout << "Organization:       " << lic.organization << "\n";
                std::cout << "Expiration Date:    " << lic.expirationDate << "\n";
                std::cout << "Status Message:     " << lic.statusMessage << "\n";

                std::cout << "\n[1] Enter a new License Key\n";
                std::cout << "[2] Back\n";
                int lAct = Console::ReadInt("Select action (1-2): ", 1, 2);
                if (lAct == 1) {
                    std::string newKey = Console::ReadLine("Enter new license key (e.g. XIII-ENT-2029-XXXX-XXXX-XXXX): ");
                    auto check = LicenseManager::Instance().ValidateKey(newKey);
                    if (check.isValid) {
                        LicenseManager::Instance().InstallLicense(newKey);
                        Console::Success("License successfully installed and activated!");
                    } else {
                        Console::Error("Invalid license key: " + check.statusMessage);
                    }
                    Console::Pause();
                }
            }
        }
    }

} // namespace XIII
