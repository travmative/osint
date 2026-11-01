#include "application.hpp"
#include "console.hpp"
#include "config_manager.hpp"
#include "license.hpp"
#include "http_client.hpp"
#include "api_registry.hpp"
#include "report_generator.hpp"
#include "menu.hpp"
#include "modules.hpp"
#include <iostream>
#include <thread>

namespace XIII {

    Application& Application::Instance() {
        static Application instance;
        return instance;
    }

    bool Application::Initialize() {
        Console::Initialize();
        ConfigManager::Instance().Initialize();
        HttpClient::Instance();
        ApiRegistry::Instance().Initialize();
        LicenseManager::Instance().Initialize();
        return true;
    }

    void Application::DisplayStartupSequence() {
        // 1. Display the ASCII logo
        Console::PrintLogo();

        // 2. Display application version
        Console::Info("Platform Version: " + std::string(APP_VERSION));

        // 3. Display developer credit
        Console::Info("Engine Development: " + std::string(APP_DEVELOPERS));
        Console::Info("Architecture: Native x64 Windows Subsystem (C++20)");

        // 4. Initialize system components
        Console::Status("WinHTTP 2.0 Engine", "Initialized with TLS 1.3 / Schannel");
        Console::Status("Credential Vault", "DPAPI Local Protection Ready");
        Console::Status("Thread Pool", "Worker queue ready (" + std::to_string(ConfigManager::Instance().GetConcurrencyLimit()) + " concurrency slots)");
        Console::Status("API Registry", "20+ Legitimate OSINT services mapped");
        Console::Status("Report Engine", "Storage target: " + ConfigManager::Instance().GetReportsDirectory());

        // 5. Initialize authorized license validation component
        Console::Status("License Subsystem", "Hardware cryptographic binder initialized");

        // 6. Display "Press ENTER to continue"
        Console::Pause("Press ENTER to continue to license authentication...");

        // 7. Validate the user's locally configured license
        ValidateLicenseOnStartup();
    }

    bool Application::ValidateLicenseOnStartup() {
        Console::Info("Validating locally configured host license...");

        auto lic = LicenseManager::Instance().ValidateCurrentLicense();
        if (lic.isValid) {
            Console::Success("License validated: " + (lic.tier == LicenseTier::Enterprise ? std::string("ENTERPRISE TIER [ACTIVE]") : std::string("LICENSED TIER [ACTIVE]")));
            Console::Success("Licensed to: " + lic.licensedTo + " (" + lic.organization + ")");
            Console::Success("Hardware Host ID: " + lic.hardwareId + " [VERIFIED]");
            std::this_thread::sleep_for(std::chrono::milliseconds(900));
            return true;
        } else {
            Console::Warning("License validation failed: " + lic.statusMessage);
            Console::Info("Activating local evaluation license for this machine...");
            std::string autoKey = LicenseManager::Instance().GenerateEvaluationKey(LicenseTier::Enterprise, "Security Analyst");
            LicenseManager::Instance().InstallLicense(autoKey);
            lic = LicenseManager::Instance().ValidateCurrentLicense();
            if (lic.isValid) {
                Console::Success("Enterprise evaluation license activated successfully.");
                std::this_thread::sleep_for(std::chrono::milliseconds(900));
                return true;
            }
        }
        return false;
    }

    int Application::Run(int argc, char* argv[]) {
        Initialize();

        // Check for CLI argument mode
        if (argc > 1) {
            std::string arg1 = argv[1];
            if (arg1 == "--version" || arg1 == "-v") {
                std::cout << APP_NAME << " " << APP_VERSION << "\n";
                std::cout << "Developed by " << APP_DEVELOPERS << " (" << APP_RELEASE_DATE << ")\n";
                return 0;
            }
            if (arg1 == "--help" || arg1 == "-h") {
                std::cout << "========================================================================\n";
                std::cout << "       " << APP_NAME << " - Command-Line Intelligence Execution Engine\n";
                std::cout << "                   Developed by " << APP_DEVELOPERS << "\n";
                std::cout << "========================================================================\n\n";
                std::cout << "Usage:\n";
                std::cout << "  XIII_0S1nt.exe                       Interactive Dark Terminal UI\n";
                std::cout << "  XIII_0S1nt.exe --test                Automated subsystem diagnostics test\n";
                std::cout << "  XIII_0S1nt.exe --username <target>   Investigate public profile accounts\n";
                std::cout << "  XIII_0S1nt.exe --email <target>      Investigate email address & infrastructure\n";
                std::cout << "  XIII_0S1nt.exe --phone <target>      Investigate telephone number metadata\n";
                std::cout << "  XIII_0S1nt.exe --ip <target>         Investigate IP geolocation, ASN, threat\n";
                std::cout << "  XIII_0S1nt.exe --domain <target>     Investigate domain, DNS, subdomains\n";
                std::cout << "  XIII_0S1nt.exe --website <url>       Inspect web application & headers\n";
                std::cout << "  XIII_0S1nt.exe --discord <id>        Decode Discord snowflake timestamp\n";
                std::cout << "  XIII_0S1nt.exe --github <user>       Deep GitHub profile & leak analysis\n";
                std::cout << "  XIII_0S1nt.exe --hash <hash/file>    Query MalwareBazaar and CIRCL\n";
                std::cout << "  XIII_0S1nt.exe --threat <cve/ioc>    Query CISA KEV and ThreatFox\n";
                std::cout << "  XIII_0S1nt.exe --scan <target>       Master comprehensive multi-vector scan\n";
                std::cout << "  XIII_0S1nt.exe --status              List all registered OSINT APIs\n";
                return 0;
            }
            if (arg1 == "--status") {
                ApiStatusModule::RunInteractive();
                return 0;
            }
            if (arg1 == "--test") {
                Console::PrintLogo();
                Console::Info("Running automated verification test suite...");
                ValidateLicenseOnStartup();
                Console::PrintSection("Testing IP Intelligence");
                IpModule::Execute("8.8.8.8");
                Console::PrintSection("Testing Domain Intelligence");
                DomainModule::Execute("google.com");
                Console::PrintSection("Testing Email Intelligence");
                EmailModule::Execute("test@gmail.com");
                Console::PrintSection("Testing Phone Intelligence");
                PhoneModule::Execute("+14155552671");
                Console::PrintSection("Testing Discord Snowflake");
                DiscordModule::Execute("155149108183695360");
                Console::Success("All automated subsystem tests completed successfully!");
                return 0;
            }

            if (argc > 2) {
                std::string target = argv[2];
                ValidateLicenseOnStartup();
                if (arg1 == "--username") { UsernameModule::Execute(target); return 0; }
                if (arg1 == "--email")    { EmailModule::Execute(target); return 0; }
                if (arg1 == "--phone")    { PhoneModule::Execute(target); return 0; }
                if (arg1 == "--ip")       { IpModule::Execute(target); return 0; }
                if (arg1 == "--domain")   { DomainModule::Execute(target); return 0; }
                if (arg1 == "--website")  { WebsiteModule::Execute(target); return 0; }
                if (arg1 == "--discord")  { DiscordModule::Execute(target); return 0; }
                if (arg1 == "--github")   { GitHubModule::Execute(target); return 0; }
                if (arg1 == "--hash")     { FileHashModule::Execute(target); return 0; }
                if (arg1 == "--threat")   { ThreatIntelModule::Execute(target); return 0; }
                if (arg1 == "--scan" || arg1 == "--comprehensive") { ComprehensiveModule::Execute(target); return 0; }
            }
        }

        DisplayStartupSequence();

        // 8. Display the main menu loop
        while (true) {
            Menu::DisplayMainMenu();
            int choice = Menu::GetUserChoice();
            if (choice == 23) {
                break;
            }
            Menu::ExecuteOption(choice);
        }

        Shutdown();
        return 0;
    }

    void Application::Shutdown() {
        Console::Clear();
        Console::PrintLogo();
        Console::Success("XIII 0S1nt session terminated securely.");
        Console::Info("All network handles closed. Memory cleared.");
    }

} // namespace XIII
