#include "modules.hpp"
#include "console.hpp"
#include "api_registry.hpp"
#include <iostream>
#include <iomanip>

namespace XIII {

    void ApiStatusModule::RunInteractive() {
        while (true) {
            Console::Clear();
            Console::PrintHeader("API STATUS & RESEARCH REGISTRY [21]");

            auto endpoints = ApiRegistry::Instance().GetAllEndpoints();

            std::cout << "\nRegistered Open Source Intelligence & Security APIs:\n\n";

            std::vector<std::string> headers = {"#", "Provider Name", "Category", "Auth Type", "Rate Limit", "Status"};
            std::vector<std::vector<std::string>> rows;

            for (size_t i = 0; i < endpoints.size(); ++i) {
                const auto& ep = endpoints[i];
                std::string num = "[" + std::to_string(i + 1) + "]";
                std::string auth;
                switch (ep.authType) {
                    case AuthType::None: auth = "Free (No Key)"; break;
                    case AuthType::FreeKeyOptional: auth = "Key Optional"; break;
                    case AuthType::FreeKeyRequired: auth = ep.isConfigured ? "Key Active" : "Key Required"; break;
                    case AuthType::CommercialKey: auth = "Paid Key"; break;
                }

                std::string statusStr = ep.isEnabled ? (ep.isOperational ? "ONLINE (" + std::to_string(ep.lastLatencyMs) + "ms)" : "STANDBY") : "DISABLED";
                rows.push_back({num, ep.name, ep.category, auth, ep.rateLimits, statusStr});
            }

            Console::PrintTable(headers, rows);

            std::cout << "\nOptions:\n";
            std::cout << "[1] Run Live Health Check on all endpoints\n";
            std::cout << "[2] View details & documentation for a specific API\n";
            std::cout << "[3] Toggle API enabled/disabled\n";
            std::cout << "[4] Return to Main Menu\n";

            int action = Console::ReadInt("Select option (1-4): ", 1, 4);
            if (action == 4) return;

            if (action == 1) {
                Console::Info("Testing connectivity and measuring latency for active endpoints...");
                ApiRegistry::Instance().RefreshAllStatuses();
                Console::Success("Health check completed.");
                Console::Pause();
            } else if (action == 2) {
                int index = Console::ReadInt("Select API number (1-" + std::to_string(endpoints.size()) + "): ", 1, static_cast<int>(endpoints.size())) - 1;
                const auto& ep = endpoints[index];

                Console::Clear();
                Console::PrintHeader("API DETAILS: " + ep.name);
                std::cout << "\n";
                std::cout << "Identifier:        " << ep.id << "\n";
                std::cout << "Documentation:     " << ep.docUrl << "\n";
                std::cout << "Category:          " << ep.category << "\n";
                std::cout << "Free Tier Limits:  " << ep.freeTierLimits << "\n";
                std::cout << "Rate Limits:       " << ep.rateLimits << "\n";
                std::cout << "Commercial Terms:  " << ep.commercialUsage << "\n";
                std::cout << "Response Format:   " << ep.responseFormat << "\n";
                std::cout << "Error Handling:    " << ep.errorHandlingNotes << "\n";
                std::cout << "Status:            " << (ep.isEnabled ? "Enabled" : "Disabled") << "\n";
                Console::Pause();
            } else if (action == 3) {
                int index = Console::ReadInt("Select API number to toggle (1-" + std::to_string(endpoints.size()) + "): ", 1, static_cast<int>(endpoints.size())) - 1;
                auto& ep = endpoints[index];
                ApiRegistry::Instance().SetEndpointEnabled(ep.id, !ep.isEnabled);
                Console::Success("API " + ep.name + " is now " + (!ep.isEnabled ? "ENABLED" : "DISABLED") + ".");
                Console::Pause();
            }
        }
    }

} // namespace XIII
