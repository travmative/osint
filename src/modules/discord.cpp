#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>

namespace XIII {

    InvestigationReport DiscordModule::Execute(const std::string& snowflakeId) {
        InvestigationReport report;
        report.moduleName = "Discord";
        report.target = snowflakeId;
        report.targetType = "Discord Snowflake ID";

        Console::Info("Initializing Discord intelligence analysis engine");

        // Validate numeric snowflake
        uint64_t snowflake = 0;
        try {
            snowflake = std::stoull(snowflakeId);
        } catch (...) {
            Console::Error("Invalid Discord Snowflake ID format (must be a 64-bit unsigned integer).");
            ServiceResult errRes;
            errRes.serviceName = "Snowflake Parser";
            errRes.status = FindingStatus::UNVERIFIED;
            errRes.summary = "Supplied ID is not a valid 64-bit integer.";
            report.results.push_back(errRes);
            return report;
        }

        Console::Status("Snowflake Math", "Decoding internal bitfield components");

        // Discord Epoch: January 1, 2015 00:00:00.000 UTC
        constexpr uint64_t DISCORD_EPOCH = 1420070400000ULL;
        uint64_t timestampMs = (snowflake >> 22) + DISCORD_EPOCH;
        uint32_t internalWorkerId = (snowflake & 0x3E0000ULL) >> 17;
        uint32_t internalProcessId = (snowflake & 0x1F000ULL) >> 12;
        uint32_t increment = (snowflake & 0xFFFULL);

        std::time_t createdTimeSec = static_cast<std::time_t>(timestampMs / 1000);
        std::tm tmBuf;
        gmtime_s(&tmBuf, &createdTimeSec);

        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S UTC", &tmBuf);

        // Account age calculation
        auto now = std::chrono::system_clock::now();
        std::time_t nowSec = std::chrono::system_clock::to_time_t(now);
        double ageDays = (nowSec - createdTimeSec) / 86400.0;
        double ageYears = ageDays / 365.25;

        ServiceResult snowRes;
        snowRes.serviceName = "Snowflake Epoch Decoder";
        snowRes.providerUrl = "Discord Developer Documentation (Snowflake Specifications)";
        snowRes.timestamp = Utils::GetCurrentTimestamp();
        snowRes.status = FindingStatus::CONFIRMED;

        std::ostringstream ageSs;
        ageSs << std::fixed << std::setprecision(1) << ageDays << " days (" << std::setprecision(2) << ageYears << " years)";

        snowRes.summary = "Creation Timestamp: " + std::string(timeStr) + " | Age: " + ageSs.str();
        snowRes.details.push_back({snowRes.serviceName, "Chronology", "Creation Timestamp", timeStr, FindingStatus::CONFIRMED, "", 0, timeStr, snowRes.timestamp});
        snowRes.details.push_back({snowRes.serviceName, "Chronology", "Account Age", ageSs.str(), FindingStatus::CONFIRMED, "", 0, ageSs.str(), snowRes.timestamp});
        snowRes.details.push_back({snowRes.serviceName, "Internal Hardware", "Worker ID", std::to_string(internalWorkerId), FindingStatus::CONFIRMED, "", 0, std::to_string(internalWorkerId), snowRes.timestamp});
        snowRes.details.push_back({snowRes.serviceName, "Internal Hardware", "Process ID", std::to_string(internalProcessId), FindingStatus::CONFIRMED, "", 0, std::to_string(internalProcessId), snowRes.timestamp});
        snowRes.details.push_back({snowRes.serviceName, "Internal Hardware", "Sequence Increment", std::to_string(increment), FindingStatus::CONFIRMED, "", 0, std::to_string(increment), snowRes.timestamp});

        report.results.push_back(snowRes);

        // 2. Official Discord API (when bot token configured)
        Console::Status("Discord API", "Querying public user metadata");
        ServiceResult apiRes;
        apiRes.serviceName = "Discord REST API v10";
        apiRes.providerUrl = "https://discord.com/api/v10/users/" + snowflakeId;
        apiRes.timestamp = Utils::GetCurrentTimestamp();

        std::string botToken = ConfigManager::Instance().GetApiKey("DISCORD_BOT_TOKEN");
        if (!botToken.empty()) {
            HttpRequestOptions dOpts;
            dOpts.headers["Authorization"] = "Bot " + botToken;
            auto dHttp = HttpClient::Instance().Get(apiRes.providerUrl, dOpts);
            apiRes.httpStatus = dHttp.statusCode;
            apiRes.responseTimeMs = dHttp.elapsedMilliseconds;

            if (dHttp.statusCode == 200) {
                apiRes.status = FindingStatus::CONFIRMED;
                auto j = dHttp.AsJson();
                std::string username = j.value("username", "");
                std::string globalName = j.value("global_name", "");
                std::string avatar = j.value("avatar", "");
                std::string banner = j.value("banner", "");
                int flags = j.value("public_flags", 0);

                apiRes.summary = "Resolved User: " + (globalName.empty() ? username : globalName + " (@" + username + ")");
                apiRes.details.push_back({apiRes.serviceName, "Identity", "Username", username, FindingStatus::CONFIRMED, apiRes.providerUrl, 200, username, apiRes.timestamp});
                if (!globalName.empty()) apiRes.details.push_back({apiRes.serviceName, "Identity", "Global Display Name", globalName, FindingStatus::CONFIRMED, apiRes.providerUrl, 200, globalName, apiRes.timestamp});
                if (!avatar.empty()) {
                    std::string avatarUrl = "https://cdn.discordapp.com/avatars/" + snowflakeId + "/" + avatar + ".png?size=512";
                    apiRes.profileUrl = avatarUrl;
                    apiRes.details.push_back({apiRes.serviceName, "Media", "Avatar CDN URL", avatarUrl, FindingStatus::CONFIRMED, apiRes.providerUrl, 200, avatarUrl, apiRes.timestamp});
                }
                apiRes.details.push_back({apiRes.serviceName, "Account", "Public Flags", std::to_string(flags), FindingStatus::CONFIRMED, apiRes.providerUrl, 200, std::to_string(flags), apiRes.timestamp});
            } else {
                apiRes.status = FindingStatus::NOT_FOUND;
                apiRes.summary = "Discord API returned status " + std::to_string(dHttp.statusCode);
            }
        } else {
            apiRes.status = FindingStatus::UNVERIFIED;
            apiRes.summary = "No Discord Bot Token configured in Settings (Option 22). To query real-time user profiles, add an authorized Bot Token.";
        }
        report.results.push_back(apiRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Discord snowflake intelligence for ID " << snowflakeId << " completed. "
           << "Created on: " << timeStr << " (" << ageSs.str() << "). "
           << "Hardware Origin: Worker " << internalWorkerId << ", Process " << internalProcessId << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void DiscordModule::RunInteractive() {
        Console::PrintHeader("DISCORD ID INTELLIGENCE [07]");
        std::string id = Console::ReadLine("Enter Discord Snowflake ID (e.g. 155149108183695360): ");
        if (id.empty()) {
            Console::Warning("No ID entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(id);
        Console::Pause();
    }

} // namespace XIII
