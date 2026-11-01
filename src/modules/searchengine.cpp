#include "modules.hpp"
#include "console.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>
#include <filesystem>

namespace XIII {

    InvestigationReport SearchEngineModule::Execute(const std::string& target) {
        InvestigationReport report;
        report.moduleName = "Comprehensive";
        report.target = target;
        report.targetType = "Search Engine Dork Reconnaissance Target";

        Console::Info("Initializing automated Google Dork reconnaissance suite");
        Console::Status("Dork Matrix", "Compiling high-impact intelligence query vectors");

        struct DorkCategory {
            std::string category;
            std::string dork;
            std::string objective;
        };

        std::vector<DorkCategory> dorks = {
            {"Exposed Configs", "site:" + target + " (filetype:env OR filetype:yml OR filetype:conf OR filetype:ini)", "Locates unencrypted server configurations and environment variables."},
            {"Database Backups", "site:" + target + " (filetype:sql OR filetype:bak OR filetype:dump OR filetype:db)", "Identifies abandoned database exports or raw SQL dumps."},
            {"Sensitive Documents", "site:" + target + " (filetype:pdf OR filetype:xlsx OR filetype:docx) (\"confidential\" OR \"internal\")", "Discovers indexed internal or restricted enterprise documents."},
            {"Administrative Portals", "site:" + target + " (inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard)", "Maps unauthenticated or exposed administration gateways."},
            {"Directory Indexing", "site:" + target + " intitle:\"index of /\"", "Finds webservers with directory indexing enabled exposing files."},
            {"Code Leaks & Secrets", "site:github.com OR site:gitlab.com \"" + target + "\" (api_key OR password OR secret OR token)", "Discovers leaked hardcoded credentials or access keys on public VCS."},
            {"Pastebin & Leaks", "(site:pastebin.com OR site:justpaste.it OR site:rentry.co) \"" + target + "\"", "Scans public paste sites for target mentions or credential dumps."},
            {"Subdomain Discovery", "site:*." + target + " -www." + target, "Enumerates indexed third-level domain assets."}
        };

        ServiceResult dorkRes;
        dorkRes.serviceName = "Google Dork Reconnaissance Matrix";
        dorkRes.providerUrl = "https://www.google.com/search";
        dorkRes.timestamp = Utils::GetCurrentTimestamp();
        dorkRes.status = FindingStatus::CONFIRMED;
        dorkRes.summary = "Compiled " + std::to_string(dorks.size()) + " targeted intelligence search queries.";

        for (const auto& d : dorks) {
            std::string searchLink = "https://www.google.com/search?q=" + Utils::UrlEncode(d.dork);
            dorkRes.details.push_back({dorkRes.serviceName, d.category, d.dork, d.objective + " -> Link: " + searchLink, FindingStatus::CONFIRMED, searchLink, 200, d.dork, dorkRes.timestamp});
        }

        report.results.push_back(dorkRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Search engine intelligence dork matrix compiled for target '" << target << "'. "
           << "Constructed " << dorks.size() << " precision queries covering configurations, databases, leaks, and admin panels.";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void SearchEngineModule::RunInteractive() {
        Console::PrintHeader("SEARCH ENGINE INTELLIGENCE [18]");
        std::string target = Console::ReadLine("Enter target domain or organization name: ");
        if (target.empty()) {
            Console::Warning("No target entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(target);
        Console::Pause();
    }

} // namespace XIII
