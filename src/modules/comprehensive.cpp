#include "modules.hpp"
#include "console.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>
#include <filesystem>

namespace XIII {

    InvestigationReport ComprehensiveModule::Execute(const std::string& target) {
        InvestigationReport report;
        report.moduleName = "Comprehensive";
        report.target = target;
        report.targetType = "Multi-Vector Correlated Target";

        Console::Info("Initializing master comprehensive OSINT correlation scan");
        Console::Status("Classifier", "Determining target characteristics and investigative vectors");

        bool isEmail = (target.find('@') != std::string::npos && target.find('.') != std::string::npos);
        bool isIp = (target.find('.') != std::string::npos && isdigit((unsigned char)target[0])) || (target.find(':') != std::string::npos && isxdigit((unsigned char)target[0]));
        bool isDomain = (!isEmail && !isIp && target.find('.') != std::string::npos && target.find(' ') == std::string::npos);

        if (isEmail) {
            Console::Info("Detected vector: EMAIL IDENTITY");
            auto emailRep = EmailModule::Execute(target);
            for (const auto& r : emailRep.results) report.results.push_back(r);

            size_t atPos = target.find('@');
            std::string userPart = target.substr(0, atPos);
            std::string domainPart = target.substr(atPos + 1);

            Console::Info("Correlating username vector: " + userPart);
            auto userRep = UsernameModule::Execute(userPart);
            for (const auto& r : userRep.results) report.results.push_back(r);

            Console::Info("Correlating domain vector: " + domainPart);
            auto domRep = DomainModule::Execute(domainPart);
            for (const auto& r : domRep.results) report.results.push_back(r);
        } else if (isIp) {
            Console::Info("Detected vector: IP INFRASTRUCTURE");
            auto ipRep = IpModule::Execute(target);
            for (const auto& r : ipRep.results) report.results.push_back(r);

            auto whoisRep = WhoisModule::Execute(target);
            for (const auto& r : whoisRep.results) report.results.push_back(r);
        } else if (isDomain) {
            Console::Info("Detected vector: DOMAIN & WEB ASSETS");
            auto domRep = DomainModule::Execute(target);
            for (const auto& r : domRep.results) report.results.push_back(r);

            auto dnsRep = DnsModule::Execute(target);
            for (const auto& r : dnsRep.results) report.results.push_back(r);

            auto webRep = WebsiteModule::Execute("https://" + target);
            for (const auto& r : webRep.results) report.results.push_back(r);

            auto dorkRep = SearchEngineModule::Execute(target);
            for (const auto& r : dorkRep.results) report.results.push_back(r);
        } else {
            // Username / Handle / Identity
            Console::Info("Detected vector: USERNAME / DIGITAL IDENTITY");
            auto userRep = UsernameModule::Execute(target);
            for (const auto& r : userRep.results) report.results.push_back(r);

            auto ghRep = GitHubModule::Execute(target);
            for (const auto& r : ghRep.results) report.results.push_back(r);

            auto socRep = SocialModule::Execute(target);
            for (const auto& r : socRep.results) report.results.push_back(r);

            auto profRep = PublicProfileModule::Execute(target);
            for (const auto& r : profRep.results) report.results.push_back(r);
        }

        Console::Success("Comprehensive multi-vector investigation completed");

        std::ostringstream ss;
        ss << "Comprehensive multi-vector investigation completed for target '" << target << "'. "
           << "Executed cross-correlation across " << report.results.size() << " combined service endpoints. "
           << "Review the consolidated dossier below for confirmed links and intelligence markers.";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void ComprehensiveModule::RunInteractive() {
        Console::PrintHeader("COMPREHENSIVE OSINT SCAN [19]");
        std::string target = Console::ReadLine("Enter target entity (Username, Email, Domain, or IP): ");
        if (target.empty()) {
            Console::Warning("No target entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(target);
        Console::Pause();
    }

} // namespace XIII
