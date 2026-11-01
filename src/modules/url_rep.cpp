#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport UrlReputationModule::Execute(const std::string& url) {
        InvestigationReport report;
        report.moduleName = "Threat";
        report.target = url;
        report.targetType = "Uniform Resource Locator (URL)";

        Console::Info("Initializing URL threat & reputation scanner");

        // 1. URLhaus Query
        Console::Status("URLhaus", "Searching malicious payload URL database");
        ServiceResult uhRes;
        uhRes.serviceName = "URLhaus Malware Feed";
        uhRes.providerUrl = "https://urlhaus-api.abuse.ch/v1/url/";
        uhRes.timestamp = Utils::GetCurrentTimestamp();

        std::string uhPost = "url=" + Utils::UrlEncode(url);
        auto uhResp = HttpClient::Instance().Post(uhRes.providerUrl, uhPost, "application/x-www-form-urlencoded");
        uhRes.httpStatus = uhResp.statusCode;
        uhRes.responseTimeMs = uhResp.elapsedMilliseconds;

        if (uhResp.statusCode == 200) {
            auto j = uhResp.AsJson();
            std::string qStatus = j.value("query_status", "");
            if (qStatus == "ok") {
                uhRes.status = FindingStatus::CONFIRMED;
                std::string urlStatus = j.value("url_status", "unknown");
                std::string threat = j.value("threat", "malware_download");
                std::string reporter = j.value("reporter", "");
                uhRes.summary = "MALICIOUS URL DETECTED: Status=" + urlStatus + ", Threat=" + threat;
                uhRes.details.push_back({uhRes.serviceName, "Threat", "Status", urlStatus, FindingStatus::CONFIRMED, uhRes.providerUrl, 200, urlStatus, uhRes.timestamp});
                uhRes.details.push_back({uhRes.serviceName, "Threat", "Payload Classification", threat, FindingStatus::CONFIRMED, uhRes.providerUrl, 200, threat, uhRes.timestamp});
                if (!reporter.empty()) uhRes.details.push_back({uhRes.serviceName, "Threat", "Reported By", reporter, FindingStatus::CONFIRMED, uhRes.providerUrl, 200, reporter, uhRes.timestamp});
            } else {
                uhRes.status = FindingStatus::NOT_FOUND;
                uhRes.summary = "URL is clean in URLhaus malicious repository.";
            }
        } else {
            uhRes.status = FindingStatus::UNAVAILABLE;
            uhRes.summary = "URLhaus returned HTTP " + std::to_string(uhResp.statusCode);
        }
        report.results.push_back(uhRes);

        // 2. ThreatFox IOC Search
        Console::Status("ThreatFox", "Querying open Indicators of Compromise (IOC)");
        ServiceResult tfRes;
        tfRes.serviceName = "ThreatFox IOC Database";
        tfRes.providerUrl = "https://threatfox-api.abuse.ch/v1/";
        tfRes.timestamp = Utils::GetCurrentTimestamp();

        nlohmann::json tfQuery;
        tfQuery["query"] = "search_ioc";
        tfQuery["search_term"] = url;
        auto tfResp = HttpClient::Instance().Post(tfRes.providerUrl, tfQuery.dump());
        tfRes.httpStatus = tfResp.statusCode;
        tfRes.responseTimeMs = tfResp.elapsedMilliseconds;

        if (tfResp.statusCode == 200) {
            auto j = tfResp.AsJson();
            if (j.value("query_status", "") == "ok" && j.contains("data") && j["data"].is_array() && !j["data"].empty()) {
                tfRes.status = FindingStatus::CONFIRMED;
                auto firstIoc = j["data"][0];
                std::string threatType = firstIoc.value("threat_type", "");
                std::string malware = firstIoc.value("malware_printable", "");
                tfRes.summary = "CONFIRMED IOC: " + malware + " (" + threatType + ")";
                tfRes.details.push_back({tfRes.serviceName, "Threat", "Malware Family", malware, FindingStatus::CONFIRMED, tfRes.providerUrl, 200, malware, tfRes.timestamp});
            } else {
                tfRes.status = FindingStatus::NOT_FOUND;
                tfRes.summary = "No associated Indicators of Compromise found in ThreatFox.";
            }
        } else {
            tfRes.status = FindingStatus::UNAVAILABLE;
            tfRes.summary = "ThreatFox returned HTTP " + std::to_string(tfResp.statusCode);
        }
        report.results.push_back(tfRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "URL reputation check for " << url << " finished. "
           << "Threat Status: " << ((uhRes.status == FindingStatus::CONFIRMED || tfRes.status == FindingStatus::CONFIRMED) ? "ALERT: KNOWN MALICIOUS URL" : "No malicious detections in public threat repositories.");
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void UrlReputationModule::RunInteractive() {
        Console::PrintHeader("URL REPUTATION INTELLIGENCE [14]");
        std::string url = Console::ReadLine("Enter target URL: ");
        if (url.empty()) {
            Console::Warning("No URL entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(url);
        Console::Pause();
    }

} // namespace XIII
