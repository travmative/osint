#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport ThreatIntelModule::Execute(const std::string& indicator) {
        InvestigationReport report;
        report.moduleName = "Threat";
        report.target = indicator;
        report.targetType = "Threat Indicator / CVE";

        Console::Info("Initializing threat intelligence correlation engine");

        // 1. CISA Known Exploited Vulnerabilities Check
        if (indicator.rfind("CVE-", 0) == 0 || indicator.rfind("cve-", 0) == 0) {
            Console::Status("CISA KEV Catalog", "Searching US CISA Known Exploited Vulnerabilities");
            ServiceResult cisaRes;
            cisaRes.serviceName = "CISA KEV Database";
            std::string cisaUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
            cisaRes.providerUrl = cisaUrl;
            cisaRes.timestamp = Utils::GetCurrentTimestamp();

            auto resp = HttpClient::Instance().Get(cisaUrl);
            cisaRes.httpStatus = resp.statusCode;
            cisaRes.responseTimeMs = resp.elapsedMilliseconds;

            if (resp.statusCode == 200) {
                auto j = resp.AsJson();
                bool found = false;
                if (j.contains("vulnerabilities") && j["vulnerabilities"].is_array()) {
                    std::string upperTarget = Utils::ToUpper(indicator);
                    for (const auto& v : j["vulnerabilities"]) {
                        std::string cveId = v.value("cveID", "");
                        if (cveId == upperTarget) {
                            found = true;
                            cisaRes.status = FindingStatus::CONFIRMED;
                            std::string vendor = v.value("vendorProject", "");
                            std::string product = v.value("product", "");
                            std::string vulnName = v.value("vulnerabilityName", "");
                            std::string dateAdded = v.value("dateAdded", "");
                            std::string action = v.value("requiredAction", "");

                            cisaRes.summary = "CONFIRMED EXPLOITED IN WILD: " + vendor + " " + product + " - " + vulnName;
                            cisaRes.details.push_back({cisaRes.serviceName, "CISA KEV", "Vendor", vendor, FindingStatus::CONFIRMED, cisaUrl, 200, vendor, cisaRes.timestamp});
                            cisaRes.details.push_back({cisaRes.serviceName, "CISA KEV", "Product", product, FindingStatus::CONFIRMED, cisaUrl, 200, product, cisaRes.timestamp});
                            cisaRes.details.push_back({cisaRes.serviceName, "CISA KEV", "Date Added", dateAdded, FindingStatus::CONFIRMED, cisaUrl, 200, dateAdded, cisaRes.timestamp});
                            cisaRes.details.push_back({cisaRes.serviceName, "CISA KEV", "Required Action", action, FindingStatus::CONFIRMED, cisaUrl, 200, action, cisaRes.timestamp});
                            break;
                        }
                    }
                }

                if (!found) {
                    cisaRes.status = FindingStatus::NOT_FOUND;
                    cisaRes.summary = "Vulnerability is not listed in active CISA KEV catalog.";
                }
            } else {
                cisaRes.status = FindingStatus::UNAVAILABLE;
                cisaRes.summary = "CISA feed returned HTTP " + std::to_string(resp.statusCode);
            }
            report.results.push_back(cisaRes);
        } else {
            // General IOC Check in ThreatFox
            Console::Status("ThreatFox IOC", "Querying open threat indicators");
            ServiceResult tfRes;
            tfRes.serviceName = "ThreatFox IOC Search";
            tfRes.providerUrl = "https://threatfox-api.abuse.ch/v1/";
            tfRes.timestamp = Utils::GetCurrentTimestamp();

            nlohmann::json tfQuery;
            tfQuery["query"] = "search_ioc";
            tfQuery["search_term"] = indicator;
            auto tfResp = HttpClient::Instance().Post(tfRes.providerUrl, tfQuery.dump());
            tfRes.httpStatus = tfResp.statusCode;
            tfRes.responseTimeMs = tfResp.elapsedMilliseconds;

            if (tfResp.statusCode == 200) {
                auto j = tfResp.AsJson();
                if (j.value("query_status", "") == "ok" && j.contains("data") && j["data"].is_array() && !j["data"].empty()) {
                    tfRes.status = FindingStatus::CONFIRMED;
                    auto ioc = j["data"][0];
                    std::string malware = ioc.value("malware_printable", "Unknown Threat");
                    std::string threatType = ioc.value("threat_type", "");
                    tfRes.summary = "THREAT IOC CONFIRMED: " + malware + " (" + threatType + ")";
                    tfRes.details.push_back({tfRes.serviceName, "Threat", "Malware", malware, FindingStatus::CONFIRMED, tfRes.providerUrl, 200, malware, tfRes.timestamp});
                } else {
                    tfRes.status = FindingStatus::NOT_FOUND;
                    tfRes.summary = "Indicator not registered as active threat in ThreatFox.";
                }
            } else {
                tfRes.status = FindingStatus::UNAVAILABLE;
                tfRes.summary = "ThreatFox returned HTTP " + std::to_string(tfResp.statusCode);
            }
            report.results.push_back(tfRes);
        }

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Threat intelligence lookup for indicator '" << indicator << "' finished.";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void ThreatIntelModule::RunInteractive() {
        Console::PrintHeader("THREAT INTELLIGENCE [16]");
        std::string indicator = Console::ReadLine("Enter indicator (IP, Domain, Hash, or CVE ID like CVE-2023-38606): ");
        if (indicator.empty()) {
            Console::Warning("No indicator entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(indicator);
        Console::Pause();
    }

} // namespace XIII
