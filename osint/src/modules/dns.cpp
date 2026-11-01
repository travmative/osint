#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport DnsModule::Execute(const std::string& domain) {
        InvestigationReport report;
        report.moduleName = "DNS";
        report.target = domain;
        report.targetType = "Domain / Hostname";

        Console::Info("Initializing comprehensive DNS intelligence resolver");

        std::vector<std::string> recordTypes = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"};

        int totalFound = 0;
        for (const auto& rType : recordTypes) {
            Console::Status("DNS " + rType, "Querying DNS-over-HTTPS");
            ServiceResult sRes;
            sRes.serviceName = "DoH Record [" + rType + "]";
            std::string qUrl = "https://dns.google/resolve?name=" + Utils::UrlEncode(domain) + "&type=" + rType;
            sRes.providerUrl = qUrl;
            sRes.timestamp = Utils::GetCurrentTimestamp();

            auto resp = HttpClient::Instance().Get(qUrl);
            sRes.httpStatus = resp.statusCode;
            sRes.responseTimeMs = resp.elapsedMilliseconds;

            if (resp.statusCode == 200) {
                auto j = resp.AsJson();
                bool dnssec = j.value("AD", false); // Authenticated Data
                if (j.contains("Answer") && j["Answer"].is_array() && !j["Answer"].empty()) {
                    sRes.status = FindingStatus::CONFIRMED;
                    std::vector<std::string> records;
                    for (const auto& ans : j["Answer"]) {
                        std::string d = ans.value("data", "");
                        if (!d.empty()) {
                            records.push_back(d);
                            sRes.details.push_back({sRes.serviceName, "Record", rType, d, FindingStatus::CONFIRMED, qUrl, 200, d, sRes.timestamp});
                            totalFound++;
                        }
                    }
                    sRes.summary = "Resolved " + std::to_string(records.size()) + " record(s). DNSSEC: " + (dnssec ? "Verified (AD flag set)" : "Unsigned / Inactive");
                } else {
                    sRes.status = FindingStatus::NOT_FOUND;
                    sRes.summary = "No " + rType + " records returned (NXDOMAIN / NODATA).";
                }
            } else {
                sRes.status = FindingStatus::UNAVAILABLE;
                sRes.summary = "DNS query returned HTTP " + std::to_string(resp.statusCode);
            }
            report.results.push_back(sRes);
        }

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "DNS analysis for '" << domain << "' finished. "
           << "Discovered a total of " << totalFound << " active resource records across "
           << recordTypes.size() << " queried record types.";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void DnsModule::RunInteractive() {
        Console::PrintHeader("DNS INTELLIGENCE [11]");
        std::string domain = Console::ReadLine("Enter target domain for DNS inspection: ");
        if (domain.empty()) {
            Console::Warning("No domain entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(domain);
        Console::Pause();
    }

} // namespace XIII
