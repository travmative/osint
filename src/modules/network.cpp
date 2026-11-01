#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport NetworkModule::Execute(const std::string& asnOrPrefix) {
        InvestigationReport report;
        report.moduleName = "IP";
        report.target = asnOrPrefix;
        report.targetType = "Autonomous System / BGP Prefix";

        Console::Info("Initializing BGP & network routing intelligence engine");

        std::string cleanAsn = asnOrPrefix;
        if (cleanAsn.rfind("AS", 0) == 0 || cleanAsn.rfind("as", 0) == 0) {
            cleanAsn = cleanAsn.substr(2);
        }

        Console::Status("BGPView ASN", "Querying global routing table and peers");
        ServiceResult asnRes;
        asnRes.serviceName = "BGPView Autonomous System";
        std::string bgpUrl = "https://api.bgpview.io/asn/" + cleanAsn;
        asnRes.providerUrl = bgpUrl;
        asnRes.timestamp = Utils::GetCurrentTimestamp();

        auto resp = HttpClient::Instance().Get(bgpUrl);
        asnRes.httpStatus = resp.statusCode;
        asnRes.responseTimeMs = resp.elapsedMilliseconds;

        if (resp.statusCode == 200) {
            auto j = resp.AsJson();
            if (j.value("status", "") == "ok" && j.contains("data")) {
                asnRes.status = FindingStatus::CONFIRMED;
                auto data = j["data"];
                std::string name = data.value("name", "Unknown ASN");
                std::string desc = data.value("description_short", "");
                std::string country = data.value("country_code", "");
                std::string registry = data.value("rir_name", "");

                asnRes.summary = "AS" + cleanAsn + " - " + name + " (" + country + ") | RIR: " + registry;
                asnRes.details.push_back({asnRes.serviceName, "ASN", "Number", "AS" + cleanAsn, FindingStatus::CONFIRMED, bgpUrl, 200, cleanAsn, asnRes.timestamp});
                asnRes.details.push_back({asnRes.serviceName, "ASN", "Name", name, FindingStatus::CONFIRMED, bgpUrl, 200, name, asnRes.timestamp});
                asnRes.details.push_back({asnRes.serviceName, "ASN", "Description", desc, FindingStatus::CONFIRMED, bgpUrl, 200, desc, asnRes.timestamp});
                asnRes.details.push_back({asnRes.serviceName, "ASN", "Country", country, FindingStatus::CONFIRMED, bgpUrl, 200, country, asnRes.timestamp});
                asnRes.details.push_back({asnRes.serviceName, "ASN", "Allocated By", registry, FindingStatus::CONFIRMED, bgpUrl, 200, registry, asnRes.timestamp});
            } else {
                asnRes.status = FindingStatus::NOT_FOUND;
                asnRes.summary = "No routing records found for ASN: " + cleanAsn;
            }
        } else {
            asnRes.status = FindingStatus::UNAVAILABLE;
            asnRes.summary = "BGPView returned HTTP " + std::to_string(resp.statusCode);
        }
        report.results.push_back(asnRes);

        // Prefixes lookup
        Console::Status("BGP Prefixes", "Querying IPv4/IPv6 prefix announcements");
        ServiceResult pfxRes;
        pfxRes.serviceName = "BGP Announced Prefixes";
        std::string pfxUrl = "https://api.bgpview.io/asn/" + cleanAsn + "/prefixes";
        pfxRes.providerUrl = pfxUrl;
        pfxRes.timestamp = Utils::GetCurrentTimestamp();

        auto pfxHttp = HttpClient::Instance().Get(pfxUrl);
        if (pfxHttp.statusCode == 200) {
            auto j = pfxHttp.AsJson();
            if (j.value("status", "") == "ok" && j.contains("data") && j["data"].contains("ipv4_prefixes")) {
                pfxRes.status = FindingStatus::CONFIRMED;
                auto pfxList = j["data"]["ipv4_prefixes"];
                pfxRes.summary = "Announces " + std::to_string(pfxList.size()) + " IPv4 prefix(es).";
                int count = 0;
                for (const auto& p : pfxList) {
                    std::string prefixStr = p.value("prefix", "");
                    std::string desc = p.value("description", "");
                    pfxRes.details.push_back({pfxRes.serviceName, "Prefix", prefixStr, desc, FindingStatus::CONFIRMED, pfxUrl, 200, prefixStr, pfxRes.timestamp});
                    if (++count >= 15) break;
                }
            } else {
                pfxRes.status = FindingStatus::NOT_FOUND;
                pfxRes.summary = "No active prefix announcements recorded.";
            }
        }
        report.results.push_back(pfxRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Network routing intelligence for AS" << cleanAsn << " finished. "
           << "Status: " << StatusToString(asnRes.status) << " | " << asnRes.summary;
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void NetworkModule::RunInteractive() {
        Console::PrintHeader("NETWORK INTELLIGENCE [13]");
        std::string asn = Console::ReadLine("Enter target ASN (e.g. AS15169 or 13335): ");
        if (asn.empty()) {
            Console::Warning("No ASN entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(asn);
        Console::Pause();
    }

} // namespace XIII
