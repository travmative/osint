#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport WhoisModule::Execute(const std::string& target) {
        InvestigationReport report;
        report.moduleName = "Domain";
        report.target = target;

        bool isIp = (target.find('.') != std::string::npos && isdigit((unsigned char)target[0])) || (target.find(':') != std::string::npos);
        report.targetType = isIp ? "IP Address" : "Domain Name";

        Console::Info("Initializing authoritative RDAP/WHOIS registry query");
        Console::Status("RDAP Federation", "Querying authoritative RFC 7484 endpoint");

        std::string rdapUrl = isIp ? ("https://rdap.org/ip/" + target) : ("https://rdap.org/domain/" + target);

        ServiceResult rdapRes;
        rdapRes.serviceName = "RDAP Registry Federation";
        rdapRes.providerUrl = rdapUrl;
        rdapRes.timestamp = Utils::GetCurrentTimestamp();

        auto resp = HttpClient::Instance().Get(rdapUrl);
        rdapRes.httpStatus = resp.statusCode;
        rdapRes.responseTimeMs = resp.elapsedMilliseconds;

        if (resp.statusCode == 200) {
            rdapRes.status = FindingStatus::CONFIRMED;
            auto j = resp.AsJson();

            std::string handle = j.value("handle", target);
            std::string ldhName = j.value("ldhName", target);
            rdapRes.details.push_back({rdapRes.serviceName, "Object", "Identifier", handle, FindingStatus::CONFIRMED, rdapUrl, 200, handle, rdapRes.timestamp});

            // Nameservers
            if (j.contains("nameservers") && j["nameservers"].is_array()) {
                for (const auto& ns : j["nameservers"]) {
                    std::string nsName = ns.value("ldhName", "");
                    if (!nsName.empty()) {
                        rdapRes.details.push_back({rdapRes.serviceName, "Nameserver", "Host", nsName, FindingStatus::CONFIRMED, rdapUrl, 200, nsName, rdapRes.timestamp});
                    }
                }
            }

            // Status
            if (j.contains("status") && j["status"].is_array()) {
                for (const auto& st : j["status"]) {
                    std::string s = st.get<std::string>();
                    rdapRes.details.push_back({rdapRes.serviceName, "Status", "Code", s, FindingStatus::CONFIRMED, rdapUrl, 200, s, rdapRes.timestamp});
                }
            }

            // Events (Dates)
            std::string crDate, upDate, exDate;
            if (j.contains("events") && j["events"].is_array()) {
                for (const auto& ev : j["events"]) {
                    std::string act = ev.value("eventAction", "");
                    std::string dt = ev.value("eventDate", "");
                    if (act == "registration") crDate = dt;
                    if (act == "last changed" || act == "last update") upDate = dt;
                    if (act == "expiration") exDate = dt;
                    rdapRes.details.push_back({rdapRes.serviceName, "Dates", act, dt, FindingStatus::CONFIRMED, rdapUrl, 200, dt, rdapRes.timestamp});
                }
            }

            rdapRes.summary = "RDAP record retrieved. Registered: " + crDate + " | Expires: " + exDate;
        } else {
            rdapRes.status = FindingStatus::UNAVAILABLE;
            rdapRes.summary = "RDAP query returned HTTP " + std::to_string(resp.statusCode);
        }
        report.results.push_back(rdapRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "RDAP / WHOIS registry intelligence query for '" << target << "' finished. "
           << "Status: " << StatusToString(rdapRes.status);
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void WhoisModule::RunInteractive() {
        Console::PrintHeader("WHOIS / RDAP INTELLIGENCE [12]");
        std::string target = Console::ReadLine("Enter target domain or IP: ");
        if (target.empty()) {
            Console::Warning("No target entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(target);
        Console::Pause();
    }

} // namespace XIII
