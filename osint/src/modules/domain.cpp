#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>
#include <set>

namespace XIII {

    InvestigationReport DomainModule::Execute(const std::string& domain) {
        InvestigationReport report;
        report.moduleName = "Domain";
        report.target = domain;
        report.targetType = "Internet Domain Name";

        Console::Info("Initializing domain intelligence engine");

        // 1. RDAP Domain Registration Information
        Console::Status("RDAP Registry", "Querying registrar and dates");
        ServiceResult rdapRes;
        rdapRes.serviceName = "RDAP Domain Registration";
        std::string rdapUrl = "https://rdap.org/domain/" + domain;
        rdapRes.providerUrl = rdapUrl;
        rdapRes.timestamp = Utils::GetCurrentTimestamp();

        auto rdapHttp = HttpClient::Instance().Get(rdapUrl);
        rdapRes.httpStatus = rdapHttp.statusCode;
        rdapRes.responseTimeMs = rdapHttp.elapsedMilliseconds;

        std::string registrarName = "Unknown";
        if (rdapHttp.statusCode == 200) {
            rdapRes.status = FindingStatus::CONFIRMED;
            auto j = rdapHttp.AsJson();
            std::string ldhName = j.value("ldhName", domain);

            if (j.contains("entities") && j["entities"].is_array()) {
                for (const auto& ent : j["entities"]) {
                    if (ent.contains("roles") && ent["roles"].is_array()) {
                        for (const auto& role : ent["roles"]) {
                            if (role == "registrar") {
                                if (ent.contains("vcardArray")) {
                                    registrarName = ent.value("handle", "Registrar Listed");
                                }
                            }
                        }
                    }
                }
            }

            std::string creationDate, expDate;
            if (j.contains("events") && j["events"].is_array()) {
                for (const auto& ev : j["events"]) {
                    std::string action = ev.value("eventAction", "");
                    std::string date = ev.value("eventDate", "");
                    if (action == "registration") creationDate = date;
                    if (action == "expiration") expDate = date;
                }
            }

            rdapRes.summary = "Domain registered. Registrar: " + registrarName + " | Created: " + creationDate;
            rdapRes.details.push_back({rdapRes.serviceName, "Registration", "Domain Name", ldhName, FindingStatus::CONFIRMED, rdapUrl, 200, ldhName, rdapRes.timestamp});
            if (!creationDate.empty()) rdapRes.details.push_back({rdapRes.serviceName, "Dates", "Creation Date", creationDate, FindingStatus::CONFIRMED, rdapUrl, 200, creationDate, rdapRes.timestamp});
            if (!expDate.empty()) rdapRes.details.push_back({rdapRes.serviceName, "Dates", "Expiration Date", expDate, FindingStatus::CONFIRMED, rdapUrl, 200, expDate, rdapRes.timestamp});
        } else {
            rdapRes.status = FindingStatus::UNAVAILABLE;
            rdapRes.summary = "RDAP query returned HTTP " + std::to_string(rdapHttp.statusCode);
        }
        report.results.push_back(rdapRes);

        // 2. DNS-over-HTTPS Records Resolution
        Console::Status("DNS Resolution", "Resolving A, AAAA, MX, NS, TXT");
        ServiceResult dnsRes;
        dnsRes.serviceName = "DNS-over-HTTPS (Google)";
        dnsRes.providerUrl = "https://dns.google/resolve";
        dnsRes.timestamp = Utils::GetCurrentTimestamp();

        std::vector<std::string> queryTypes = {"A", "AAAA", "MX", "NS", "TXT"};
        int foundRecords = 0;

        for (const auto& type : queryTypes) {
            std::string dohUrl = "https://dns.google/resolve?name=" + Utils::UrlEncode(domain) + "&type=" + type;
            auto res = HttpClient::Instance().Get(dohUrl);
            if (res.statusCode == 200) {
                auto j = res.AsJson();
                if (j.contains("Answer") && j["Answer"].is_array()) {
                    for (const auto& ans : j["Answer"]) {
                        std::string data = ans.value("data", "");
                        if (!data.empty()) {
                            dnsRes.details.push_back({dnsRes.serviceName, "DNS Records", type, data, FindingStatus::CONFIRMED, dohUrl, 200, data, dnsRes.timestamp});
                            foundRecords++;
                        }
                    }
                }
            }
        }

        if (foundRecords > 0) {
            dnsRes.status = FindingStatus::CONFIRMED;
            dnsRes.summary = "Discovered " + std::to_string(foundRecords) + " active DNS resource records.";
        } else {
            dnsRes.status = FindingStatus::NOT_FOUND;
            dnsRes.summary = "No active DNS records returned for target.";
        }
        report.results.push_back(dnsRes);

        // 3. crt.sh Certificate Transparency Subdomain Enumeration
        Console::Status("crt.sh Logs", "Enumerating Certificate Transparency records");
        ServiceResult crtRes;
        crtRes.serviceName = "crt.sh Certificate Transparency";
        std::string crtUrl = "https://crt.sh/?q=%25." + domain + "&output=json";
        crtRes.providerUrl = crtUrl;
        crtRes.timestamp = Utils::GetCurrentTimestamp();

        HttpRequestOptions crtOpts;
        crtOpts.timeoutSeconds = 12;
        auto crtHttp = HttpClient::Instance().Get(crtUrl, crtOpts);
        crtRes.httpStatus = crtHttp.statusCode;
        crtRes.responseTimeMs = crtHttp.elapsedMilliseconds;

        if (crtHttp.statusCode == 200) {
            auto j = crtHttp.AsJson();
            if (j.is_array() && !j.empty()) {
                crtRes.status = FindingStatus::CONFIRMED;
                std::set<std::string> uniqueSubdomains;
                for (const auto& entry : j) {
                    std::string nameValue = entry.value("name_value", "");
                    std::stringstream ss(nameValue);
                    std::string sub;
                    while (std::getline(ss, sub)) {
                        sub = Utils::Trim(sub);
                        if (!sub.empty() && sub.find(domain) != std::string::npos && sub.find('*') == std::string::npos) {
                            uniqueSubdomains.insert(Utils::ToLower(sub));
                        }
                    }
                    if (uniqueSubdomains.size() >= 30) break; // Limit to 30 most recent unique subdomains
                }

                crtRes.summary = "Enumerated " + std::to_string(uniqueSubdomains.size()) + " unique subdomains from public SSL certs.";
                for (const auto& s : uniqueSubdomains) {
                    crtRes.details.push_back({crtRes.serviceName, "Subdomain", "Host", s, FindingStatus::CONFIRMED, crtUrl, 200, s, crtRes.timestamp});
                }
            } else {
                crtRes.status = FindingStatus::NOT_FOUND;
                crtRes.summary = "No certificate logs recorded for domain wildcard.";
            }
        } else {
            crtRes.status = FindingStatus::UNAVAILABLE;
            crtRes.summary = "crt.sh service unavailable (HTTP " + std::to_string(crtHttp.statusCode) + ")";
        }
        report.results.push_back(crtRes);

        // 4. URLhaus Host Threat Check
        Console::Status("URLhaus", "Scanning malware host repository");
        ServiceResult urlhausRes;
        urlhausRes.serviceName = "URLhaus Malware Check";
        std::string uhUrl = "https://urlhaus-api.abuse.ch/v1/host/";
        urlhausRes.providerUrl = uhUrl;
        urlhausRes.timestamp = Utils::GetCurrentTimestamp();

        std::string postPayload = "host=" + Utils::UrlEncode(domain);
        auto uhHttp = HttpClient::Instance().Post(uhUrl, postPayload, "application/x-www-form-urlencoded");
        urlhausRes.httpStatus = uhHttp.statusCode;
        urlhausRes.responseTimeMs = uhHttp.elapsedMilliseconds;

        if (uhHttp.statusCode == 200) {
            auto j = uhHttp.AsJson();
            std::string qStatus = j.value("query_status", "");
            if (qStatus == "ok") {
                urlhausRes.status = FindingStatus::CONFIRMED;
                int urlCount = j.value("url_count", 0);
                urlhausRes.summary = "ALERT: Domain identified in URLhaus malicious repository! Total URLs: " + std::to_string(urlCount);
                urlhausRes.details.push_back({urlhausRes.serviceName, "Threat", "Malware URLs", std::to_string(urlCount), FindingStatus::CONFIRMED, uhUrl, 200, "", urlhausRes.timestamp});
            } else {
                urlhausRes.status = FindingStatus::NOT_FOUND;
                urlhausRes.summary = "Clean: Domain is not listed in URLhaus active threat database.";
            }
        } else {
            urlhausRes.status = FindingStatus::UNAVAILABLE;
            urlhausRes.summary = "URLhaus returned HTTP " + std::to_string(uhHttp.statusCode);
        }
        report.results.push_back(urlhausRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Domain reconnaissance for '" << domain << "' completed. "
           << "Registrar: " << registrarName << ". "
           << "DNS Records: " << foundRecords << " discovered. "
           << "Threat Status: " << (urlhausRes.status == FindingStatus::CONFIRMED ? "THREAT DETECTED" : "Clean in public feeds") << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void DomainModule::RunInteractive() {
        Console::PrintHeader("DOMAIN INTELLIGENCE [05]");
        std::string domain = Console::ReadLine("Enter target domain (e.g. example.com): ");
        if (domain.empty()) {
            Console::Warning("No domain entered. Aborting.");
            Console::Pause();
            return;
        }

        // Clean domain
        if (domain.rfind("http://", 0) == 0) domain = domain.substr(7);
        if (domain.rfind("https://", 0) == 0) domain = domain.substr(8);
        size_t slash = domain.find('/');
        if (slash != std::string::npos) domain = domain.substr(0, slash);

        Execute(domain);
        Console::Pause();
    }

} // namespace XIII
