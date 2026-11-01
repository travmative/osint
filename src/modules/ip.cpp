#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport IpModule::Execute(const std::string& ip) {
        InvestigationReport report;
        report.moduleName = "IP";
        report.target = ip;
        report.targetType = (ip.find(':') != std::string::npos) ? "IPv6 Address" : "IPv4 Address";

        Console::Info("Initializing multi-source IP intelligence engine");

        // 1. IP-API Geolocation & Network Provider
        Console::Status("IP-API", "Querying geolocation and ASN");
        ServiceResult ipApiRes;
        ipApiRes.serviceName = "IP-API Geolocation";
        std::string ipApiUrl = "http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query";
        ipApiRes.providerUrl = ipApiUrl;
        ipApiRes.timestamp = Utils::GetCurrentTimestamp();

        auto ipApiHttp = HttpClient::Instance().Get(ipApiUrl);
        ipApiRes.httpStatus = ipApiHttp.statusCode;
        ipApiRes.responseTimeMs = ipApiHttp.elapsedMilliseconds;

        std::string country, city, asn, isp, org;
        if (ipApiHttp.statusCode == 200) {
            auto j = ipApiHttp.AsJson();
            if (j.value("status", "") == "success") {
                ipApiRes.status = FindingStatus::CONFIRMED;
                country = j.value("country", "");
                city = j.value("city", "");
                asn = j.value("as", "");
                isp = j.value("isp", "");
                org = j.value("org", "");
                double lat = j.value("lat", 0.0);
                double lon = j.value("lon", 0.0);
                std::string timezone = j.value("timezone", "");

                ipApiRes.summary = "Resolved: " + city + ", " + country + " | " + asn + " (" + isp + ")";
                ipApiRes.details.push_back({ipApiRes.serviceName, "Geo", "Country", country, FindingStatus::CONFIRMED, ipApiUrl, 200, country, ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Geo", "City", city, FindingStatus::CONFIRMED, ipApiUrl, 200, city, ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Geo", "Coordinates", std::to_string(lat) + ", " + std::to_string(lon), FindingStatus::CONFIRMED, ipApiUrl, 200, "", ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Geo", "Timezone", timezone, FindingStatus::CONFIRMED, ipApiUrl, 200, timezone, ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Network", "ASN", asn, FindingStatus::CONFIRMED, ipApiUrl, 200, asn, ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Network", "ISP", isp, FindingStatus::CONFIRMED, ipApiUrl, 200, isp, ipApiRes.timestamp});
                ipApiRes.details.push_back({ipApiRes.serviceName, "Network", "Organization", org, FindingStatus::CONFIRMED, ipApiUrl, 200, org, ipApiRes.timestamp});
            } else {
                ipApiRes.status = FindingStatus::NOT_FOUND;
                ipApiRes.summary = "IP-API returned fail: " + j.value("message", "unknown error");
            }
        } else {
            ipApiRes.status = FindingStatus::UNAVAILABLE;
            ipApiRes.summary = "Service returned HTTP " + std::to_string(ipApiHttp.statusCode);
        }
        report.results.push_back(ipApiRes);

        // 2. ipwho.is Metadata & Threat Flags
        Console::Status("ipwho.is", "Querying security and connection attributes");
        ServiceResult ipwhoRes;
        ipwhoRes.serviceName = "ipwho.is Threat Engine";
        std::string ipwhoUrl = "https://ipwho.is/" + ip;
        ipwhoRes.providerUrl = ipwhoUrl;
        ipwhoRes.timestamp = Utils::GetCurrentTimestamp();

        auto ipwhoHttp = HttpClient::Instance().Get(ipwhoUrl);
        ipwhoRes.httpStatus = ipwhoHttp.statusCode;
        ipwhoRes.responseTimeMs = ipwhoHttp.elapsedMilliseconds;

        if (ipwhoHttp.statusCode == 200) {
            auto j = ipwhoHttp.AsJson();
            if (j.value("success", false)) {
                ipwhoRes.status = FindingStatus::CONFIRMED;
                ipwhoRes.summary = "Successfully retrieved security metadata.";
                if (j.contains("connection")) {
                    auto conn = j["connection"];
                    std::string connAsn = std::to_string(conn.value("asn", 0));
                    std::string connOrg = conn.value("org", "");
                    std::string connIsp = conn.value("isp", "");
                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Network", "BGP ASN", connAsn, FindingStatus::CONFIRMED, ipwhoUrl, 200, connAsn, ipwhoRes.timestamp});
                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Network", "Carrier Org", connOrg, FindingStatus::CONFIRMED, ipwhoUrl, 200, connOrg, ipwhoRes.timestamp});
                }
                if (j.contains("security")) {
                    auto sec = j["security"];
                    bool isVpn = sec.value("vpn", false);
                    bool isProxy = sec.value("proxy", false);
                    bool isTor = sec.value("tor", false);
                    bool isHosting = sec.value("hosting", false);

                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Security", "VPN", isVpn ? "TRUE" : "FALSE", FindingStatus::CONFIRMED, ipwhoUrl, 200, "", ipwhoRes.timestamp});
                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Security", "Proxy", isProxy ? "TRUE" : "FALSE", FindingStatus::CONFIRMED, ipwhoUrl, 200, "", ipwhoRes.timestamp});
                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Security", "Tor Exit", isTor ? "TRUE" : "FALSE", FindingStatus::CONFIRMED, ipwhoUrl, 200, "", ipwhoRes.timestamp});
                    ipwhoRes.details.push_back({ipwhoRes.serviceName, "Security", "Datacenter/Hosting", isHosting ? "TRUE" : "FALSE", FindingStatus::CONFIRMED, ipwhoUrl, 200, "", ipwhoRes.timestamp});
                }
            } else {
                ipwhoRes.status = FindingStatus::NOT_FOUND;
                ipwhoRes.summary = "Target not found in ipwho.is dataset.";
            }
        } else {
            ipwhoRes.status = FindingStatus::UNAVAILABLE;
            ipwhoRes.summary = "Service returned HTTP " + std::to_string(ipwhoHttp.statusCode);
        }
        report.results.push_back(ipwhoRes);

        // 3. BGPView IP Routing & Prefix
        Console::Status("BGPView", "Querying BGP prefixes and routing tables");
        ServiceResult bgpRes;
        bgpRes.serviceName = "BGPView Routing Data";
        std::string bgpUrl = "https://api.bgpview.io/ip/" + ip;
        bgpRes.providerUrl = bgpUrl;
        bgpRes.timestamp = Utils::GetCurrentTimestamp();

        auto bgpHttp = HttpClient::Instance().Get(bgpUrl);
        bgpRes.httpStatus = bgpHttp.statusCode;
        bgpRes.responseTimeMs = bgpHttp.elapsedMilliseconds;

        if (bgpHttp.statusCode == 200) {
            auto j = bgpHttp.AsJson();
            if (j.value("status", "") == "ok" && j.contains("data")) {
                bgpRes.status = FindingStatus::CONFIRMED;
                auto data = j["data"];
                std::string ptrRecord = data.value("ptr_record", "None");
                bgpRes.summary = "PTR: " + ptrRecord;
                bgpRes.details.push_back({bgpRes.serviceName, "DNS", "Reverse DNS (PTR)", ptrRecord, FindingStatus::CONFIRMED, bgpUrl, 200, ptrRecord, bgpRes.timestamp});

                if (data.contains("prefixes") && data["prefixes"].is_array() && !data["prefixes"].empty()) {
                    std::string pfx = data["prefixes"][0].value("prefix", "");
                    bgpRes.details.push_back({bgpRes.serviceName, "BGP", "Announced Prefix", pfx, FindingStatus::CONFIRMED, bgpUrl, 200, pfx, bgpRes.timestamp});
                }
            } else {
                bgpRes.status = FindingStatus::NOT_FOUND;
                bgpRes.summary = "No active BGP routing data found.";
            }
        } else {
            bgpRes.status = FindingStatus::UNAVAILABLE;
            bgpRes.summary = "BGPView returned HTTP " + std::to_string(bgpHttp.statusCode);
        }
        report.results.push_back(bgpRes);

        // 4. AbuseIPDB (if API key present)
        Console::Status("AbuseIPDB", "Checking crowdsourced abuse reports");
        ServiceResult abuseRes;
        abuseRes.serviceName = "AbuseIPDB Threat Intelligence";
        abuseRes.providerUrl = "https://api.abuseipdb.com/api/v2/check";
        abuseRes.timestamp = Utils::GetCurrentTimestamp();

        std::string abuseKey = ConfigManager::Instance().GetApiKey("ABUSEIPDB_API_KEY");
        if (!abuseKey.empty()) {
            HttpRequestOptions aOpts;
            aOpts.headers["Key"] = abuseKey;
            aOpts.headers["Accept"] = "application/json";
            std::string aUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + Utils::UrlEncode(ip) + "&maxAgeInDays=90&verbose";
            auto aHttp = HttpClient::Instance().Get(aUrl, aOpts);
            abuseRes.httpStatus = aHttp.statusCode;
            abuseRes.responseTimeMs = aHttp.elapsedMilliseconds;

            if (aHttp.statusCode == 200) {
                abuseRes.status = FindingStatus::CONFIRMED;
                auto j = aHttp.AsJson();
                if (j.contains("data")) {
                    int score = j["data"].value("abuseConfidenceScore", 0);
                    int totalReports = j["data"].value("totalReports", 0);
                    std::string usageType = j["data"].value("usageType", "Unknown");

                    abuseRes.summary = "Abuse Confidence Score: " + std::to_string(score) + "% (" + std::to_string(totalReports) + " reports)";
                    abuseRes.details.push_back({abuseRes.serviceName, "Reputation", "Abuse Score", std::to_string(score) + "%", FindingStatus::CONFIRMED, aUrl, 200, "", abuseRes.timestamp});
                    abuseRes.details.push_back({abuseRes.serviceName, "Reputation", "Total Reports", std::to_string(totalReports), FindingStatus::CONFIRMED, aUrl, 200, "", abuseRes.timestamp});
                    abuseRes.details.push_back({abuseRes.serviceName, "Reputation", "Usage Type", usageType, FindingStatus::CONFIRMED, aUrl, 200, usageType, abuseRes.timestamp});
                }
            } else {
                abuseRes.status = FindingStatus::UNAVAILABLE;
                abuseRes.summary = "AbuseIPDB returned HTTP " + std::to_string(aHttp.statusCode);
            }
        } else {
            abuseRes.status = FindingStatus::UNVERIFIED;
            abuseRes.summary = "No AbuseIPDB API key configured. Public community lookups skipped.";
        }
        report.results.push_back(abuseRes);

        // 5. RDAP Universal Registry Check
        Console::Status("RDAP Registry", "Querying authoritative RIR allocation");
        ServiceResult rdapRes;
        rdapRes.serviceName = "RDAP Universal Registry";
        std::string rdapUrl = "https://rdap.org/ip/" + ip;
        rdapRes.providerUrl = rdapUrl;
        rdapRes.timestamp = Utils::GetCurrentTimestamp();

        auto rdapHttp = HttpClient::Instance().Get(rdapUrl);
        rdapRes.httpStatus = rdapHttp.statusCode;
        rdapRes.responseTimeMs = rdapHttp.elapsedMilliseconds;

        if (rdapHttp.statusCode == 200) {
            rdapRes.status = FindingStatus::CONFIRMED;
            auto j = rdapHttp.AsJson();
            std::string netName = j.value("name", "Unknown Network");
            std::string startIp = j.value("startAddress", "");
            std::string endIp = j.value("endAddress", "");

            rdapRes.summary = "Network: " + netName + " (" + startIp + " - " + endIp + ")";
            rdapRes.details.push_back({rdapRes.serviceName, "Registry", "NetName", netName, FindingStatus::CONFIRMED, rdapUrl, 200, netName, rdapRes.timestamp});
            if (!startIp.empty()) rdapRes.details.push_back({rdapRes.serviceName, "Registry", "Range", startIp + " - " + endIp, FindingStatus::CONFIRMED, rdapUrl, 200, "", rdapRes.timestamp});
        } else {
            rdapRes.status = FindingStatus::UNAVAILABLE;
            rdapRes.summary = "RDAP returned HTTP " + std::to_string(rdapHttp.statusCode);
        }
        report.results.push_back(rdapRes);

        Console::Success("Investigation completed");

        // Format executive summary
        std::ostringstream ss;
        ss << "IP intelligence examination for " << ip << " complete. "
           << "Location: " << city << ", " << country << ". "
           << "Autonomous System: " << asn << " (" << isp << "). "
           << "Network: " << org << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void IpModule::RunInteractive() {
        Console::PrintHeader("IP ADDRESS INTELLIGENCE [04]");
        std::string ip = Console::ReadLine("Enter target IP address (e.g. 1.1.1.1 or 8.8.8.8): ");
        if (ip.empty()) {
            Console::Warning("No IP address entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(ip);
        Console::Pause();
    }

} // namespace XIII
