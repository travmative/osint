#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport WebsiteModule::Execute(const std::string& targetUrl) {
        InvestigationReport report;
        report.moduleName = "Website";
        report.target = targetUrl;
        report.targetType = "Web Application / URL";

        Console::Info("Initializing website inspection engine");

        std::string fullUrl = targetUrl;
        if (fullUrl.rfind("http://", 0) != 0 && fullUrl.rfind("https://", 0) != 0) {
            fullUrl = "https://" + fullUrl;
        }

        // 1. Root HTTP Response & Header Analysis
        Console::Status("HTTP Inspection", "Analyzing response headers and server banner");
        ServiceResult headerRes;
        headerRes.serviceName = "HTTP Headers & Server Banner";
        headerRes.providerUrl = fullUrl;
        headerRes.timestamp = Utils::GetCurrentTimestamp();

        HttpRequestOptions opts;
        opts.timeoutSeconds = 10;
        opts.followRedirects = true;
        auto httpResp = HttpClient::Instance().Get(fullUrl, opts);

        headerRes.httpStatus = httpResp.statusCode;
        headerRes.responseTimeMs = httpResp.elapsedMilliseconds;

        if (httpResp.statusCode > 0) {
            headerRes.status = FindingStatus::CONFIRMED;
            std::string server = httpResp.headers.count("server") ? httpResp.headers.at("server") : (httpResp.headers.count("Server") ? httpResp.headers.at("Server") : "Not Disclosed");
            std::string poweredBy = httpResp.headers.count("x-powered-by") ? httpResp.headers.at("x-powered-by") : (httpResp.headers.count("X-Powered-By") ? httpResp.headers.at("X-Powered-By") : "None");

            headerRes.summary = "HTTP " + std::to_string(httpResp.statusCode) + " | Server: " + server + " | Powered-By: " + poweredBy;
            headerRes.details.push_back({headerRes.serviceName, "Server", "Server Banner", server, FindingStatus::CONFIRMED, fullUrl, httpResp.statusCode, server, headerRes.timestamp});
            if (poweredBy != "None") headerRes.details.push_back({headerRes.serviceName, "Server", "X-Powered-By", poweredBy, FindingStatus::CONFIRMED, fullUrl, httpResp.statusCode, poweredBy, headerRes.timestamp});

            // Security Headers
            Console::Status("Security Headers", "Auditing defense-in-depth posture");
            std::vector<std::string> secHeaders = {
                "strict-transport-security", "content-security-policy", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy"
            };

            for (const auto& sh : secHeaders) {
                bool found = false;
                std::string val;
                for (const auto& [hk, hv] : httpResp.headers) {
                    if (Utils::ToLower(hk) == sh) {
                        found = true;
                        val = hv;
                        break;
                    }
                }
                headerRes.details.push_back({headerRes.serviceName, "Security Headers", sh, found ? val : "MISSING", found ? FindingStatus::CONFIRMED : FindingStatus::POTENTIAL, fullUrl, httpResp.statusCode, "", headerRes.timestamp});
            }
        } else {
            headerRes.status = FindingStatus::UNAVAILABLE;
            headerRes.summary = "Failed to establish connection: " + httpResp.errorMessage;
        }
        report.results.push_back(headerRes);

        // 2. Robots.txt Analysis
        Console::Status("robots.txt", "Inspecting search engine crawling rules");
        ServiceResult robotsRes;
        robotsRes.serviceName = "Robots.txt Crawl Directive";
        std::string robotsUrl = fullUrl + "/robots.txt";
        robotsRes.providerUrl = robotsUrl;
        robotsRes.timestamp = Utils::GetCurrentTimestamp();

        auto robotsHttp = HttpClient::Instance().Get(robotsUrl, opts);
        robotsRes.httpStatus = robotsHttp.statusCode;
        robotsRes.responseTimeMs = robotsHttp.elapsedMilliseconds;

        if (robotsHttp.statusCode == 200 && !robotsHttp.body.empty() && robotsHttp.body.find("Disallow:") != std::string::npos) {
            robotsRes.status = FindingStatus::CONFIRMED;
            robotsRes.summary = "Found active robots.txt file with crawling directives.";
            robotsRes.rawData = robotsHttp.body.substr(0, 1024);
        } else {
            robotsRes.status = FindingStatus::NOT_FOUND;
            robotsRes.summary = "robots.txt not present or returned non-200 status.";
        }
        report.results.push_back(robotsRes);

        // 3. Wayback Machine Historical Snapshots
        Console::Status("Wayback Machine", "Checking historical internet archive snapshots");
        ServiceResult archiveRes;
        archiveRes.serviceName = "Internet Archive Wayback Machine";
        std::string wbUrl = "https://archive.org/wayback/available?url=" + Utils::UrlEncode(fullUrl);
        archiveRes.providerUrl = wbUrl;
        archiveRes.timestamp = Utils::GetCurrentTimestamp();

        auto wbHttp = HttpClient::Instance().Get(wbUrl, opts);
        archiveRes.httpStatus = wbHttp.statusCode;
        archiveRes.responseTimeMs = wbHttp.elapsedMilliseconds;

        if (wbHttp.statusCode == 200) {
            auto j = wbHttp.AsJson();
            if (j.contains("archived_snapshots") && j["archived_snapshots"].contains("closest")) {
                auto closest = j["archived_snapshots"]["closest"];
                bool available = closest.value("available", false);
                std::string snapUrl = closest.value("url", "");
                std::string snapTs = closest.value("timestamp", "");

                if (available) {
                    archiveRes.status = FindingStatus::CONFIRMED;
                    archiveRes.profileUrl = snapUrl;
                    archiveRes.summary = "Archived snapshot located from " + snapTs;
                    archiveRes.details.push_back({archiveRes.serviceName, "Archive", "Snapshot URL", snapUrl, FindingStatus::CONFIRMED, wbUrl, 200, snapUrl, archiveRes.timestamp});
                    archiveRes.details.push_back({archiveRes.serviceName, "Archive", "Snapshot Timestamp", snapTs, FindingStatus::CONFIRMED, wbUrl, 200, snapTs, archiveRes.timestamp});
                } else {
                    archiveRes.status = FindingStatus::NOT_FOUND;
                    archiveRes.summary = "No snapshots available in Wayback repository.";
                }
            } else {
                archiveRes.status = FindingStatus::NOT_FOUND;
                archiveRes.summary = "Target not archived.";
            }
        } else {
            archiveRes.status = FindingStatus::UNAVAILABLE;
            archiveRes.summary = "Wayback API returned HTTP " + std::to_string(wbHttp.statusCode);
        }
        report.results.push_back(archiveRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Website reconnaissance for " << fullUrl << " completed. "
           << "HTTP Status: " << httpResp.statusCode << ". "
           << "Robots.txt: " << (robotsRes.status == FindingStatus::CONFIRMED ? "Present" : "Not Found") << ". "
           << "Archival Snapshots: " << (archiveRes.status == FindingStatus::CONFIRMED ? "Available" : "None") << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void WebsiteModule::RunInteractive() {
        Console::PrintHeader("WEBSITE INTELLIGENCE [06]");
        std::string url = Console::ReadLine("Enter target website URL (e.g. https://example.com): ");
        if (url.empty()) {
            Console::Warning("No URL entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(url);
        Console::Pause();
    }

} // namespace XIII
