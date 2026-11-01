#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport PublicProfileModule::Execute(const std::string& query) {
        InvestigationReport report;
        report.moduleName = "Username";
        report.target = query;
        report.targetType = "Developer / Public Identity";

        Console::Info("Initializing public profile discovery engine");

        // 1. Hacker News User
        Console::Status("Hacker News", "Querying YCombinator Firebase API");
        ServiceResult hnRes;
        hnRes.serviceName = "Hacker News Profile";
        std::string hnUrl = "https://hacker-news.firebaseio.com/v0/user/" + Utils::UrlEncode(query) + ".json";
        hnRes.providerUrl = hnUrl;
        hnRes.timestamp = Utils::GetCurrentTimestamp();

        auto hnResp = HttpClient::Instance().Get(hnUrl);
        hnRes.httpStatus = hnResp.statusCode;
        hnRes.responseTimeMs = hnResp.elapsedMilliseconds;

        if (hnResp.statusCode == 200) {
            auto j = hnResp.AsJson();
            if (!j.is_null() && j.contains("id")) {
                hnRes.status = FindingStatus::CONFIRMED;
                hnRes.profileUrl = "https://news.ycombinator.com/user?id=" + query;
                int karma = j.value("karma", 0);
                std::string about = j.value("about", "");
                hnRes.summary = "Confirmed Hacker News user. Karma: " + std::to_string(karma);
                hnRes.details.push_back({hnRes.serviceName, "Profile", "Karma", std::to_string(karma), FindingStatus::CONFIRMED, hnUrl, 200, std::to_string(karma), hnRes.timestamp});
                if (!about.empty()) hnRes.details.push_back({hnRes.serviceName, "Profile", "About", about, FindingStatus::CONFIRMED, hnUrl, 200, about, hnRes.timestamp});
            } else {
                hnRes.status = FindingStatus::NOT_FOUND;
                hnRes.summary = "User not found in Hacker News records.";
            }
        }
        report.results.push_back(hnRes);

        // 2. Keybase Identity
        Console::Status("Keybase", "Querying cryptographic identity graph");
        ServiceResult kbRes;
        kbRes.serviceName = "Keybase Directory";
        std::string kbUrl = "https://keybase.io/_/api/1.0/user/lookup.json?usernames=" + Utils::UrlEncode(query);
        kbRes.providerUrl = kbUrl;
        kbRes.timestamp = Utils::GetCurrentTimestamp();

        auto kbResp = HttpClient::Instance().Get(kbUrl);
        kbRes.httpStatus = kbResp.statusCode;
        kbRes.responseTimeMs = kbResp.elapsedMilliseconds;

        if (kbResp.statusCode == 200) {
            auto j = kbResp.AsJson();
            if (j.contains("them") && !j["them"].empty() && !j["them"][0].is_null()) {
                kbRes.status = FindingStatus::CONFIRMED;
                kbRes.profileUrl = "https://keybase.io/" + query;
                kbRes.summary = "Confirmed Keybase cryptographic profile.";
                kbRes.details.push_back({kbRes.serviceName, "Identity", "Profile URL", kbRes.profileUrl, FindingStatus::CONFIRMED, kbUrl, 200, kbRes.profileUrl, kbRes.timestamp});
            } else {
                kbRes.status = FindingStatus::NOT_FOUND;
                kbRes.summary = "Identity not found on Keybase.";
            }
        }
        report.results.push_back(kbRes);

        // 3. PyPI Package Index Check
        Console::Status("PyPI Registry", "Checking Python package ecosystem");
        ServiceResult pypiRes;
        pypiRes.serviceName = "PyPI Package Registry";
        std::string pypiUrl = "https://pypi.org/pypi/" + Utils::UrlEncode(query) + "/json";
        pypiRes.providerUrl = pypiUrl;
        pypiRes.timestamp = Utils::GetCurrentTimestamp();

        auto pypiResp = HttpClient::Instance().Get(pypiUrl);
        if (pypiResp.statusCode == 200) {
            auto j = pypiResp.AsJson();
            if (j.contains("info")) {
                pypiRes.status = FindingStatus::CONFIRMED;
                std::string author = j["info"].value("author", "");
                std::string authorEmail = j["info"].value("author_email", "");
                std::string summary = j["info"].value("summary", "");
                pypiRes.profileUrl = "https://pypi.org/project/" + query;
                pypiRes.summary = "Active Python package found. Author: " + author;
                if (!author.empty()) pypiRes.details.push_back({pypiRes.serviceName, "Package", "Author", author, FindingStatus::CONFIRMED, pypiUrl, 200, author, pypiRes.timestamp});
                if (!authorEmail.empty()) pypiRes.details.push_back({pypiRes.serviceName, "Package", "Author Email", authorEmail, FindingStatus::CONFIRMED, pypiUrl, 200, authorEmail, pypiRes.timestamp});
            }
        } else {
            pypiRes.status = FindingStatus::NOT_FOUND;
            pypiRes.summary = "No matching PyPI package found.";
        }
        report.results.push_back(pypiRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Public developer profile discovery for '" << query << "' complete.";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void PublicProfileModule::RunInteractive() {
        Console::PrintHeader("PUBLIC PROFILE DISCOVERY [17]");
        std::string query = Console::ReadLine("Enter username or project handle: ");
        if (query.empty()) {
            Console::Warning("No query entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(query);
        Console::Pause();
    }

} // namespace XIII
