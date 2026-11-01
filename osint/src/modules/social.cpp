#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <sstream>

namespace XIII {

    InvestigationReport SocialModule::Execute(const std::string& handle) {
        InvestigationReport report;
        report.moduleName = "Social";
        report.target = handle;
        report.targetType = "Social Media Handle";

        Console::Info("Initializing cross-platform social intelligence correlator");

        // 1. Bluesky AT Protocol
        Console::Status("Bluesky", "Querying AT Protocol public actor");
        ServiceResult bskyRes;
        bskyRes.serviceName = "Bluesky (AT Protocol)";
        std::string bskyUrl = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=" + Utils::UrlEncode(handle + ".bsky.social");
        bskyRes.providerUrl = bskyUrl;
        bskyRes.timestamp = Utils::GetCurrentTimestamp();

        auto bskyHttp = HttpClient::Instance().Get(bskyUrl);
        bskyRes.httpStatus = bskyHttp.statusCode;
        bskyRes.responseTimeMs = bskyHttp.elapsedMilliseconds;

        if (bskyHttp.statusCode == 200) {
            bskyRes.status = FindingStatus::CONFIRMED;
            auto j = bskyHttp.AsJson();
            std::string disp = j.value("displayName", "");
            std::string desc = j.value("description", "");
            int followers = j.value("followersCount", 0);
            int follows = j.value("followsCount", 0);
            int posts = j.value("postsCount", 0);

            bskyRes.profileUrl = "https://bsky.app/profile/" + handle + ".bsky.social";
            bskyRes.summary = "Confirmed active Bluesky identity. Posts: " + std::to_string(posts) + " | Followers: " + std::to_string(followers);
            if (!disp.empty()) bskyRes.details.push_back({bskyRes.serviceName, "Profile", "Display Name", disp, FindingStatus::CONFIRMED, bskyUrl, 200, disp, bskyRes.timestamp});
            if (!desc.empty()) bskyRes.details.push_back({bskyRes.serviceName, "Profile", "Bio", desc, FindingStatus::CONFIRMED, bskyUrl, 200, desc, bskyRes.timestamp});
            bskyRes.details.push_back({bskyRes.serviceName, "Stats", "Followers", std::to_string(followers), FindingStatus::CONFIRMED, bskyUrl, 200, "", bskyRes.timestamp});
        } else {
            bskyRes.status = FindingStatus::NOT_FOUND;
            bskyRes.summary = "Handle @" + handle + ".bsky.social not registered on Bluesky.";
        }
        report.results.push_back(bskyRes);

        // 2. Mastodon Fediverse
        Console::Status("Mastodon", "Querying fediverse instance directory");
        ServiceResult mastRes;
        mastRes.serviceName = "Mastodon (mastodon.social)";
        std::string mastUrl = "https://mastodon.social/api/v1/accounts/lookup?acct=" + Utils::UrlEncode(handle);
        mastRes.providerUrl = mastUrl;
        mastRes.timestamp = Utils::GetCurrentTimestamp();

        auto mastHttp = HttpClient::Instance().Get(mastUrl);
        mastRes.httpStatus = mastHttp.statusCode;
        mastRes.responseTimeMs = mastHttp.elapsedMilliseconds;

        if (mastHttp.statusCode == 200) {
            mastRes.status = FindingStatus::CONFIRMED;
            auto j = mastHttp.AsJson();
            std::string disp = j.value("display_name", "");
            std::string note = j.value("note", "");
            mastRes.profileUrl = j.value("url", "https://mastodon.social/@" + handle);
            mastRes.summary = "Confirmed active Fediverse identity: " + disp;
            if (!disp.empty()) mastRes.details.push_back({mastRes.serviceName, "Profile", "Display Name", disp, FindingStatus::CONFIRMED, mastUrl, 200, disp, mastRes.timestamp});
        } else {
            mastRes.status = FindingStatus::NOT_FOUND;
            mastRes.summary = "Account not found on flagship mastodon.social instance.";
        }
        report.results.push_back(mastRes);

        // 3. Reddit
        Console::Status("Reddit", "Querying public user endpoint");
        ServiceResult redRes;
        redRes.serviceName = "Reddit Profile API";
        std::string redUrl = "https://www.reddit.com/user/" + handle + "/about.json";
        redRes.providerUrl = redUrl;
        redRes.timestamp = Utils::GetCurrentTimestamp();

        auto redHttp = HttpClient::Instance().Get(redUrl);
        redRes.httpStatus = redHttp.statusCode;
        redRes.responseTimeMs = redHttp.elapsedMilliseconds;

        if (redHttp.statusCode == 200) {
            auto j = redHttp.AsJson();
            if (j.contains("data") && !j["data"].value("is_suspended", false)) {
                redRes.status = FindingStatus::CONFIRMED;
                redRes.profileUrl = "https://www.reddit.com/user/" + handle;
                int totalKarma = j["data"].value("total_karma", 0);
                redRes.summary = "Active Reddit account. Karma: " + std::to_string(totalKarma);
                redRes.details.push_back({redRes.serviceName, "Stats", "Karma", std::to_string(totalKarma), FindingStatus::CONFIRMED, redUrl, 200, "", redRes.timestamp});
            } else {
                redRes.status = FindingStatus::NOT_FOUND;
                redRes.summary = "Reddit user not found or suspended.";
            }
        } else {
            redRes.status = FindingStatus::NOT_FOUND;
            redRes.summary = "User does not exist on Reddit.";
        }
        report.results.push_back(redRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "Cross-platform social media intelligence for '" << handle << "' completed. "
           << "Bluesky: " << (bskyRes.status == FindingStatus::CONFIRMED ? "Found" : "Not Found") << " | "
           << "Mastodon: " << (mastRes.status == FindingStatus::CONFIRMED ? "Found" : "Not Found") << " | "
           << "Reddit: " << (redRes.status == FindingStatus::CONFIRMED ? "Found" : "Not Found") << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void SocialModule::RunInteractive() {
        Console::PrintHeader("SOCIAL MEDIA INTELLIGENCE [09]");
        std::string handle = Console::ReadLine("Enter target social media handle: ");
        if (handle.empty()) {
            Console::Warning("No handle entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(handle);
        Console::Pause();
    }

} // namespace XIII
