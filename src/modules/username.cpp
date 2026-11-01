#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <thread>

namespace XIII {

    struct UsernameTargetService {
        std::string name;
        std::string urlTemplate;
        std::string checkType; // "status", "json_field", "regex"
        std::string successCondition;
        std::string category;
    };

    static const std::vector<UsernameTargetService> USERNAME_SERVICES = {
        {"GitHub", "https://api.github.com/users/{}", "status", "200", "Code & Dev"},
        {"GitLab", "https://gitlab.com/api/v4/users?username={}", "json_field", "id", "Code & Dev"},
        {"Reddit", "https://www.reddit.com/user/{}/about.json", "status", "200", "Social"},
        {"Bluesky", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social", "status", "200", "Social"},
        {"Mastodon", "https://mastodon.social/api/v1/accounts/lookup?acct={}", "status", "200", "Fediverse"},
        {"Gravatar", "https://gravatar.com/{}.json", "status", "200", "Identity"},
        {"Hacker News", "https://hacker-news.firebaseio.com/v0/user/{}.json", "json_field", "id", "Tech Community"},
        {"Codeberg", "https://codeberg.org/api/v1/users/{}", "status", "200", "Code & Dev"},
        {"DEV Community", "https://dev.to/api/users/by_username?url={}", "status", "200", "Blogging & Dev"},
        {"Docker Hub", "https://hub.docker.com/v2/users/{}/", "status", "200", "Containers & Dev"},
        {"NPM", "https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1", "status", "200", "Package Repos"},
        {"SourceForge", "https://sourceforge.net/rest/u/{}/profile", "status", "200", "Open Source"},
        {"Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "json_field", "them", "Crypto & Identity"},
        {"Medium", "https://medium.com/@{}", "status", "200", "Publishing"},
        {"Tumblr", "https://{}.tumblr.com", "status", "200", "Blogging"},
        {"Pinterest", "https://www.pinterest.com/{}/", "status", "200", "Creative & Media"},
        {"Flickr", "https://www.flickr.com/people/{}/", "status", "200", "Photography"},
        {"Steam", "https://steamcommunity.com/id/{}", "status", "200", "Gaming"},
        {"Twitch", "https://www.twitch.tv/{}", "status", "200", "Streaming"},
        {"YouTube", "https://www.youtube.com/@{}", "status", "200", "Video"},
        {"Product Hunt", "https://www.producthunt.com/@{}", "status", "200", "Product Community"},
        {"Kaggle", "https://www.kaggle.com/{}", "status", "200", "Data Science"},
        {"Hugging Face", "https://huggingface.co/api/users/{}/overview", "status", "200", "AI & ML"},
        {"TikTok", "https://www.tiktok.com/@{}", "status", "200", "Social Video"},
        {"Instagram", "https://www.instagram.com/{}/", "status", "200", "Social Photos"},
        {"X / Twitter", "https://x.com/{}", "status", "200", "Microblogging"},
        {"Roblox", "https://users.roblox.com/v1/usernames/users", "roblox_api", "roblox", "Gaming"}
    };

    InvestigationReport UsernameModule::Execute(const std::string& username) {
        InvestigationReport report;
        report.moduleName = "Username";
        report.target = username;
        report.targetType = "Handle / Username";

        Console::Info("Initializing investigation engine");
        Console::Info("Loading API registry and target profiles");

        ThreadPool pool(10);
        std::vector<std::future<ServiceResult>> futures;

        for (const auto& svc : USERNAME_SERVICES) {
            Console::Status(svc.name, "Searching");

            futures.push_back(pool.Enqueue([svc, username]() -> ServiceResult {
                ServiceResult sr;
                sr.serviceName = svc.name;
                sr.timestamp = Utils::GetCurrentTimestamp();

                // Format URL
                std::string targetUrl;
                size_t placeholder = svc.urlTemplate.find("{}");
                if (placeholder != std::string::npos) {
                    targetUrl = svc.urlTemplate.substr(0, placeholder) + username + svc.urlTemplate.substr(placeholder + 2);
                } else {
                    targetUrl = svc.urlTemplate;
                }
                sr.providerUrl = targetUrl;
                sr.profileUrl = targetUrl;

                HttpRequestOptions opts;
                opts.timeoutSeconds = 8;
                opts.maxRetries = 1;
                opts.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
                opts.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8";

                HttpResponse resp;
                if (svc.checkType == "roblox_api") {
                    std::string payload = "{\"usernames\":[\"" + username + "\"],\"excludeBannedUsers\":false}";
                    resp = HttpClient::Instance().Post(targetUrl, payload, "application/json", opts);
                } else {
                    resp = HttpClient::Instance().Get(targetUrl, opts);
                }

                sr.httpStatus = resp.statusCode;
                sr.responseTimeMs = resp.elapsedMilliseconds;

                if (resp.statusCode == 429) {
                    sr.status = FindingStatus::RATE_LIMITED;
                    sr.summary = "Target server returned HTTP 429 Rate Limited.";
                    return sr;
                }

                if (resp.statusCode >= 500) {
                    sr.status = FindingStatus::UNAVAILABLE;
                    sr.summary = "Remote service unavailable (HTTP " + std::to_string(resp.statusCode) + ").";
                    return sr;
                }

                if (svc.name == "GitHub" && resp.statusCode == 200) {
                    sr.status = FindingStatus::CONFIRMED;
                    sr.profileUrl = "https://github.com/" + username;
                    auto j = resp.AsJson();
                    if (!j.is_null()) {
                        std::string name = j.value("name", "");
                        std::string bio = j.value("bio", "");
                        std::string company = j.value("company", "");
                        std::string location = j.value("location", "");
                        std::string blog = j.value("blog", "");
                        std::string created_at = j.value("created_at", "");
                        int repos = j.value("public_repos", 0);
                        int followers = j.value("followers", 0);

                        sr.summary = "Confirmed active GitHub profile. Repos: " + std::to_string(repos) + ", Followers: " + std::to_string(followers);
                        if (!name.empty()) sr.details.push_back({svc.name, "Profile", "Name", name, FindingStatus::CONFIRMED, targetUrl, 200, name, sr.timestamp});
                        if (!bio.empty()) sr.details.push_back({svc.name, "Profile", "Bio", bio, FindingStatus::CONFIRMED, targetUrl, 200, bio, sr.timestamp});
                        if (!location.empty()) sr.details.push_back({svc.name, "Profile", "Location", location, FindingStatus::CONFIRMED, targetUrl, 200, location, sr.timestamp});
                        if (!company.empty()) sr.details.push_back({svc.name, "Profile", "Company", company, FindingStatus::CONFIRMED, targetUrl, 200, company, sr.timestamp});
                        if (!blog.empty()) sr.details.push_back({svc.name, "Profile", "Website", blog, FindingStatus::CONFIRMED, targetUrl, 200, blog, sr.timestamp});
                        if (!created_at.empty()) sr.details.push_back({svc.name, "Profile", "Member Since", created_at, FindingStatus::CONFIRMED, targetUrl, 200, created_at, sr.timestamp});
                    }
                } else if (svc.name == "GitLab") {
                    auto j = resp.AsJson();
                    if (j.is_array() && !j.empty()) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://gitlab.com/" + username;
                        auto first = j[0];
                        std::string name = first.value("name", "");
                        sr.summary = "Confirmed active GitLab profile (" + name + ").";
                        sr.details.push_back({svc.name, "Profile", "Display Name", name, FindingStatus::CONFIRMED, targetUrl, 200, name, sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "Username not registered on GitLab.";
                    }
                } else if (svc.name == "Reddit" && resp.statusCode == 200) {
                    auto j = resp.AsJson();
                    if (j.contains("data") && !j["data"].value("is_suspended", false)) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://www.reddit.com/user/" + username;
                        int karma = j["data"].value("total_karma", 0);
                        sr.summary = "Confirmed active Reddit user. Total Karma: " + std::to_string(karma);
                        sr.details.push_back({svc.name, "Profile", "Karma", std::to_string(karma), FindingStatus::CONFIRMED, targetUrl, 200, "", sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "User not found or suspended on Reddit.";
                    }
                } else if (svc.name == "Hacker News") {
                    auto j = resp.AsJson();
                    if (!j.is_null() && j.contains("id")) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://news.ycombinator.com/user?id=" + username;
                        int karma = j.value("karma", 0);
                        sr.summary = "Confirmed active Hacker News profile. Karma: " + std::to_string(karma);
                        sr.details.push_back({svc.name, "Profile", "Karma", std::to_string(karma), FindingStatus::CONFIRMED, targetUrl, 200, "", sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "Username not found in Hacker News records.";
                    }
                } else if (svc.name == "Gravatar" && resp.statusCode == 200) {
                    sr.status = FindingStatus::CONFIRMED;
                    sr.profileUrl = "https://gravatar.com/" + username;
                    sr.summary = "Confirmed public Gravatar profile.";
                } else if (svc.name == "Bluesky" && resp.statusCode == 200) {
                    sr.status = FindingStatus::CONFIRMED;
                    sr.profileUrl = "https://bsky.app/profile/" + username + ".bsky.social";
                    auto j = resp.AsJson();
                    std::string disp = j.value("displayName", "");
                    std::string desc = j.value("description", "");
                    sr.summary = "Confirmed active Bluesky handle (@" + username + ".bsky.social).";
                    if (!disp.empty()) sr.details.push_back({svc.name, "Profile", "Display Name", disp, FindingStatus::CONFIRMED, targetUrl, 200, disp, sr.timestamp});
                    if (!desc.empty()) sr.details.push_back({svc.name, "Profile", "Bio", desc, FindingStatus::CONFIRMED, targetUrl, 200, desc, sr.timestamp});
                } else if (svc.name == "Keybase") {
                    auto j = resp.AsJson();
                    if (j.contains("them") && !j["them"].is_null() && !j["them"].empty()) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://keybase.io/" + username;
                        sr.summary = "Confirmed active Keybase identity.";
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "Handle not registered on Keybase.";
                    }
                } else if (svc.name == "DEV Community" && resp.statusCode == 200) {
                    auto j = resp.AsJson();
                    if (j.contains("username")) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://dev.to/" + username;
                        std::string name = j.value("name", "");
                        std::string summary = j.value("summary", "");
                        sr.summary = "Confirmed active DEV Community profile (" + name + ").";
                        if (!summary.empty()) sr.details.push_back({svc.name, "Profile", "Summary", summary, FindingStatus::CONFIRMED, targetUrl, 200, summary, sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                    }
                } else if (svc.name == "Docker Hub" && resp.statusCode == 200) {
                    auto j = resp.AsJson();
                    if (j.contains("username") || j.contains("id")) {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.profileUrl = "https://hub.docker.com/u/" + username;
                        std::string fullname = j.value("full_name", "");
                        sr.summary = "Confirmed active Docker Hub repository account.";
                        if (!fullname.empty()) sr.details.push_back({svc.name, "Profile", "Full Name", fullname, FindingStatus::CONFIRMED, targetUrl, 200, fullname, sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                    }
                } else if (svc.name == "Roblox") {
                    auto j = resp.AsJson();
                    if (j.contains("data") && j["data"].is_array() && !j["data"].empty()) {
                        sr.status = FindingStatus::CONFIRMED;
                        int id = j["data"][0].value("id", 0);
                        sr.profileUrl = "https://www.roblox.com/users/" + std::to_string(id) + "/profile";
                        sr.summary = "Confirmed active Roblox player ID: " + std::to_string(id);
                        sr.details.push_back({svc.name, "Profile", "User ID", std::to_string(id), FindingStatus::CONFIRMED, targetUrl, 200, "", sr.timestamp});
                    } else {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "Handle not found on Roblox.";
                    }
                } else if (resp.statusCode == 200) {
                    // Check if response contains typical 404 text in 200 OK (soft 404s)
                    std::string bodyLower = Utils::ToLower(resp.body);
                    if (bodyLower.find("not found") != std::string::npos && bodyLower.length() < 3000) {
                        sr.status = FindingStatus::NOT_FOUND;
                        sr.summary = "Service returned soft-404 page.";
                    } else {
                        sr.status = FindingStatus::CONFIRMED;
                        sr.summary = "Public profile located at " + targetUrl;
                    }
                } else if (resp.statusCode == 404) {
                    sr.status = FindingStatus::NOT_FOUND;
                    sr.summary = "Profile does not exist on " + svc.name + ".";
                } else {
                    sr.status = FindingStatus::UNVERIFIED;
                    sr.summary = "Response received with HTTP status " + std::to_string(resp.statusCode);
                }

                return sr;
            }));
        }

        // Collect results
        for (auto& f : futures) {
            report.results.push_back(f.get());
        }

        Console::Success("Investigation completed");

        // Format executive summary
        std::ostringstream execSummary;
        execSummary << "Reconnaissance scan for target handle '" << username << "' executed across "
                    << report.results.size() << " major public platforms. ";
        
        int hits = 0;
        for (const auto& r : report.results) {
            if (r.status == FindingStatus::CONFIRMED) hits++;
        }

        if (hits > 0) {
            execSummary << "Discovered " << hits << " confirmed active profile(s) with matching identity. "
                        << "Review corroborated metadata in the service breakdown below.";
        } else {
            execSummary << "No confirmed active public accounts were identified with this exact handle on queried services.";
        }
        report.executiveSummary = execSummary.str();

        // Generate TXT report file
        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        // Display ONLY the final report information prominently
        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void UsernameModule::RunInteractive() {
        Console::PrintHeader("USERNAME INTELLIGENCE [01]");
        std::string username = Console::ReadLine("Enter target username to investigate: ");
        if (username.empty()) {
            Console::Warning("No target entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(username);
        Console::Pause();
    }

} // namespace XIII
