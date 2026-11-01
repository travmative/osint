#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <iostream>
#include <sstream>
#include <set>

namespace XIII {

    InvestigationReport GitHubModule::Execute(const std::string& targetUser) {
        InvestigationReport report;
        report.moduleName = "GitHub";
        report.target = targetUser;
        report.targetType = "GitHub Developer Account";

        Console::Info("Initializing deep GitHub intelligence scan");

        HttpRequestOptions opts;
        std::string ghToken = ConfigManager::Instance().GetApiKey("GITHUB_TOKEN");
        if (!ghToken.empty()) {
            opts.headers["Authorization"] = "token " + ghToken;
        }

        // 1. Core Profile
        Console::Status("GitHub Profile", "Querying profile metadata");
        ServiceResult profRes;
        profRes.serviceName = "GitHub REST API Profile";
        std::string profUrl = "https://api.github.com/users/" + targetUser;
        profRes.providerUrl = profUrl;
        profRes.profileUrl = "https://github.com/" + targetUser;
        profRes.timestamp = Utils::GetCurrentTimestamp();

        auto profHttp = HttpClient::Instance().Get(profUrl, opts);
        profRes.httpStatus = profHttp.statusCode;
        profRes.responseTimeMs = profHttp.elapsedMilliseconds;

        if (profHttp.statusCode == 200) {
            profRes.status = FindingStatus::CONFIRMED;
            auto j = profHttp.AsJson();

            std::string name = j.value("name", "");
            std::string bio = j.value("bio", "");
            std::string company = j.value("company", "");
            std::string location = j.value("location", "");
            std::string blog = j.value("blog", "");
            std::string email = j.value("email", "");
            std::string twitter = j.value("twitter_username", "");
            std::string created_at = j.value("created_at", "");
            int repos = j.value("public_repos", 0);
            int followers = j.value("followers", 0);

            profRes.summary = "Active GitHub profile. Name: " + name + " | Repos: " + std::to_string(repos) + " | Followers: " + std::to_string(followers);
            if (!name.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Name", name, FindingStatus::CONFIRMED, profUrl, 200, name, profRes.timestamp});
            if (!email.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Public Email", email, FindingStatus::CONFIRMED, profUrl, 200, email, profRes.timestamp});
            if (!bio.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Bio", bio, FindingStatus::CONFIRMED, profUrl, 200, bio, profRes.timestamp});
            if (!company.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Company", company, FindingStatus::CONFIRMED, profUrl, 200, company, profRes.timestamp});
            if (!location.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Location", location, FindingStatus::CONFIRMED, profUrl, 200, location, profRes.timestamp});
            if (!blog.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Website", blog, FindingStatus::CONFIRMED, profUrl, 200, blog, profRes.timestamp});
            if (!twitter.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Twitter Handle", "@" + twitter, FindingStatus::CONFIRMED, profUrl, 200, twitter, profRes.timestamp});
            if (!created_at.empty()) profRes.details.push_back({profRes.serviceName, "Profile", "Member Since", created_at, FindingStatus::CONFIRMED, profUrl, 200, created_at, profRes.timestamp});
        } else if (profHttp.statusCode == 404) {
            profRes.status = FindingStatus::NOT_FOUND;
            profRes.summary = "User '" + targetUser + "' not found on GitHub.";
        } else {
            profRes.status = FindingStatus::UNAVAILABLE;
            profRes.summary = "GitHub returned HTTP " + std::to_string(profHttp.statusCode);
        }
        report.results.push_back(profRes);

        // 2. Public SSH Keys
        Console::Status("SSH Keys", "Enumerating public SSH key fingerprints");
        ServiceResult sshRes;
        sshRes.serviceName = "GitHub Public SSH Keys";
        std::string sshUrl = "https://github.com/" + targetUser + ".keys";
        sshRes.providerUrl = sshUrl;
        sshRes.timestamp = Utils::GetCurrentTimestamp();

        auto sshHttp = HttpClient::Instance().Get(sshUrl);
        sshRes.httpStatus = sshHttp.statusCode;
        sshRes.responseTimeMs = sshHttp.elapsedMilliseconds;

        if (sshHttp.statusCode == 200 && !sshHttp.body.empty()) {
            sshRes.status = FindingStatus::CONFIRMED;
            std::stringstream ss(sshHttp.body);
            std::string keyLine;
            int keyCount = 0;
            while (std::getline(ss, keyLine)) {
                keyLine = Utils::Trim(keyLine);
                if (!keyLine.empty()) {
                    keyCount++;
                    std::string keyPrefix = keyLine.substr(0, std::min<size_t>(keyLine.length(), 40)) + "...";
                    sshRes.details.push_back({sshRes.serviceName, "Crypto Keys", "SSH Key #" + std::to_string(keyCount), keyPrefix, FindingStatus::CONFIRMED, sshUrl, 200, keyLine, sshRes.timestamp});
                }
            }
            sshRes.summary = "Discovered " + std::to_string(keyCount) + " public SSH authentication keys.";
        } else {
            sshRes.status = FindingStatus::NOT_FOUND;
            sshRes.summary = "No public SSH keys published.";
        }
        report.results.push_back(sshRes);

        // 3. Public Commit Email Discovery (Events)
        Console::Status("Public Commits", "Scanning push events for exposed author emails");
        ServiceResult eventRes;
        eventRes.serviceName = "Commit Event Email Leak Detector";
        std::string eventUrl = "https://api.github.com/users/" + targetUser + "/events/public";
        eventRes.providerUrl = eventUrl;
        eventRes.timestamp = Utils::GetCurrentTimestamp();

        auto eventHttp = HttpClient::Instance().Get(eventUrl, opts);
        eventRes.httpStatus = eventHttp.statusCode;
        eventRes.responseTimeMs = eventHttp.elapsedMilliseconds;

        std::set<std::string> discoveredEmails;
        if (eventHttp.statusCode == 200) {
            auto j = eventHttp.AsJson();
            if (j.is_array()) {
                for (const auto& ev : j) {
                    if (ev.value("type", "") == "PushEvent" && ev.contains("payload") && ev["payload"].contains("commits")) {
                        for (const auto& commit : ev["payload"]["commits"]) {
                            if (commit.contains("author")) {
                                std::string authEmail = commit["author"].value("email", "");
                                std::string authName = commit["author"].value("name", "");
                                if (!authEmail.empty() && authEmail.find("noreply.github.com") == std::string::npos) {
                                    discoveredEmails.insert(authEmail + " (" + authName + ")");
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!discoveredEmails.empty()) {
            eventRes.status = FindingStatus::CONFIRMED;
            eventRes.summary = "Found " + std::to_string(discoveredEmails.size()) + " commit author email(s) in public event stream.";
            for (const auto& em : discoveredEmails) {
                eventRes.details.push_back({eventRes.serviceName, "Identity Leak", "Commit Email", em, FindingStatus::CONFIRMED, eventUrl, 200, em, eventRes.timestamp});
            }
        } else {
            eventRes.status = FindingStatus::NOT_FOUND;
            eventRes.summary = "No non-noreply author emails exposed in recent public commit events.";
        }
        report.results.push_back(eventRes);

        // 4. Repositories
        Console::Status("Repositories", "Analyzing recent repositories");
        ServiceResult repoRes;
        repoRes.serviceName = "Public Repositories";
        std::string repoUrl = "https://api.github.com/users/" + targetUser + "/repos?sort=updated&per_page=5";
        repoRes.providerUrl = repoUrl;
        repoRes.timestamp = Utils::GetCurrentTimestamp();

        auto repoHttp = HttpClient::Instance().Get(repoUrl, opts);
        if (repoHttp.statusCode == 200) {
            auto j = repoHttp.AsJson();
            if (j.is_array() && !j.empty()) {
                repoRes.status = FindingStatus::CONFIRMED;
                repoRes.summary = "Retrieved " + std::to_string(j.size()) + " active repositories.";
                for (const auto& r : j) {
                    std::string rName = r.value("name", "");
                    std::string rLang = r.value("language", "None");
                    int stars = r.value("stargazers_count", 0);
                    repoRes.details.push_back({repoRes.serviceName, "Repository", rName, "Language: " + rLang + " | Stars: " + std::to_string(stars), FindingStatus::CONFIRMED, repoUrl, 200, "", repoRes.timestamp});
                }
            } else {
                repoRes.status = FindingStatus::NOT_FOUND;
                repoRes.summary = "No public repositories found.";
            }
        }
        report.results.push_back(repoRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "GitHub intelligence scan for '" << targetUser << "' finished. "
           << "Profile Status: " << (profRes.status == FindingStatus::CONFIRMED ? "Confirmed Active" : "Not Found") << ". "
           << "Exposed Emails: " << discoveredEmails.size() << " discovered from commits. "
           << "SSH Keys: " << (sshRes.status == FindingStatus::CONFIRMED ? "Published" : "None") << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void GitHubModule::RunInteractive() {
        Console::PrintHeader("GITHUB INTELLIGENCE [08]");
        std::string user = Console::ReadLine("Enter target GitHub username: ");
        if (user.empty()) {
            Console::Warning("No username entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(user);
        Console::Pause();
    }

} // namespace XIII
