#pragma once

#include <string>
#include "common.hpp"

namespace XIII {

    class UsernameModule {
    public:
        static InvestigationReport Execute(const std::string& username);
        static void RunInteractive();
    };

    class EmailModule {
    public:
        static InvestigationReport Execute(const std::string& email);
        static void RunInteractive();
    };

    class PhoneModule {
    public:
        static InvestigationReport Execute(const std::string& phone);
        static void RunInteractive();
    };

    class IpModule {
    public:
        static InvestigationReport Execute(const std::string& ip);
        static void RunInteractive();
    };

    class DomainModule {
    public:
        static InvestigationReport Execute(const std::string& domain);
        static void RunInteractive();
    };

    class WebsiteModule {
    public:
        static InvestigationReport Execute(const std::string& targetUrl);
        static void RunInteractive();
    };

    class DiscordModule {
    public:
        static InvestigationReport Execute(const std::string& snowflakeId);
        static void RunInteractive();
    };

    class GitHubModule {
    public:
        static InvestigationReport Execute(const std::string& targetUser);
        static void RunInteractive();
    };

    class SocialModule {
    public:
        static InvestigationReport Execute(const std::string& handle);
        static void RunInteractive();
    };

    class BreachModule {
    public:
        static InvestigationReport Execute(const std::string& accountOrDomain);
        static void RunInteractive();
    };

    class DnsModule {
    public:
        static InvestigationReport Execute(const std::string& domain);
        static void RunInteractive();
    };

    class WhoisModule {
    public:
        static InvestigationReport Execute(const std::string& target);
        static void RunInteractive();
    };

    class NetworkModule {
    public:
        static InvestigationReport Execute(const std::string& asnOrPrefix);
        static void RunInteractive();
    };

    class UrlReputationModule {
    public:
        static InvestigationReport Execute(const std::string& url);
        static void RunInteractive();
    };

    class FileHashModule {
    public:
        static InvestigationReport Execute(const std::string& hashOrFilePath);
        static void RunInteractive();
    };

    class ThreatIntelModule {
    public:
        static InvestigationReport Execute(const std::string& indicator);
        static void RunInteractive();
    };

    class PublicProfileModule {
    public:
        static InvestigationReport Execute(const std::string& query);
        static void RunInteractive();
    };

    class SearchEngineModule {
    public:
        static InvestigationReport Execute(const std::string& target);
        static void RunInteractive();
    };

    class ComprehensiveModule {
    public:
        static InvestigationReport Execute(const std::string& target);
        static void RunInteractive();
    };

    class ReportManagerModule {
    public:
        static void RunInteractive();
    };

    class ApiStatusModule {
    public:
        static void RunInteractive();
    };

    class SettingsModule {
    public:
        static void RunInteractive();
    };

} // namespace XIII
