#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <iostream>
#include <regex>
#include <set>

namespace XIII {

    static const std::set<std::string> DISPOSABLE_EMAIL_DOMAINS = {
        "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
        "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
        "getairmail.com", "dispostable.com", "mailcatch.com", "inboxkitten.com",
        "temp-mail.org", "fakeinbox.com", "generator.email", "nada.ltd",
        "crazymailing.com", "mohmal.com", "mytemp.email", "burnermail.io",
        "tempinbox.com", "dayrep.com", "teleworm.us", "armyspy.com"
    };

    static std::string ClassifyEmailProvider(const std::string& domain, const std::string& mxData) {
        std::string d = Utils::ToLower(domain);
        std::string mx = Utils::ToLower(mxData);

        if (d == "gmail.com" || mx.find("google.com") != std::string::npos || mx.find("googlemail.com") != std::string::npos) {
            return (d == "gmail.com") ? "Google Consumer (Gmail)" : "Google Workspace (Enterprise)";
        }
        if (d == "outlook.com" || d == "hotmail.com" || d == "live.com" || mx.find("outlook.com") != std::string::npos) {
            return (d.find("outlook") != std::string::npos || d.find("hotmail") != std::string::npos) ? "Microsoft Consumer (Outlook/Hotmail)" : "Microsoft 365 / Exchange Online (Enterprise)";
        }
        if (d == "proton.me" || d == "protonmail.com" || mx.find("protonmail.ch") != std::string::npos) {
            return "Proton AG (Encrypted Mail)";
        }
        if (d == "yahoo.com" || mx.find("yahoodns.net") != std::string::npos) {
            return "Yahoo Mail Infrastructure";
        }
        if (d == "icloud.com" || mx.find("icloud.com") != std::string::npos) {
            return "Apple iCloud Mail";
        }
        if (mx.find("zoho.com") != std::string::npos) {
            return "Zoho Mail Infrastructure";
        }
        if (mx.find("fastmail.com") != std::string::npos) {
            return "Fastmail Pty Ltd";
        }
        return "Self-Hosted or Custom Domain Mailserver";
    }

    InvestigationReport EmailModule::Execute(const std::string& email) {
        InvestigationReport report;
        report.moduleName = "Email";
        report.target = email;
        report.targetType = "Email Address";

        Console::Info("Initializing email reconnaissance pipeline");
        Console::Status("Email Syntax", "Validating");

        // 1. Syntax Validation
        std::regex emailRegex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
        bool validSyntax = std::regex_match(email, emailRegex);

        ServiceResult syntaxRes;
        syntaxRes.serviceName = "Syntax Validator";
        syntaxRes.providerUrl = "RFC 5322 Standard";
        syntaxRes.timestamp = Utils::GetCurrentTimestamp();

        if (!validSyntax) {
            syntaxRes.status = FindingStatus::CONFIRMED;
            syntaxRes.summary = "Email syntax is INVALID according to RFC 5322 specifications.";
            report.results.push_back(syntaxRes);
            Console::Error("Email format is invalid.");
        } else {
            syntaxRes.status = FindingStatus::CONFIRMED;
            syntaxRes.summary = "Email syntax is VALID (conforms to RFC 5322).";
            report.results.push_back(syntaxRes);
        }

        // Domain extraction
        size_t atPos = email.find('@');
        std::string localPart = (atPos != std::string::npos) ? email.substr(0, atPos) : "";
        std::string domain = (atPos != std::string::npos) ? email.substr(atPos + 1) : "";

        // 2. Disposable Email Check
        Console::Status("Disposable Check", "Analyzing domain classification");
        ServiceResult dispRes;
        dispRes.serviceName = "Disposable Domain Detector";
        dispRes.providerUrl = "Local Threat Registry";
        dispRes.timestamp = Utils::GetCurrentTimestamp();

        if (DISPOSABLE_EMAIL_DOMAINS.count(Utils::ToLower(domain))) {
            dispRes.status = FindingStatus::CONFIRMED;
            dispRes.summary = "ALERT: Domain '" + domain + "' is a known disposable/temporary email provider.";
            dispRes.details.push_back({"Disposable Detector", "Risk", "Disposable", "TRUE", FindingStatus::CONFIRMED, "", 0, "", dispRes.timestamp});
        } else {
            dispRes.status = FindingStatus::CONFIRMED;
            dispRes.summary = "Domain is not listed in active disposable email registries.";
            dispRes.details.push_back({"Disposable Detector", "Risk", "Disposable", "FALSE", FindingStatus::CONFIRMED, "", 0, "", dispRes.timestamp});
        }
        report.results.push_back(dispRes);

        // 3. MX Record Lookup via Google DoH
        Console::Status("DNS MX Resolution", "Querying mail exchange servers");
        ServiceResult mxRes;
        mxRes.serviceName = "DNS MX Lookup";
        mxRes.providerUrl = "https://dns.google/resolve";
        mxRes.timestamp = Utils::GetCurrentTimestamp();

        std::string mxUrl = "https://dns.google/resolve?name=" + Utils::UrlEncode(domain) + "&type=MX";
        auto mxHttp = HttpClient::Instance().Get(mxUrl);
        mxRes.httpStatus = mxHttp.statusCode;
        mxRes.responseTimeMs = mxHttp.elapsedMilliseconds;

        std::string mxRecordsSummary;
        if (mxHttp.statusCode == 200) {
            auto j = mxHttp.AsJson();
            if (j.contains("Answer") && j["Answer"].is_array() && !j["Answer"].empty()) {
                mxRes.status = FindingStatus::CONFIRMED;
                std::vector<std::string> mxHosts;
                for (const auto& ans : j["Answer"]) {
                    if (ans.contains("data")) {
                        std::string d = ans["data"].get<std::string>();
                        mxHosts.push_back(d);
                        mxRes.details.push_back({"MX Record", "DNS", "MX", d, FindingStatus::CONFIRMED, mxUrl, 200, d, mxRes.timestamp});
                    }
                }
                mxRecordsSummary = !mxHosts.empty() ? mxHosts[0] : "";
                mxRes.summary = "Domain has " + std::to_string(mxHosts.size()) + " active MX record(s). Domain is capable of receiving mail.";
            } else {
                mxRes.status = FindingStatus::NOT_FOUND;
                mxRes.summary = "No MX records found for domain '" + domain + "'. Mail cannot be delivered.";
            }
        } else {
            mxRes.status = FindingStatus::UNAVAILABLE;
            mxRes.summary = "DoH resolver returned status " + std::to_string(mxHttp.statusCode);
        }
        report.results.push_back(mxRes);

        // 4. Provider Classification
        Console::Status("Provider Analysis", "Identifying email infrastructure");
        ServiceResult provRes;
        provRes.serviceName = "Mail Infrastructure Analysis";
        provRes.providerUrl = "Heuristic Classifier";
        provRes.timestamp = Utils::GetCurrentTimestamp();
        provRes.status = FindingStatus::CONFIRMED;
        std::string providerName = ClassifyEmailProvider(domain, mxRecordsSummary);
        provRes.summary = "Email service managed by: " + providerName;
        provRes.details.push_back({"Provider", "Infrastructure", "Classification", providerName, FindingStatus::CONFIRMED, "", 0, "", provRes.timestamp});
        report.results.push_back(provRes);

        // 5. SPF & DMARC Policy Lookups
        Console::Status("SPF / DMARC Security", "Verifying email authentication policies");
        ServiceResult secRes;
        secRes.serviceName = "Email Security Policies";
        secRes.providerUrl = "https://dns.google/resolve";
        secRes.timestamp = Utils::GetCurrentTimestamp();

        // SPF Check (TXT record on domain)
        std::string txtUrl = "https://dns.google/resolve?name=" + Utils::UrlEncode(domain) + "&type=TXT";
        auto txtHttp = HttpClient::Instance().Get(txtUrl);
        std::string spfRecord = "None found";
        if (txtHttp.statusCode == 200) {
            auto j = txtHttp.AsJson();
            if (j.contains("Answer") && j["Answer"].is_array()) {
                for (const auto& a : j["Answer"]) {
                    std::string val = a.value("data", "");
                    if (val.find("v=spf1") != std::string::npos) {
                        spfRecord = val;
                        secRes.details.push_back({"SPF Policy", "Security", "SPF", spfRecord, FindingStatus::CONFIRMED, txtUrl, 200, val, secRes.timestamp});
                        break;
                    }
                }
            }
        }

        // DMARC Check (TXT record on _dmarc.<domain>)
        std::string dmarcUrl = "https://dns.google/resolve?name=" + Utils::UrlEncode("_dmarc." + domain) + "&type=TXT";
        auto dmarcHttp = HttpClient::Instance().Get(dmarcUrl);
        std::string dmarcRecord = "None found";
        if (dmarcHttp.statusCode == 200) {
            auto j = dmarcHttp.AsJson();
            if (j.contains("Answer") && j["Answer"].is_array()) {
                for (const auto& a : j["Answer"]) {
                    std::string val = a.value("data", "");
                    if (val.find("v=DMARC1") != std::string::npos) {
                        dmarcRecord = val;
                        secRes.details.push_back({"DMARC Policy", "Security", "DMARC", dmarcRecord, FindingStatus::CONFIRMED, dmarcUrl, 200, val, secRes.timestamp});
                        break;
                    }
                }
            }
        }

        secRes.status = (spfRecord != "None found" || dmarcRecord != "None found") ? FindingStatus::CONFIRMED : FindingStatus::NOT_FOUND;
        std::string spfStatus = (spfRecord != "None found") ? "Configured" : "Missing";
        std::string dmarcStatus = (dmarcRecord != "None found") ? "Configured" : "Missing";
        secRes.summary = "SPF: " + spfStatus + " | DMARC: " + dmarcStatus;
        report.results.push_back(secRes);

        // 6. Gravatar Lookup
        Console::Status("Gravatar Recon", "Checking public avatar and identity");
        ServiceResult gravRes;
        gravRes.serviceName = "Gravatar Identity";
        std::string emailHash = Utils::CalculateMD5(Utils::ToLower(Utils::Trim(email)));
        std::string gravUrl = "https://gravatar.com/" + emailHash + ".json";
        gravRes.providerUrl = gravUrl;
        gravRes.timestamp = Utils::GetCurrentTimestamp();

        HttpRequestOptions gOpts;
        gOpts.timeoutSeconds = 6;
        gOpts.headers["User-Agent"] = "Mozilla/5.0 XIII-0S1nt/2.4";
        auto gravHttp = HttpClient::Instance().Get(gravUrl, gOpts);
        gravRes.httpStatus = gravHttp.statusCode;
        gravRes.responseTimeMs = gravHttp.elapsedMilliseconds;

        if (gravHttp.statusCode == 200) {
            gravRes.status = FindingStatus::CONFIRMED;
            gravRes.profileUrl = "https://gravatar.com/" + emailHash;
            gravRes.summary = "Confirmed active Gravatar profile associated with email hash.";
            auto j = gravHttp.AsJson();
            if (j.contains("entry") && j["entry"].is_array() && !j["entry"].empty()) {
                auto entry = j["entry"][0];
                std::string displayName = entry.value("displayName", "");
                std::string preferredUsername = entry.value("preferredUsername", "");
                if (!displayName.empty()) gravRes.details.push_back({"Gravatar", "Identity", "Display Name", displayName, FindingStatus::CONFIRMED, gravUrl, 200, displayName, gravRes.timestamp});
                if (!preferredUsername.empty()) gravRes.details.push_back({"Gravatar", "Identity", "Handle", preferredUsername, FindingStatus::CONFIRMED, gravUrl, 200, preferredUsername, gravRes.timestamp});
            }
        } else {
            gravRes.status = FindingStatus::NOT_FOUND;
            gravRes.summary = "No public Gravatar profile registered for this address.";
        }
        report.results.push_back(gravRes);

        // 7. Have I Been Pwned Check (API Key if present)
        Console::Status("HIBP Breach Check", "Checking known data breach exposure");
        ServiceResult hibpRes;
        hibpRes.serviceName = "Have I Been Pwned";
        hibpRes.providerUrl = "https://haveibeenpwned.com/api/v3/breachedaccount/";
        hibpRes.timestamp = Utils::GetCurrentTimestamp();

        std::string hibpKey = ConfigManager::Instance().GetApiKey("HIBP_API_KEY");
        if (!hibpKey.empty()) {
            HttpRequestOptions hOpts;
            hOpts.headers["hibp-api-key"] = hibpKey;
            hOpts.headers["user-agent"] = "XIII-0S1nt-Scanner";
            auto hHttp = HttpClient::Instance().Get("https://haveibeenpwned.com/api/v3/breachedaccount/" + Utils::UrlEncode(email) + "?truncateResponse=false", hOpts);
            hibpRes.httpStatus = hHttp.statusCode;
            hibpRes.responseTimeMs = hHttp.elapsedMilliseconds;

            if (hHttp.statusCode == 200) {
                hibpRes.status = FindingStatus::CONFIRMED;
                auto j = hHttp.AsJson();
                if (j.is_array()) {
                    hibpRes.summary = "ALERT: Email was discovered in " + std::to_string(j.size()) + " documented breach(es).";
                    for (const auto& b : j) {
                        std::string bName = b.value("Name", "Unknown");
                        std::string bDate = b.value("BreachDate", "");
                        hibpRes.details.push_back({"HIBP", "Breach", bName, "Breached on " + bDate, FindingStatus::CONFIRMED, "https://haveibeenpwned.com", 200, "", hibpRes.timestamp});
                    }
                }
            } else if (hHttp.statusCode == 404) {
                hibpRes.status = FindingStatus::NOT_FOUND;
                hibpRes.summary = "Clean: Email address not found in any documented HIBP breaches.";
            } else if (hHttp.statusCode == 429) {
                hibpRes.status = FindingStatus::RATE_LIMITED;
                hibpRes.summary = "HIBP rate limit exceeded. Please wait between queries.";
            } else {
                hibpRes.status = FindingStatus::UNAVAILABLE;
                hibpRes.summary = "HIBP API returned status " + std::to_string(hHttp.statusCode);
            }
        } else {
            hibpRes.status = FindingStatus::UNVERIFIED;
            hibpRes.summary = "No HIBP API Key configured in Application Settings. (To enable direct breach lookups, add key in Option 22).";
        }
        report.results.push_back(hibpRes);

        Console::Success("Investigation completed");

        // Format executive summary
        std::ostringstream ss;
        ss << "Email intelligence inquiry completed for '" << email << "'. "
           << "Domain: " << domain << " (" << providerName << "). "
           << "MX Deliverability: " << (mxRes.status == FindingStatus::CONFIRMED ? "Confirmed active" : "No MX records found") << ". "
           << "Disposable Domain: " << (DISPOSABLE_EMAIL_DOMAINS.count(Utils::ToLower(domain)) ? "YES (High Risk)" : "NO") << ". "
           << "Gravatar: " << (gravRes.status == FindingStatus::CONFIRMED ? "Confirmed identity match" : "None") << ".";
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void EmailModule::RunInteractive() {
        Console::PrintHeader("EMAIL INTELLIGENCE [02]");
        std::string email = Console::ReadLine("Enter target email address to investigate: ");
        if (email.empty()) {
            Console::Warning("No email entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(email);
        Console::Pause();
    }

} // namespace XIII
