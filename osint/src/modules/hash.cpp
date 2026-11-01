#include "modules.hpp"
#include "console.hpp"
#include "http_client.hpp"
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <iostream>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace XIII {

    InvestigationReport FileHashModule::Execute(const std::string& hashOrFilePath) {
        InvestigationReport report;
        report.moduleName = "Threat";
        report.target = hashOrFilePath;

        Console::Info("Initializing file hash intelligence analysis");

        std::string targetHash = hashOrFilePath;
        std::string calculatedMd5, calculatedSha1, calculatedSha256;

        // Check if input is a local file
        if (fs::exists(hashOrFilePath) && fs::is_regular_file(hashOrFilePath)) {
            Console::Status("Local File", "Computing MD5, SHA-1, and SHA-256 digests");
            report.targetType = "Local File Path";
            calculatedMd5 = Utils::CalculateFileHash(hashOrFilePath, "md5");
            calculatedSha1 = Utils::CalculateFileHash(hashOrFilePath, "sha1");
            calculatedSha256 = Utils::CalculateFileHash(hashOrFilePath, "sha256");
            targetHash = calculatedSha256;

            ServiceResult fileRes;
            fileRes.serviceName = "Local File Hashes";
            fileRes.status = FindingStatus::CONFIRMED;
            fileRes.providerUrl = "Windows BCrypt Engine";
            fileRes.timestamp = Utils::GetCurrentTimestamp();
            fileRes.summary = "Computed cryptographic hashes for local binary.";
            fileRes.details.push_back({fileRes.serviceName, "Hash", "MD5", calculatedMd5, FindingStatus::CONFIRMED, "", 0, calculatedMd5, fileRes.timestamp});
            fileRes.details.push_back({fileRes.serviceName, "Hash", "SHA-1", calculatedSha1, FindingStatus::CONFIRMED, "", 0, calculatedSha1, fileRes.timestamp});
            fileRes.details.push_back({fileRes.serviceName, "Hash", "SHA-256", calculatedSha256, FindingStatus::CONFIRMED, "", 0, calculatedSha256, fileRes.timestamp});
            report.results.push_back(fileRes);
        } else {
            report.targetType = "Cryptographic Hash";
        }

        // 1. MalwareBazaar Lookup
        Console::Status("MalwareBazaar", "Querying known malware sample hashes");
        ServiceResult mbRes;
        mbRes.serviceName = "MalwareBazaar (abuse.ch)";
        mbRes.providerUrl = "https://mb-api.abuse.ch/api/v1/";
        mbRes.timestamp = Utils::GetCurrentTimestamp();

        std::string mbPayload = "query=get_info&hash=" + Utils::UrlEncode(targetHash);
        auto mbResp = HttpClient::Instance().Post(mbRes.providerUrl, mbPayload, "application/x-www-form-urlencoded");
        mbRes.httpStatus = mbResp.statusCode;
        mbRes.responseTimeMs = mbResp.elapsedMilliseconds;

        if (mbResp.statusCode == 200) {
            auto j = mbResp.AsJson();
            if (j.value("query_status", "") == "ok" && j.contains("data") && j["data"].is_array() && !j["data"].empty()) {
                mbRes.status = FindingStatus::CONFIRMED;
                auto info = j["data"][0];
                std::string sig = info.value("signature", "Unknown Malware");
                std::string fType = info.value("file_type", "");
                std::string reporter = info.value("reporter", "");

                mbRes.summary = "CONFIRMED MALWARE: " + sig + " (Type: " + fType + ")";
                mbRes.details.push_back({mbRes.serviceName, "Threat", "Signature", sig, FindingStatus::CONFIRMED, mbRes.providerUrl, 200, sig, mbRes.timestamp});
                mbRes.details.push_back({mbRes.serviceName, "Threat", "File Type", fType, FindingStatus::CONFIRMED, mbRes.providerUrl, 200, fType, mbRes.timestamp});
            } else {
                mbRes.status = FindingStatus::NOT_FOUND;
                mbRes.summary = "Hash is not present in MalwareBazaar repository.";
            }
        } else {
            mbRes.status = FindingStatus::UNAVAILABLE;
            mbRes.summary = "MalwareBazaar returned HTTP " + std::to_string(mbResp.statusCode);
        }
        report.results.push_back(mbRes);

        // 2. ThreatFox Hash Search
        Console::Status("ThreatFox", "Querying IOC hash database");
        ServiceResult tfRes;
        tfRes.serviceName = "ThreatFox Hash Query";
        tfRes.providerUrl = "https://threatfox-api.abuse.ch/v1/";
        tfRes.timestamp = Utils::GetCurrentTimestamp();

        nlohmann::json tfQuery;
        tfQuery["query"] = "search_hash";
        tfQuery["hash"] = targetHash;
        auto tfResp = HttpClient::Instance().Post(tfRes.providerUrl, tfQuery.dump());
        tfRes.httpStatus = tfResp.statusCode;
        tfRes.responseTimeMs = tfResp.elapsedMilliseconds;

        if (tfResp.statusCode == 200) {
            auto j = tfResp.AsJson();
            if (j.value("query_status", "") == "ok" && j.contains("data") && j["data"].is_array() && !j["data"].empty()) {
                tfRes.status = FindingStatus::CONFIRMED;
                auto ioc = j["data"][0];
                std::string malware = ioc.value("malware_printable", "Unknown");
                std::string threatType = ioc.value("threat_type", "");
                tfRes.summary = "THREAT IOC: " + malware + " (" + threatType + ")";
                tfRes.details.push_back({tfRes.serviceName, "Threat", "Malware Family", malware, FindingStatus::CONFIRMED, tfRes.providerUrl, 200, malware, tfRes.timestamp});
            } else {
                tfRes.status = FindingStatus::NOT_FOUND;
                tfRes.summary = "No threat indicators linked to this hash.";
            }
        } else {
            tfRes.status = FindingStatus::UNAVAILABLE;
            tfRes.summary = "ThreatFox returned HTTP " + std::to_string(tfResp.statusCode);
        }
        report.results.push_back(tfRes);

        // 3. CIRCL Hashlookup
        Console::Status("CIRCL Hashlookup", "Checking European known good/bad repository");
        ServiceResult circlRes;
        circlRes.serviceName = "CIRCL Hashlookup";
        std::string circlUrl = "https://hashlookup.circl.lu/lookup/sha256/" + targetHash;
        circlRes.providerUrl = circlUrl;
        circlRes.timestamp = Utils::GetCurrentTimestamp();

        auto circlResp = HttpClient::Instance().Get(circlUrl);
        circlRes.httpStatus = circlResp.statusCode;
        circlRes.responseTimeMs = circlResp.elapsedMilliseconds;

        if (circlResp.statusCode == 200) {
            circlRes.status = FindingStatus::CONFIRMED;
            auto j = circlResp.AsJson();
            std::string fileName = j.value("FileName", "Unknown");
            circlRes.summary = "Known file catalog match: " + fileName;
            circlRes.details.push_back({circlRes.serviceName, "Catalog", "File Name", fileName, FindingStatus::CONFIRMED, circlUrl, 200, fileName, circlRes.timestamp});
        } else if (circlResp.statusCode == 404) {
            circlRes.status = FindingStatus::NOT_FOUND;
            circlRes.summary = "Hash not found in CIRCL known file database.";
        } else {
            circlRes.status = FindingStatus::UNAVAILABLE;
            circlRes.summary = "CIRCL returned HTTP " + std::to_string(circlResp.statusCode);
        }
        report.results.push_back(circlRes);

        Console::Success("Investigation completed");

        std::ostringstream ss;
        ss << "File hash intelligence inquiry for " << targetHash << " completed. "
           << "Threat Detection: " << ((mbRes.status == FindingStatus::CONFIRMED || tfRes.status == FindingStatus::CONFIRMED) ? "ALERT: CONFIRMED MALWARE SAMPLE" : "Clean in public threat feeds.");
        report.executiveSummary = ss.str();

        std::string reportPath = ReportGenerator::Instance().GenerateReport(report);

        Console::PrintReportBanner(
            std::filesystem::path(reportPath).filename().string(),
            std::filesystem::path(reportPath).parent_path().string()
        );

        return report;
    }

    void FileHashModule::RunInteractive() {
        Console::PrintHeader("FILE HASH INTELLIGENCE [15]");
        std::string input = Console::ReadLine("Enter file hash (MD5/SHA1/SHA256) or local file path: ");
        if (input.empty()) {
            Console::Warning("No hash or path entered. Aborting.");
            Console::Pause();
            return;
        }

        Execute(input);
        Console::Pause();
    }

} // namespace XIII
