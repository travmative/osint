#define NOMINMAX
#include "report_generator.hpp"
#include "config_manager.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

namespace XIII {

    ReportGenerator& ReportGenerator::Instance() {
        static ReportGenerator instance;
        return instance;
    }

    ReportGenerator::ReportGenerator() {}

    std::string ReportGenerator::EnsureCategoryDirectory(const std::string& category) {
        std::string baseDir = ConfigManager::Instance().GetReportsDirectory();
        fs::path p = fs::path(baseDir) / category;
        if (!fs::exists(p)) {
            fs::create_directories(p);
        }
        return p.string();
    }

    void ReportGenerator::CalculateSummaryStatistics(InvestigationReport& report) {
        report.summary.totalServicesChecked = static_cast<int>(report.results.size());
        report.summary.confirmedFindings = 0;
        report.summary.potentialFindings = 0;
        report.summary.unverifiedFindings = 0;
        report.summary.notFound = 0;
        report.summary.serviceUnavailable = 0;
        report.summary.rateLimited = 0;

        for (const auto& res : report.results) {
            switch (res.status) {
                case FindingStatus::CONFIRMED:    report.summary.confirmedFindings++; break;
                case FindingStatus::POTENTIAL:    report.summary.potentialFindings++; break;
                case FindingStatus::UNVERIFIED:   report.summary.unverifiedFindings++; break;
                case FindingStatus::NOT_FOUND:    report.summary.notFound++; break;
                case FindingStatus::UNAVAILABLE:  report.summary.serviceUnavailable++; break;
                case FindingStatus::RATE_LIMITED: report.summary.rateLimited++; break;
            }
        }

        // Calculate confidence score
        if (report.summary.totalServicesChecked > 0) {
            int effectiveChecked = report.summary.totalServicesChecked - report.summary.serviceUnavailable - report.summary.rateLimited;
            if (effectiveChecked > 0) {
                double rawScore = ((report.summary.confirmedFindings * 1.0) + (report.summary.potentialFindings * 0.5)) / effectiveChecked;
                report.summary.confidenceScore = (std::min)(100.0, rawScore * 100.0);
            } else {
                report.summary.confidenceScore = 0.0;
            }
        }

        if (report.summary.confirmedFindings >= 3) {
            report.summary.assessment = "HIGH CONFIDENCE: Multiple verified intelligence indicators correlate directly to the target.";
        } else if (report.summary.confirmedFindings >= 1) {
            report.summary.assessment = "MODERATE CONFIDENCE: Target identified with confirmed activity; additional corroboration recommended.";
        } else if (report.summary.potentialFindings > 0) {
            report.summary.assessment = "LOW-TO-MODERATE CONFIDENCE: Potential associations detected but lack definitive confirmation.";
        } else {
            report.summary.assessment = "INCONCLUSIVE: No definitive public intelligence matches found across active repositories.";
        }
    }

    std::string ReportGenerator::FormatPlainTextReport(const InvestigationReport& report) {
        std::ostringstream ss;
        std::string sep(80, '=');
        std::string subsep(80, '-');

        ss << sep << "\n";
        ss << "                    XIII 0S1NT - INTELLIGENCE REPORT                    \n";
        ss << "                 AUTOMATED OSINT RECONNAISSANCE DOSSIER                 \n";
        ss << "                      DEVELOPED BY FINDHOST $ TRAVMA                    \n";
        ss << sep << "\n\n";

        ss << "[+] INVESTIGATION METADATA\n";
        ss << subsep << "\n";
        ss << std::left << std::setw(26) << "Investigation ID:"       << report.investigationId << "\n";
        ss << std::left << std::setw(26) << "Investigation Module:"   << report.moduleName << "\n";
        ss << std::left << std::setw(26) << "Target Identifier:"      << report.target << " [" << report.targetType << "]\n";
        ss << std::left << std::setw(26) << "Timestamp (UTC):"        << report.timestamp << "\n";
        ss << std::left << std::setw(26) << "Platform Version:"       << report.appVersion << "\n";
        ss << std::left << std::setw(26) << "Classification:"         << "PUBLIC OSINT / UNCLASSIFIED" << "\n";
        ss << "\n";

        ss << "[+] EXECUTIVE SUMMARY & CONFIDENCE ASSESSMENT\n";
        ss << subsep << "\n";
        ss << std::left << std::setw(26) << "Confidence Score:"       << std::fixed << std::setprecision(1) << report.summary.confidenceScore << "%\n";
        ss << std::left << std::setw(26) << "Overall Assessment:"     << report.summary.assessment << "\n";
        if (!report.executiveSummary.empty()) {
            ss << "\n" << report.executiveSummary << "\n";
        }
        ss << "\n";

        ss << "[+] RECONNAISSANCE METRICS\n";
        ss << subsep << "\n";
        ss << std::left << std::setw(26) << "Total Services Queried:"  << report.summary.totalServicesChecked << "\n";
        ss << std::left << std::setw(26) << "Confirmed Findings:"     << report.summary.confirmedFindings << "\n";
        ss << std::left << std::setw(26) << "Potential Findings:"     << report.summary.potentialFindings << "\n";
        ss << std::left << std::setw(26) << "Unverified Findings:"    << report.summary.unverifiedFindings << "\n";
        ss << std::left << std::setw(26) << "Not Found (404/Empty):"  << report.summary.notFound << "\n";
        ss << std::left << std::setw(26) << "Service Unavailable:"    << report.summary.serviceUnavailable << "\n";
        ss << std::left << std::setw(26) << "Rate-Limited Requests:"  << report.summary.rateLimited << "\n";
        ss << "\n";

        ss << "[+] SERVICE-BY-SERVICE FINDINGS & EVIDENCE\n";
        ss << sep << "\n";

        for (const auto& res : report.results) {
            ss << "\n";
            ss << "[" << StatusToString(res.status) << "] " << res.serviceName << "\n";
            ss << subsep << "\n";
            ss << "  Provider URL:    " << res.providerUrl << "\n";
            ss << "  HTTP Status:     " << res.httpStatus << " (" << res.responseTimeMs << " ms)\n";
            if (!res.profileUrl.empty()) {
                ss << "  Target URL:      " << res.profileUrl << "\n";
            }
            if (!res.timestamp.empty()) {
                ss << "  Query Timestamp: " << res.timestamp << "\n";
            }
            if (!res.summary.empty()) {
                ss << "  Intelligence:    " << res.summary << "\n";
            }

            if (!res.details.empty()) {
                ss << "  Extracted Metadata:\n";
                for (const auto& det : res.details) {
                    ss << "    * " << std::left << std::setw(20) << (det.key + ":") << det.value;
                    if (det.status != FindingStatus::CONFIRMED && det.status != FindingStatus::UNVERIFIED) {
                        ss << " [" << StatusToString(det.status) << "]";
                    }
                    ss << "\n";
                }
            }

            if (!res.rawData.empty()) {
                ss << "  Raw Data Extract:\n";
                std::istringstream iss(res.rawData);
                std::string line;
                int linesPrinted = 0;
                while (std::getline(iss, line) && linesPrinted < 8) {
                    if (!line.empty()) {
                        ss << "    | " << line << "\n";
                        linesPrinted++;
                    }
                }
            }
        }

        ss << "\n" << sep << "\n";
        ss << "                      END OF XIII 0S1NT REPORT                          \n";
        ss << "           DO NOT DISTRIBUTE SENSITIVE DATA WITHOUT PERMISSION          \n";
        ss << sep << "\n";

        return ss.str();
    }

    std::string ReportGenerator::GenerateReport(InvestigationReport& report) {
        if (report.investigationId.empty()) {
            report.investigationId = Utils::GenerateUUID();
        }
        if (report.timestamp.empty()) {
            report.timestamp = Utils::GetCurrentTimestamp();
        }

        CalculateSummaryStatistics(report);

        std::string category = report.moduleName;
        std::string targetClean = Utils::SanitizeFilename(report.target);
        std::string tsForFile = Utils::GetTimestampForFilename();

        std::string filename = "XIII_" + Utils::ToUpper(category) + "_" + targetClean + "_" + tsForFile + ".txt";
        std::string dirPath = EnsureCategoryDirectory(category);
        std::string fullPath = (fs::path(dirPath) / filename).string();

        std::string content = FormatPlainTextReport(report);

        std::ofstream outFile(fullPath, std::ios::out | std::ios::trunc);
        if (outFile.is_open()) {
            outFile << content;
            outFile.close();
            report.savedReportPath = fullPath;
        }

        return fullPath;
    }

    std::vector<ReportMetadata> ReportGenerator::ListAllReports() {
        std::vector<ReportMetadata> list;
        std::string baseDir = ConfigManager::Instance().GetReportsDirectory();
        if (!fs::exists(baseDir)) return list;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(baseDir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".txt") {
                    ReportMetadata meta;
                    meta.filename = entry.path().filename().string();
                    meta.fullPath = entry.path().string();
                    meta.category = entry.path().parent_path().filename().string();
                    meta.fileSize = entry.file_size();

                    // Parse filename: XIII_CATEGORY_TARGET_TIMESTAMP.txt
                    std::string fname = meta.filename;
                    meta.target = "Unknown";
                    meta.timestamp = "";

                    list.push_back(meta);
                }
            }
        } catch (...) {}

        return list;
    }

    std::vector<ReportMetadata> ReportGenerator::ListReportsByCategory(const std::string& category) {
        std::vector<ReportMetadata> list;
        std::string dir = EnsureCategoryDirectory(category);
        if (!fs::exists(dir)) return list;

        try {
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".txt") {
                    ReportMetadata meta;
                    meta.filename = entry.path().filename().string();
                    meta.fullPath = entry.path().string();
                    meta.category = category;
                    meta.fileSize = entry.file_size();
                    list.push_back(meta);
                }
            }
        } catch (...) {}

        return list;
    }

    bool ReportGenerator::DeleteReport(const std::string& filePath) {
        try {
            if (fs::exists(filePath)) {
                return fs::remove(filePath);
            }
        } catch (...) {}
        return false;
    }

    bool ReportGenerator::OpenReportInEditor(const std::string& filePath) {
        HINSTANCE res = ShellExecuteA(NULL, "open", filePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return (reinterpret_cast<INT_PTR>(res) > 32);
    }

} // namespace XIII
