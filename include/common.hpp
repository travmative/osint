#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <filesystem>

namespace XIII {

    constexpr const char* APP_NAME = "XIII 0S1nt";
    constexpr const char* APP_VERSION = "2.4.0 (Enterprise Build)";
    constexpr const char* APP_DEVELOPERS = "Findhost $ Travma";
    constexpr const char* APP_RELEASE_DATE = "2026-11-01";

    enum class FindingStatus {
        CONFIRMED,
        POTENTIAL,
        UNVERIFIED,
        NOT_FOUND,
        UNAVAILABLE,
        RATE_LIMITED
    };

    inline std::string StatusToString(FindingStatus status) {
        switch (status) {
            case FindingStatus::CONFIRMED:    return "CONFIRMED";
            case FindingStatus::POTENTIAL:    return "POTENTIAL";
            case FindingStatus::UNVERIFIED:   return "UNVERIFIED";
            case FindingStatus::NOT_FOUND:    return "NOT FOUND";
            case FindingStatus::UNAVAILABLE:  return "SERVICE UNAVAILABLE";
            case FindingStatus::RATE_LIMITED: return "RATE LIMITED";
            default:                          return "UNKNOWN";
        }
    }

    struct FindingItem {
        std::string serviceName;
        std::string category;
        std::string key;
        std::string value;
        FindingStatus status{FindingStatus::UNVERIFIED};
        std::string sourceUrl;
        int httpStatusCode{0};
        std::string rawEvidence;
        std::string timestamp;
    };

    struct ServiceResult {
        std::string serviceName;
        std::string providerUrl;
        FindingStatus status{FindingStatus::NOT_FOUND};
        int httpStatus{0};
        long long responseTimeMs{0};
        std::string profileUrl;
        std::string summary;
        std::vector<FindingItem> details;
        std::string rawData;
        std::string timestamp;
    };

    struct InvestigationSummary {
        int totalServicesChecked{0};
        int confirmedFindings{0};
        int potentialFindings{0};
        int unverifiedFindings{0};
        int notFound{0};
        int serviceUnavailable{0};
        int rateLimited{0};
        double confidenceScore{0.0}; // 0.0 to 100.0%
        std::string assessment;
    };

    struct InvestigationReport {
        std::string investigationId;
        std::string moduleName;
        std::string target;
        std::string targetType;
        std::string timestamp;
        std::string appVersion{APP_VERSION};
        std::vector<ServiceResult> results;
        InvestigationSummary summary;
        std::string executiveSummary;
        std::string savedReportPath;
    };

    // Helper utilities
    class Utils {
    public:
        static std::string GetCurrentTimestamp();
        static std::string GetTimestampForFilename();
        static std::string Trim(const std::string& str);
        static std::string ToLower(const std::string& str);
        static std::string ToUpper(const std::string& str);
        static bool CaseInsensitiveCompare(const std::string& a, const std::string& b);
        static std::string UrlEncode(const std::string& value);
        static std::string SanitizeFilename(const std::string& name);
        static std::string GenerateUUID();
        
        // Hashing (CryptoAPI / BCrypt native)
        static std::string CalculateMD5(const std::string& input);
        static std::string CalculateSHA1(const std::string& input);
        static std::string CalculateSHA256(const std::string& input);
        static std::string CalculateFileHash(const std::string& filePath, const std::string& algorithm);
    };

} // namespace XIII
