#pragma once

#include <string>
#include <vector>
#include "common.hpp"

namespace XIII {

    struct ReportMetadata {
        std::string filename;
        std::string fullPath;
        std::string category;
        std::string target;
        std::string timestamp;
        uintmax_t fileSize{0};
    };

    class ReportGenerator {
    public:
        static ReportGenerator& Instance();

        std::string GenerateReport(InvestigationReport& report);
        
        // Report Management
        std::vector<ReportMetadata> ListAllReports();
        std::vector<ReportMetadata> ListReportsByCategory(const std::string& category);
        bool DeleteReport(const std::string& filePath);
        bool OpenReportInEditor(const std::string& filePath);

    private:
        ReportGenerator();
        ~ReportGenerator() = default;

        std::string EnsureCategoryDirectory(const std::string& category);
        std::string FormatPlainTextReport(const InvestigationReport& report);
        void CalculateSummaryStatistics(InvestigationReport& report);
    };

} // namespace XIII
