#include "modules.hpp"
#include "console.hpp"
#include "report_generator.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>

namespace XIII {

    void ReportManagerModule::RunInteractive() {
        while (true) {
            Console::Clear();
            Console::PrintHeader("REPORT MANAGER [20]");

            auto reports = ReportGenerator::Instance().ListAllReports();

            if (reports.empty()) {
                Console::Warning("No intelligence reports found in storage directory.");
                Console::Info("Run an investigation module (Options 01-19) to generate reports.");
                Console::Pause();
                return;
            }

            std::cout << "\nFound " << reports.size() << " generated intelligence report(s):\n\n";

            std::vector<std::string> headers = {"#", "Category", "Filename", "Size"};
            std::vector<std::vector<std::string>> rows;

            for (size_t i = 0; i < reports.size(); ++i) {
                std::string sizeStr = std::to_string(reports[i].fileSize / 1024) + " KB";
                std::string num = "[" + std::to_string(i + 1) + "]";
                rows.push_back({num, reports[i].category, reports[i].filename, sizeStr});
            }

            Console::PrintTable(headers, rows);

            std::cout << "\nActions:\n";
            std::cout << "[1] Open report in Notepad / default viewer\n";
            std::cout << "[2] View report content in terminal\n";
            std::cout << "[3] Delete a report\n";
            std::cout << "[4] Return to Main Menu\n";

            int action = Console::ReadInt("Select action (1-4): ", 1, 4);
            if (action == 4) return;

            int reportIndex = Console::ReadInt("Select report number (1-" + std::to_string(reports.size()) + "): ", 1, static_cast<int>(reports.size())) - 1;
            const auto& selected = reports[reportIndex];

            if (action == 1) {
                if (ReportGenerator::Instance().OpenReportInEditor(selected.fullPath)) {
                    Console::Success("Report opened in external editor.");
                } else {
                    Console::Error("Failed to launch default editor.");
                }
                Console::Pause();
            } else if (action == 2) {
                Console::Clear();
                Console::PrintHeader("VIEWING: " + selected.filename);
                std::ifstream file(selected.fullPath);
                if (file.is_open()) {
                    std::string line;
                    while (std::getline(file, line)) {
                        std::cout << line << "\n";
                    }
                } else {
                    Console::Error("Could not open report file for reading.");
                }
                Console::Pause();
            } else if (action == 3) {
                std::string confirm = Console::ReadLine("Are you sure you want to delete '" + selected.filename + "'? (y/n): ");
                if (Utils::ToLower(confirm) == "y") {
                    if (ReportGenerator::Instance().DeleteReport(selected.fullPath)) {
                        Console::Success("Report deleted successfully.");
                    } else {
                        Console::Error("Failed to delete report.");
                    }
                }
                Console::Pause();
            }
        }
    }

} // namespace XIII
