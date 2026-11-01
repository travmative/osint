#pragma once

#include <string>
#include <iostream>
#include <vector>
#include <mutex>
#include "common.hpp"

namespace XIII {

    enum class Color {
        Default,
        DarkRed,       // Crimson
        BrightRed,     // Bright Red headings
        Green,         // Success
        Yellow,        // Warnings
        Red,           // Errors
        Cyan,          // Informational
        Gray,          // Secondary / muted
        White,
        BrightWhite
    };

    class Console {
    public:
        static void Initialize();
        static void SetColor(Color color);
        static void ResetColor();
        static void Clear();
        static void Pause(const std::string& message = "Press ENTER to continue...");

        static void PrintLogo();
        static void PrintHeader(const std::string& title);
        static void PrintSection(const std::string& section);
        
        static void Success(const std::string& message);
        static void Info(const std::string& message);
        static void Warning(const std::string& message);
        static void Error(const std::string& message);
        static void Status(const std::string& service, const std::string& statusMessage);
        
        static void PrintDivider(char ch = '=', int length = 76);
        static void PrintReportBanner(const std::string& filename, const std::string& location);
        
        static std::string ReadLine(const std::string& prompt);
        static std::string ReadPassword(const std::string& prompt);
        static int ReadInt(const std::string& prompt, int minVal, int maxVal);

        static void PrintFindingStatus(FindingStatus status);
        static void PrintTable(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows);

    private:
        static bool s_ansiSupported;
        static std::mutex s_consoleMutex;
        static void EnableVirtualTerminal();
    };

} // namespace XIII
