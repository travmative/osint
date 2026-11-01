#include "console.hpp"
#include <windows.h>
#include <conio.h>
#include <io.h>
#include <fstream>
#include <iomanip>

namespace XIII {

    bool Console::s_ansiSupported = false;
    std::mutex Console::s_consoleMutex;

    void Console::EnableVirtualTerminal() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;

        DWORD dwMode = 0;
        if (!GetConsoleMode(hOut, &dwMode)) return;

        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        if (SetConsoleMode(hOut, dwMode)) {
            s_ansiSupported = true;
        }

        // Set console output code page to UTF-8
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);

        // Set console title
        SetConsoleTitleW(L"XIII 0S1nt - Intelligence & Reconnaissance Platform [v2.4.0]");
    }

    void Console::Initialize() {
        EnableVirtualTerminal();
        // Clear screen and set cursor
        std::cout << "\033[2J\033[H";
    }

    void Console::SetColor(Color color) {
        if (s_ansiSupported) {
            switch (color) {
                case Color::DarkRed:      std::cout << "\033[38;2;170;20;30m"; break;
                case Color::BrightRed:    std::cout << "\033[1;91m"; break;
                case Color::Green:        std::cout << "\033[1;92m"; break;
                case Color::Yellow:       std::cout << "\033[1;93m"; break;
                case Color::Red:          std::cout << "\033[91m"; break;
                case Color::Cyan:         std::cout << "\033[1;96m"; break;
                case Color::Gray:         std::cout << "\033[90m"; break;
                case Color::White:        std::cout << "\033[37m"; break;
                case Color::BrightWhite:  std::cout << "\033[1;97m"; break;
                default:                  std::cout << "\033[0m"; break;
            }
        } else {
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            WORD attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            switch (color) {
                case Color::DarkRed:     attr = FOREGROUND_RED; break;
                case Color::BrightRed:   attr = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
                case Color::Green:       attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
                case Color::Yellow:      attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
                case Color::Red:         attr = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
                case Color::Cyan:        attr = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
                case Color::Gray:        attr = FOREGROUND_INTENSITY; break;
                case Color::BrightWhite: attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
                default: break;
            }
            SetConsoleTextAttribute(hOut, attr);
        }
    }

    void Console::ResetColor() {
        if (s_ansiSupported) {
            std::cout << "\033[0m";
        } else {
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    void Console::Clear() {
        if (s_ansiSupported) {
            std::cout << "\033[2J\033[H";
        } else {
            system("cls");
        }
    }

    void Console::Pause(const std::string& message) {
        if (!_isatty(_fileno(stdin))) {
            return;
        }
        SetColor(Color::Gray);
        std::cout << "\n" << message << "\n";
        ResetColor();
        std::cin.sync();
        _getch();
    }

    void Console::PrintLogo() {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::DarkRed);
        std::cout << "\n";
        std::cout << "  ██╗  ██╗██╗██╗██╗     ██████╗ ███████╗ ██╗███╗   ██╗████████╗\n";
        std::cout << "  ╚██╗██╔╝██║██║██║    ██╔═████╗██╔════╝███║████╗  ██║╚══██╔══╝\n";
        std::cout << "   ╚███╔╝ ██║██║██║    ██║██╔██║███████╗╚██║██╔██╗ ██║   ██║   \n";
        std::cout << "   ██╔██╗ ██║██║██║    ████╔╝██║╚════██║ ██║██║╚██╗██║   ██║   \n";
        std::cout << "  ██╔╝ ██╗██║██║██║    ╚██████╔╝███████║ ██║██║ ╚████║   ██║   \n";
        std::cout << "  ╚═╝  ╚═╝╚═╝╚═╝╚═╝     ╚═════╝ ╚══════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   \n";
        SetColor(Color::BrightRed);
        std::cout << "========================================================================\n";
        SetColor(Color::Gray);
        std::cout << "       AUTOMATED THREAT INTELLIGENCE & OSINT RECON PLATFORM\n";
        SetColor(Color::BrightRed);
        std::cout << "                  DEVELOPED BY ";
        SetColor(Color::BrightWhite);
        std::cout << "FINDHOST $ TRAVMA\n";
        SetColor(Color::BrightRed);
        std::cout << "========================================================================\n";
        ResetColor();
    }

    void Console::PrintHeader(const std::string& title) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        std::cout << "\n";
        SetColor(Color::BrightRed);
        std::cout << ">> " << title << "\n";
        SetColor(Color::DarkRed);
        std::cout << std::string(title.length() + 3, '=') << "\n";
        ResetColor();
    }

    void Console::PrintSection(const std::string& section) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::BrightRed);
        std::cout << "\n[!] " << section << "\n";
        ResetColor();
    }

    void Console::Success(const std::string& message) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::Green);
        std::cout << "[+] " << message << "\n";
        ResetColor();
    }

    void Console::Info(const std::string& message) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::Cyan);
        std::cout << "[*] " << message << "\n";
        ResetColor();
    }

    void Console::Warning(const std::string& message) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::Yellow);
        std::cout << "[!] " << message << "\n";
        ResetColor();
    }

    void Console::Error(const std::string& message) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::Red);
        std::cout << "[-] " << message << "\n";
        ResetColor();
    }

    void Console::Status(const std::string& service, const std::string& statusMessage) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::DarkRed);
        std::cout << "[+] ";
        SetColor(Color::BrightWhite);
        std::cout << std::left << std::setw(22) << service;
        SetColor(Color::Gray);
        std::cout << ": " << statusMessage << "\n";
        ResetColor();
    }

    void Console::PrintDivider(char ch, int length) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        SetColor(Color::DarkRed);
        std::cout << std::string(length, ch) << "\n";
        ResetColor();
    }

    void Console::PrintReportBanner(const std::string& filename, const std::string& location) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        std::cout << "\n";
        SetColor(Color::BrightRed);
        std::cout << "========================================================================\n";
        SetColor(Color::Green);
        std::cout << "[+] REPORT CREATED SUCCESSFULLY\n";
        SetColor(Color::BrightWhite);
        std::cout << "    Filename: ";
        SetColor(Color::Cyan);
        std::cout << filename << "\n";
        SetColor(Color::BrightWhite);
        std::cout << "    Location: ";
        SetColor(Color::Cyan);
        std::cout << location << "\n";
        SetColor(Color::BrightRed);
        std::cout << "========================================================================\n";
        ResetColor();
    }

    std::string Console::ReadLine(const std::string& prompt) {
        SetColor(Color::BrightRed);
        std::cout << prompt;
        SetColor(Color::BrightWhite);
        std::string input;
        if (!std::getline(std::cin, input)) {
            ResetColor();
            return "";
        }
        ResetColor();
        return Utils::Trim(input);
    }

    std::string Console::ReadPassword(const std::string& prompt) {
        if (!_isatty(_fileno(stdin))) {
            return ReadLine(prompt);
        }
        SetColor(Color::BrightRed);
        std::cout << prompt;
        ResetColor();
        std::string password;
        char ch;
        while ((ch = _getch()) != '\r' && ch != '\n') {
            if (ch == '\b') {
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b";
                }
            } else if (ch >= 32 && ch <= 126) {
                password.push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << "\n";
        return password;
    }

    int Console::ReadInt(const std::string& prompt, int minVal, int maxVal) {
        while (true) {
            if (std::cin.eof()) {
                return minVal;
            }
            std::string line = ReadLine(prompt);
            try {
                int val = std::stoi(line);
                if (val >= minVal && val <= maxVal) {
                    return val;
                }
            } catch (...) {}
            if (std::cin.eof()) {
                return minVal;
            }
            Error("Invalid selection. Please enter a number between " + std::to_string(minVal) + " and " + std::to_string(maxVal) + ".");
        }
    }

    void Console::PrintFindingStatus(FindingStatus status) {
        switch (status) {
            case FindingStatus::CONFIRMED:
                SetColor(Color::Green);
                std::cout << "[CONFIRMED]   ";
                break;
            case FindingStatus::POTENTIAL:
                SetColor(Color::Yellow);
                std::cout << "[POTENTIAL]   ";
                break;
            case FindingStatus::UNVERIFIED:
                SetColor(Color::Cyan);
                std::cout << "[UNVERIFIED]  ";
                break;
            case FindingStatus::NOT_FOUND:
                SetColor(Color::Gray);
                std::cout << "[NOT FOUND]   ";
                break;
            case FindingStatus::UNAVAILABLE:
                SetColor(Color::Red);
                std::cout << "[UNAVAILABLE] ";
                break;
            case FindingStatus::RATE_LIMITED:
                SetColor(Color::Yellow);
                std::cout << "[RATE LIMIT]  ";
                break;
        }
        ResetColor();
    }

    void Console::PrintTable(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows) {
        std::lock_guard<std::mutex> lock(s_consoleMutex);
        if (headers.empty()) return;

        std::vector<size_t> colWidths(headers.size(), 0);
        for (size_t i = 0; i < headers.size(); ++i) {
            colWidths[i] = headers[i].length();
        }
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size() && i < colWidths.size(); ++i) {
                if (row[i].length() > colWidths[i]) {
                    colWidths[i] = row[i].length();
                }
            }
        }

        // Header
        SetColor(Color::BrightRed);
        for (size_t i = 0; i < headers.size(); ++i) {
            std::cout << std::left << std::setw(colWidths[i] + 3) << headers[i];
        }
        std::cout << "\n";
        SetColor(Color::DarkRed);
        for (size_t i = 0; i < headers.size(); ++i) {
            std::cout << std::string(colWidths[i] + 2, '-') << " ";
        }
        std::cout << "\n";

        // Rows
        for (const auto& row : rows) {
            SetColor(Color::BrightWhite);
            for (size_t i = 0; i < row.size() && i < colWidths.size(); ++i) {
                std::cout << std::left << std::setw(colWidths[i] + 3) << row[i];
            }
            std::cout << "\n";
        }
        ResetColor();
    }

} // namespace XIII
