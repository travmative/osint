#include "menu.hpp"
#include "console.hpp"
#include "modules.hpp"
#include <iostream>
#include <iomanip>

namespace XIII {

    static const std::vector<MenuItem> MENU_ITEMS = {
        {"01", "Username Intelligence", "Reconnaissance across 25+ public developer and social platforms"},
        {"02", "Email Intelligence", "Syntax, MX, SPF, DMARC, Gravatar, disposable check, provider classification"},
        {"03", "Phone Intelligence", "ITU-T E.164 parsing, calling codes, numbering plan, line classification"},
        {"04", "IP Address Intelligence", "Geolocation, ASN, ISP, BGP routing, security indicators, RDAP"},
        {"05", "Domain Intelligence", "Registrar RDAP, DoH DNS records, crt.sh subdomains, threat checks"},
        {"06", "Website Intelligence", "Server banner, security headers audit, robots.txt, Wayback archive"},
        {"07", "Discord ID Intelligence", "Snowflake ID 64-bit epoch timestamp decoder and user public profile"},
        {"08", "GitHub Intelligence", "Deep developer OSINT, public SSH/GPG keys, commit email leaks"},
        {"09", "Social Media Intelligence", "Cross-platform identity correlation across Fediverse, Bluesky, Reddit"},
        {"10", "Data Breach Intelligence", "Breach exposure lookup, k-Anonymity password validation"},
        {"11", "DNS Intelligence", "Authoritative DoH lookup for A, AAAA, MX, TXT, NS, SOA, CAA"},
        {"12", "WHOIS / RDAP Intelligence", "Authoritative ICANN / Regional Internet Registry registration lookup"},
        {"13", "Network Intelligence", "BGPView routing table, ASN autonomous system announcements and peers"},
        {"14", "URL Reputation", "Malware URL scanner via abuse.ch URLhaus and ThreatFox IOC database"},
        {"15", "File Hash Intelligence", "Local hash calculation and check against MalwareBazaar and CIRCL"},
        {"16", "Threat Intelligence", "CISA KEV exploited vulnerabilities catalog and ThreatFox IOCs"},
        {"17", "Public Profile Discovery", "Developer identity discovery across Hacker News, Keybase, PyPI"},
        {"18", "Search Engine Intelligence", "Precision Google Dork reconnaissance matrix for exposed assets"},
        {"19", "Comprehensive OSINT Scan", "Multi-vector coordinated scan across all intelligence modules"},
        {"20", "Report Manager", "Browse, view, export, and manage generated TXT intelligence dossiers"},
        {"21", "API Status", "Live connectivity and latency verification for registered OSINT APIs"},
        {"22", "Application Settings", "DPAPI credential vault, network timeouts, concurrency limits, license"},
        {"23", "Exit", "Perform secure memory zeroing and exit platform"}
    };

    void Menu::DisplayMainMenu() {
        Console::Clear();
        Console::PrintLogo();

        std::cout << "\n";
        Console::SetColor(Color::BrightRed);
        std::cout << " [ MAIN INTELLIGENCE RECONNAISSANCE MATRIX ]\n";
        Console::SetColor(Color::DarkRed);
        std::cout << " ========================================================================\n";

        // Display in a clean two-column or structured table format
        for (size_t i = 0; i < MENU_ITEMS.size(); ++i) {
            Console::SetColor(Color::BrightRed);
            std::cout << " [" << MENU_ITEMS[i].code << "] ";
            Console::SetColor(Color::BrightWhite);
            std::cout << std::left << std::setw(28) << MENU_ITEMS[i].title;
            Console::SetColor(Color::Gray);
            std::cout << " - " << MENU_ITEMS[i].description << "\n";
        }

        Console::SetColor(Color::DarkRed);
        std::cout << " ========================================================================\n";
        Console::ResetColor();
    }

    int Menu::GetUserChoice() {
        return Console::ReadInt("\nXIII-0S1nt > Enter Module Selection (01-23): ", 1, 23);
    }

    void Menu::ExecuteOption(int option) {
        switch (option) {
            case 1:  UsernameModule::RunInteractive(); break;
            case 2:  EmailModule::RunInteractive(); break;
            case 3:  PhoneModule::RunInteractive(); break;
            case 4:  IpModule::RunInteractive(); break;
            case 5:  DomainModule::RunInteractive(); break;
            case 6:  WebsiteModule::RunInteractive(); break;
            case 7:  DiscordModule::RunInteractive(); break;
            case 8:  GitHubModule::RunInteractive(); break;
            case 9:  SocialModule::RunInteractive(); break;
            case 10: BreachModule::RunInteractive(); break;
            case 11: DnsModule::RunInteractive(); break;
            case 12: WhoisModule::RunInteractive(); break;
            case 13: NetworkModule::RunInteractive(); break;
            case 14: UrlReputationModule::RunInteractive(); break;
            case 15: FileHashModule::RunInteractive(); break;
            case 16: ThreatIntelModule::RunInteractive(); break;
            case 17: PublicProfileModule::RunInteractive(); break;
            case 18: SearchEngineModule::RunInteractive(); break;
            case 19: ComprehensiveModule::RunInteractive(); break;
            case 20: ReportManagerModule::RunInteractive(); break;
            case 21: ApiStatusModule::RunInteractive(); break;
            case 22: SettingsModule::RunInteractive(); break;
            case 23:
                Console::Info("Zeroing memory and closing active sockets...");
                break;
            default:
                Console::Error("Invalid selection.");
                break;
        }
    }

} // namespace XIII
