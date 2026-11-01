# XIII 0S1nt
### Developed by Findhost $ Travma

[![Platform](https://img.shields.io/badge/Platform-Windows_x64-red.svg)](#)
[![Standard](https://img.shields.io/badge/C%2B%2B-20-crimson.svg)](#)
[![Security](https://img.shields.io/badge/Security-Windows_DPAPI-darkred.svg)](#)
[![Network](https://img.shields.io/badge/Network-WinHTTP_2.0-blue.svg)](#)
[![License](https://img.shields.io/badge/License-Enterprise_Active-green.svg)](#)

---

## Overview

**XIII 0S1nt** is a high-performance, Windows-native intelligence collection and automated reconnaissance reporting platform written entirely in **C++20**. It is engineered for cybersecurity operators, threat intelligence analysts, and digital forensics professionals.

The platform provides 23 dedicated reconnaissance modules that query authoritative, legitimate public data sources and threat feeds without requiring external runtimes (no Python, Node.js, Electron, or Java dependencies).

---

## Visual Identity & Terminal Interface

- **Visual Style**: Dark crimson and red accents, bright red section headers, green verified results, yellow warnings, cyan informational lines, and muted gray secondary information.
- **Windows Console APIs**: Full UTF-8 support (`CP_UTF8`) with Virtual Terminal Processing (`ENABLE_VIRTUAL_TERMINAL_PROCESSING`).
- **Startup Sequence**:
  1. ASCII Art XIII Logo display.
  2. Application version & build specification.
  3. Developer credits (`Findhost $ Travma`).
  4. Initialization of WinHTTP 2.0 network stack, thread pools, DPAPI vault, and API registry.
  5. Machine-bound cryptographic license validation.
  6. Operator acknowledgment prompt.
  7. Interactive reconnaissance matrix.

---

## Intelligence Modules

```
[01] Username Intelligence       - Deep search across 27+ public developer and social platforms
[02] Email Intelligence          - RFC 5322 syntax, MX, SPF, DMARC, Gravatar, disposable check, provider categorization
[03] Phone Intelligence          - ITU-T E.164 parsing, calling codes, numbering plan, line classification
[04] IP Address Intelligence     - Geolocation, ASN, ISP, BGP routing, security indicators, RDAP allocations
[05] Domain Intelligence         - Registrar RDAP, DoH DNS records, crt.sh subdomains, threat checks
[06] Website Intelligence        - Server banner, security headers audit, robots.txt, Wayback historical snapshots
[07] Discord ID Intelligence     - 64-bit Snowflake ID epoch decoder (creation date, age, worker/process ID)
[08] GitHub Intelligence         - Deep developer OSINT, public SSH/GPG keys, commit author email exposure discovery
[09] Social Media Intelligence   - Cross-platform identity correlation across Fediverse, Bluesky, Reddit
[10] Data Breach Intelligence    - Breach exposure lookup and k-Anonymity privacy password range verification
[11] DNS Intelligence            - Authoritative DoH lookup for A, AAAA, MX, TXT, NS, SOA, CAA records
[12] WHOIS / RDAP Intelligence   - Authoritative ICANN / Regional Internet Registry registration lookup
[13] Network Intelligence        - BGPView routing table, ASN autonomous system announcements and peers
[14] URL Reputation              - Malware URL scanner via abuse.ch URLhaus and ThreatFox IOC database
[15] File Hash Intelligence      - Local hash calculation and check against MalwareBazaar and CIRCL
[16] Threat Intelligence         - CISA KEV exploited vulnerabilities catalog and ThreatFox IOCs
[17] Public Profile Discovery    - Developer identity discovery across Hacker News, Keybase, PyPI
[18] Search Engine Intelligence  - Precision Google Dork reconnaissance matrix for exposed assets
[19] Comprehensive OSINT Scan    - Multi-vector coordinated scan across all intelligence modules
[20] Report Manager              - Browse, view, export, and manage generated TXT intelligence dossiers
[21] API Status                  - Live connectivity and latency verification for registered OSINT APIs
[22] Application Settings        - DPAPI credential vault, network timeouts, concurrency limits, license
[23] Exit                        - Perform secure memory zeroing and exit platform
```

---

## Automated Intelligence Report Generator

Every investigation automatically compiles a detailed intelligence report in plain English, saved in structured directories:

```
XIII_Reports/
    Username/
    Email/
    Phone/
    IP/
    Domain/
    Discord/
    Comprehensive/
    Threat/
```

### Report Format
Each dossier contains:
- Header & Unique Investigation UUID
- Target Identifier & Classification
- Confidence Score & Executive Summary
- Reconnaissance Metrics (Total, Confirmed, Potential, Unverified, Not Found, Unavailable, Rate-Limited)
- Service-by-service breakdown with provider URLs, HTTP response codes, latency, timestamps, and extracted metadata
- Raw evidence extracts and technical indicators

---

## Security Architecture

1. **Windows DPAPI Encryption**: API keys (VirusTotal, HIBP, AbuseIPDB, GreyNoise, GitHub, Discord) are encrypted at rest using `CryptProtectData` with the user's Windows logon credentials (`CRYPTPROTECT_UI_FORBIDDEN`). Plaintext credentials are never saved to disk or logged.
2. **Machine-Bound License Authentication**: Uses the local Windows Cryptography Machine GUID and hardware salt to validate license integrity offline without remote telemetry.
3. **Memory Safety & RAII**: Zero raw pointers; RAII resource management for WinHTTP handles, sockets, and memory buffers.
4. **Native Windows Schannel**: WinHTTP enforces TLS 1.2/1.3 and uses the Windows Root CA certificate store, eliminating missing CA bundle errors.

---

## Build Instructions

### Prerequisites
- Windows 10 / Windows 11 (x64)
- Visual Studio 2022 Community / Professional / Build Tools with C++ Desktop Development

### Quick Build
Run the provided automated build script:
```cmd
build.bat
```

Or build manually via MSVC:
```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /nologo /std:c++20 /EHsc /utf-8 /O2 /MD /I include src\*.cpp src\modules\*.cpp /link /OUT:XIII_0S1nt.exe winhttp.lib crypt32.lib bcrypt.lib advapi32.lib shell32.lib user32.lib ole32.lib
```

Or build with CMake:
```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

---

## Command-Line Usage

```cmd
:: Launch Interactive Dark Terminal UI
XIII_0S1nt.exe

:: Run Automated Diagnostic Test
XIII_0S1nt.exe --test

:: Quick Reconnaissance Queries
XIII_0S1nt.exe --username torvalds
XIII_0S1nt.exe --ip 8.8.8.8
XIII_0S1nt.exe --domain github.com
XIII_0S1nt.exe --email analyst@domain.com
XIII_0S1nt.exe --phone +14155552671
XIII_0S1nt.exe --discord 155149108183695360
XIII_0S1nt.exe --threat CVE-2023-38606
XIII_0S1nt.exe --hash 44d88612fea8a8f36de82e1278abb02f
XIII_0S1nt.exe --scan target_handle
XIII_0S1nt.exe --status
```

---

## Project Structure

```
├── include/
│   ├── nlohmann/json.hpp       # Single-header JSON library
│   ├── common.hpp              # Shared data types, enums, Utils (BCrypt hashing, timestamps)
│   ├── console.hpp             # Virtual terminal ANSI color & console interface
│   ├── http_client.hpp         # High-performance WinHTTP client, ThreadPool & RateLimiter
│   ├── config_manager.hpp      # Windows DPAPI encrypted credential vault
│   ├── license.hpp             # Hardware-bound machine license validation
│   ├── report_generator.hpp    # Automatic TXT intelligence report compiler
│   ├── api_registry.hpp        # Centralized 20+ OSINT API catalog
│   ├── menu.hpp                # Interactive 23-option menu
│   └── modules.hpp             # Interfaces for all intelligence modules
├── src/
│   ├── main.cpp                # Application entrypoint with SEH wrapper
│   ├── application.cpp         # Lifecycle, startup sequence, CLI arg parser
│   ├── console.cpp             # Windows console implementation
│   ├── utils.cpp               # Windows BCrypt hashing & string utilities
│   ├── http_client.cpp         # WinHTTP 2.0 network engine implementation
│   ├── config_manager.cpp      # DPAPI encryption & settings persistence
│   ├── license.cpp             # Host GUID licensing algorithms
│   ├── report_generator.cpp    # Report writer & dossier management
│   ├── api_registry.cpp        # Registered APIs & health checks
│   ├── menu.cpp                # Menu dispatching & command routing
│   └── modules/                # 22 dedicated intelligence module implementations
│       ├── username.cpp
│       ├── email.cpp
│       ├── phone.cpp
│       ├── ip.cpp
│       ├── domain.cpp
│       ├── website.cpp
│       ├── discord.cpp
│       ├── github.cpp
│       ├── social.cpp
│       ├── breach.cpp
│       ├── dns.cpp
│       ├── whois.cpp
│       ├── network.cpp
│       ├── url_rep.cpp
│       ├── hash.cpp
│       ├── threat.cpp
│       ├── profile.cpp
│       ├── searchengine.cpp
│       ├── comprehensive.cpp
│       ├── report_manager.cpp
│       ├── api_status.cpp
│       └── settings.cpp
├── assets/
│   └── logo.txt                # ASCII art banner
├── CMakeLists.txt              # Standard CMake build script
├── build.bat                   # Standalone MSVC compilation batch script
└── XIII_0S1nt.exe              # Fully compiled standalone executable
```

---
*Created by Findhost $ Travma - XIII 0S1nt Intelligence Platform*
