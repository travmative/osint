#include "common.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <random>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace XIII {

    std::string Utils::GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        localtime_s(&tm_buf, &now_time);
        
        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S UTC");
        return ss.str();
    }

    std::string Utils::GetTimestampForFilename() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        localtime_s(&tm_buf, &now_time);
        
        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y%m%d_%H%M%S");
        return ss.str();
    }

    std::string Utils::Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    std::string Utils::ToLower(const std::string& str) {
        std::string res = str;
        std::transform(res.begin(), res.end(), res.begin(), [](unsigned char c) { return std::tolower(c); });
        return res;
    }

    std::string Utils::ToUpper(const std::string& str) {
        std::string res = str;
        std::transform(res.begin(), res.end(), res.begin(), [](unsigned char c) { return std::toupper(c); });
        return res;
    }

    bool Utils::CaseInsensitiveCompare(const std::string& a, const std::string& b) {
        if (a.length() != b.length()) return false;
        return std::equal(a.begin(), a.end(), b.begin(), [](char a_c, char b_c) {
            return std::tolower(static_cast<unsigned char>(a_c)) == std::tolower(static_cast<unsigned char>(b_c));
        });
    }

    std::string Utils::UrlEncode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (auto i = value.begin(); i != value.end(); ++i) {
            std::string::value_type c = (*i);
            if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << int((unsigned char)c);
                escaped << std::nouppercase;
            }
        }
        return escaped.str();
    }

    std::string Utils::SanitizeFilename(const std::string& name) {
        std::string res = name;
        for (char& c : res) {
            if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c == '@' || c == ' ') {
                c = '_';
            }
        }
        return res;
    }

    std::string Utils::GenerateUUID() {
        GUID guid;
        CoCreateGuid(&guid);
        char guidStr[64];
        snprintf(guidStr, sizeof(guidStr),
            "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return std::string(guidStr);
    }

    static std::string HashBytes(const void* data, size_t length, LPCWSTR algId) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algId, NULL, 0);
        if (status < 0) return "";

        DWORD cbHash = 0, cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (status < 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        std::vector<BYTE> hash(cbHash);
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (status >= 0) {
            BCryptHashData(hHash, (PBYTE)data, (ULONG)length, 0);
            BCryptFinishHash(hHash, hash.data(), cbHash, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::ostringstream ss;
        for (BYTE b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }

    std::string Utils::CalculateMD5(const std::string& input) {
        return HashBytes(input.data(), input.length(), BCRYPT_MD5_ALGORITHM);
    }

    std::string Utils::CalculateSHA1(const std::string& input) {
        return HashBytes(input.data(), input.length(), BCRYPT_SHA1_ALGORITHM);
    }

    std::string Utils::CalculateSHA256(const std::string& input) {
        return HashBytes(input.data(), input.length(), BCRYPT_SHA256_ALGORITHM);
    }

    std::string Utils::CalculateFileHash(const std::string& filePath, const std::string& algorithm) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return "";

        LPCWSTR alg = BCRYPT_SHA256_ALGORITHM;
        if (Utils::ToLower(algorithm) == "md5") alg = BCRYPT_MD5_ALGORITHM;
        else if (Utils::ToLower(algorithm) == "sha1") alg = BCRYPT_SHA1_ALGORITHM;

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        if (BCryptOpenAlgorithmProvider(&hAlg, alg, NULL, 0) < 0) return "";

        DWORD cbHash = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> hash(cbHash);

        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) >= 0) {
            std::vector<char> buffer(65536);
            while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
                BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)file.gcount(), 0);
            }
            BCryptFinishHash(hHash, hash.data(), cbHash, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::ostringstream ss;
        for (BYTE b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }

} // namespace XIII
