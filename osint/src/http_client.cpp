#define NOMINMAX
#include "http_client.hpp"
#include "common.hpp"
#include <windows.h>
#include <winhttp.h>
#include <thread>
#include <iostream>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

namespace XIII {

    static std::string WideToUtf8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), strTo.data(), sizeNeeded, NULL, NULL);
        return strTo;
    }

    // --- ThreadPool Implementation ---
    ThreadPool::ThreadPool(size_t threads) {
        for (size_t i = 0; i < threads; ++i) {
            m_workers.emplace_back([this]() {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->m_queueMutex);
                        this->m_cv.wait(lock, [this]() {
                            return this->m_stop || !this->m_tasks.empty();
                        });
                        if (this->m_stop && this->m_tasks.empty()) {
                            return;
                        }
                        task = std::move(this->m_tasks.front());
                        this->m_tasks.pop();
                        ++m_activeTasks;
                    }
                    task();
                    {
                        std::unique_lock<std::mutex> lock(this->m_queueMutex);
                        --m_activeTasks;
                        if (m_tasks.empty() && m_activeTasks == 0) {
                            m_waitCv.notify_all();
                        }
                    }
                }
            });
        }
    }

    ThreadPool::~ThreadPool() {
        Shutdown();
    }

    void ThreadPool::WaitAll() {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_waitCv.wait(lock, [this]() {
            return m_tasks.empty() && m_activeTasks == 0;
        });
    }

    void ThreadPool::Shutdown() {
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            if (m_stop) return;
            m_stop = true;
        }
        m_cv.notify_all();
        m_waitCv.notify_all();
        for (std::thread& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    // --- RateLimiter Implementation ---
    RateLimiter::RateLimiter(int requestsPerMinute)
        : m_ratePerMinute(requestsPerMinute) {
        if (m_ratePerMinute <= 0) m_ratePerMinute = 60;
        m_minInterval = std::chrono::milliseconds(60000 / m_ratePerMinute);
        m_lastRequestTime = std::chrono::steady_clock::now() - m_minInterval;
    }

    void RateLimiter::Acquire() {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastRequestTime);
        if (elapsed < m_minInterval) {
            std::this_thread::sleep_for(m_minInterval - elapsed);
        }
        m_lastRequestTime = std::chrono::steady_clock::now();
    }

    // --- HttpClient Implementation ---
    HttpClient& HttpClient::Instance() {
        static HttpClient instance;
        return instance;
    }

    HttpClient::HttpClient() {
        // Initialize WinHTTP Session with TLS 1.2/1.3 and proxy support
        m_hSession = WinHttpOpen(
            L"XIII-0S1nt-Engine/2.4 (Windows NT 10.0; Win64; x64)",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (m_hSession) {
            // Enable HTTP/2 and modern protocols if supported
            DWORD protocols = WINHTTP_PROTOCOL_FLAG_HTTP2;
            WinHttpSetOption(m_hSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protocols, sizeof(protocols));
        }

        // Register default rate limiters for common services
        RegisterRateLimiter("api.github.com", 60);
        RegisterRateLimiter("haveibeenpwned.com", 30);
        RegisterRateLimiter("ip-api.com", 45);
        RegisterRateLimiter("ipwho.is", 60);
        RegisterRateLimiter("dns.google", 120);
        RegisterRateLimiter("cloudflare-dns.com", 120);
        RegisterRateLimiter("rdap.org", 60);
        RegisterRateLimiter("crt.sh", 20);
        RegisterRateLimiter("urlhaus-api.abuse.ch", 60);
        RegisterRateLimiter("threatfox-api.abuse.ch", 60);
        RegisterRateLimiter("mb-api.abuse.ch", 60);
        RegisterRateLimiter("hashlookup.circl.lu", 60);
        RegisterRateLimiter("www.cisa.gov", 60);
    }

    HttpClient::~HttpClient() {
        if (m_hSession) {
            WinHttpCloseHandle(m_hSession);
            m_hSession = nullptr;
        }
    }

    void HttpClient::SetGlobalUserAgent(const std::string& ua) {
        m_globalUserAgent = ua;
    }

    void HttpClient::SetGlobalTimeout(int seconds) {
        m_globalTimeoutSeconds = seconds;
    }

    void HttpClient::SetGlobalProxy(const std::string& proxy) {
        m_globalProxy = proxy;
    }

    void HttpClient::RegisterRateLimiter(const std::string& host, int requestsPerMinute) {
        std::lock_guard<std::mutex> lock(m_limiterMutex);
        m_rateLimiters[Utils::ToLower(host)] = std::make_shared<RateLimiter>(requestsPerMinute);
    }

    void HttpClient::AcquireRateLimit(const std::string& host) {
        std::shared_ptr<RateLimiter> limiter;
        {
            std::lock_guard<std::mutex> lock(m_limiterMutex);
            auto it = m_rateLimiters.find(Utils::ToLower(host));
            if (it != m_rateLimiters.end()) {
                limiter = it->second;
            }
        }
        if (limiter) {
            limiter->Acquire();
        }
    }

    std::string HttpClient::ExtractHost(const std::string& url) {
        size_t start = url.find("://");
        if (start == std::string::npos) start = 0;
        else start += 3;
        size_t end = url.find_first_of("/:?#", start);
        if (end == std::string::npos) return url.substr(start);
        return url.substr(start, end - start);
    }

    HttpResponse HttpClient::Get(const std::string& url, const HttpRequestOptions& options) {
        return ExecuteWinHttpRequest("GET", url, "", "", options);
    }

    HttpResponse HttpClient::Post(const std::string& url, const std::string& postData, const std::string& contentType, const HttpRequestOptions& options) {
        return ExecuteWinHttpRequest("POST", url, postData, contentType, options);
    }

    HttpResponse HttpClient::ExecuteWinHttpRequest(
        const std::string& verb,
        const std::string& url,
        const std::string& body,
        const std::string& contentType,
        const HttpRequestOptions& options) 
    {
        std::string host = ExtractHost(url);
        AcquireRateLimit(host);

        int maxRetries = options.maxRetries;
        int attempt = 0;
        HttpResponse response;

        while (attempt <= maxRetries) {
            auto startTime = std::chrono::steady_clock::now();

            std::wstring wideUrl(url.begin(), url.end());
            URL_COMPONENTS urlComp = {0};
            urlComp.dwStructSize = sizeof(urlComp);
            urlComp.dwSchemeLength    = (DWORD)-1;
            urlComp.dwHostNameLength  = (DWORD)-1;
            urlComp.dwUrlPathLength   = (DWORD)-1;
            urlComp.dwExtraInfoLength = (DWORD)-1;

            if (!WinHttpCrackUrl(wideUrl.c_str(), (DWORD)wideUrl.length(), 0, &urlComp)) {
                response.errorMessage = "Failed to parse URL";
                response.statusCode = 0;
                return response;
            }

            std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
            std::wstring urlPath = (urlComp.dwUrlPathLength > 0) ? std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength) : L"/";
            if (urlComp.dwExtraInfoLength > 0) {
                urlPath += std::wstring(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
            }

            HINTERNET hConnect = WinHttpConnect(m_hSession, hostName.c_str(), urlComp.nPort, 0);
            if (!hConnect) {
                response.errorMessage = "WinHttpConnect failed: " + std::to_string(GetLastError());
                ++attempt;
                std::this_thread::sleep_for(std::chrono::milliseconds(500 * (1 << attempt)));
                continue;
            }

            DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
            std::wstring wideVerb(verb.begin(), verb.end());

            HINTERNET hRequest = WinHttpOpenRequest(
                hConnect,
                wideVerb.c_str(),
                urlPath.c_str(),
                NULL,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                flags
            );

            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                response.errorMessage = "WinHttpOpenRequest failed: " + std::to_string(GetLastError());
                ++attempt;
                continue;
            }

            // Set timeouts
            int timeoutMs = (options.timeoutSeconds > 0 ? options.timeoutSeconds : m_globalTimeoutSeconds) * 1000;
            WinHttpSetTimeouts(hRequest, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

            // Follow redirects
            DWORD optRedirect = options.followRedirects ? WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS : WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &optRedirect, sizeof(optRedirect));

            // Set headers
            std::wstring headers;
            if (!contentType.empty()) {
                headers += L"Content-Type: " + std::wstring(contentType.begin(), contentType.end()) + L"\r\n";
            }
            if (!options.userAgent.empty()) {
                headers += L"User-Agent: " + std::wstring(options.userAgent.begin(), options.userAgent.end()) + L"\r\n";
            }
            for (const auto& [k, v] : options.headers) {
                headers += std::wstring(k.begin(), k.end()) + L": " + std::wstring(v.begin(), v.end()) + L"\r\n";
            }

            BOOL bResults = WinHttpSendRequest(
                hRequest,
                headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                (DWORD)headers.length(),
                body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                (DWORD)body.length(),
                (DWORD)body.length(),
                0
            );

            if (bResults) {
                bResults = WinHttpReceiveResponse(hRequest, NULL);
            }

            if (bResults) {
                DWORD statusCode = 0;
                DWORD size = sizeof(statusCode);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
                response.statusCode = static_cast<int>(statusCode);

                // Read response headers
                DWORD headerSize = 0;
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &headerSize, WINHTTP_NO_HEADER_INDEX);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<wchar_t> headerBuf(headerSize / sizeof(wchar_t) + 1);
                    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, headerBuf.data(), &headerSize, WINHTTP_NO_HEADER_INDEX)) {
                        // Parse headers
                        std::wstring rawHeaders(headerBuf.data());
                        std::wstringstream wss(rawHeaders);
                        std::wstring line;
                        while (std::getline(wss, line)) {
                            size_t colon = line.find(L":");
                            if (colon != std::wstring::npos) {
                                std::wstring hk = line.substr(0, colon);
                                std::wstring hv = line.substr(colon + 1);
                                while (!hv.empty() && (hv.front() == L' ' || hv.front() == L'\t')) hv.erase(0, 1);
                                while (!hv.empty() && (hv.back() == L'\r' || hv.back() == L'\n')) hv.pop_back();
                                response.headers[WideToUtf8(hk)] = WideToUtf8(hv);
                            }
                        }
                    }
                }

                // Read response body
                DWORD bytesAvailable = 0;
                std::string bodyBuffer;
                while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
                    std::vector<char> tempBuf(bytesAvailable);
                    DWORD bytesRead = 0;
                    if (WinHttpReadData(hRequest, tempBuf.data(), bytesAvailable, &bytesRead) && bytesRead > 0) {
                        bodyBuffer.append(tempBuf.data(), bytesRead);
                    } else {
                        break;
                    }
                }
                response.body = std::move(bodyBuffer);
                response.success = true;

                auto endTime = std::chrono::steady_clock::now();
                response.elapsedMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);

                // If transient server error (502/503/504) or rate limit (429), maybe retry
                if ((response.statusCode == 429 || response.statusCode == 503 || response.statusCode == 504) && attempt < maxRetries) {
                    ++attempt;
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000 * (1 << attempt)));
                    continue;
                }

                return response;
            } else {
                response.errorMessage = "WinHttp request failed: " + std::to_string(GetLastError());
                response.statusCode = 0;
                response.success = false;
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);

            ++attempt;
            std::this_thread::sleep_for(std::chrono::milliseconds(500 * (1 << attempt)));
        }

        return response;
    }

} // namespace XIII
