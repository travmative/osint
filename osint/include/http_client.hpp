#pragma once

#include <string>
#include <vector>
#include <map>
#include <future>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <functional>
#include <atomic>
#include <nlohmann/json.hpp>

namespace XIII {

    struct HttpResponse {
        int statusCode{0};
        std::string body;
        std::map<std::string, std::string> headers;
        long long elapsedMilliseconds{0};
        std::string errorMessage;
        bool success{false};
        
        nlohmann::json AsJson() const {
            try {
                return nlohmann::json::parse(body);
            } catch (...) {
                return nlohmann::json::object();
            }
        }

        bool IsJson() const {
            try {
                auto j = nlohmann::json::parse(body);
                return !j.is_null();
            } catch (...) {
                return false;
            }
        }
    };

    struct HttpRequestOptions {
        int timeoutSeconds{12};
        int maxRetries{2};
        bool followRedirects{true};
        std::string userAgent{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) XIII-0S1nt-Engine/2.4"};
        std::map<std::string, std::string> headers;
        std::string proxy;
    };

    class RateLimiter {
    public:
        RateLimiter(int requestsPerMinute = 60);
        void Acquire();

    private:
        int m_ratePerMinute;
        std::chrono::milliseconds m_minInterval;
        std::chrono::steady_clock::time_point m_lastRequestTime;
        std::mutex m_mutex;
    };

    class ThreadPool {
    public:
        explicit ThreadPool(size_t threads = 8);
        ~ThreadPool();

        template<class F, class... Args>
        auto Enqueue(F&& f, Args&&... args) 
            -> std::future<typename std::invoke_result<F, Args...>::type> {
            using return_type = typename std::invoke_result<F, Args...>::type;

            auto task = std::make_shared<std::packaged_task<return_type()>>(
                std::bind(std::forward<F>(f), std::forward<Args>(args)...)
            );
            
            std::future<return_type> res = task->get_future();
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                if (m_stop) {
                    throw std::runtime_error("Enqueue on stopped ThreadPool");
                }
                m_tasks.emplace([task]() { (*task)(); });
            }
            m_cv.notify_one();
            return res;
        }

        void WaitAll();
        void Shutdown();

    private:
        std::vector<std::thread> m_workers;
        std::queue<std::function<void()>> m_tasks;
        std::mutex m_queueMutex;
        std::condition_variable m_cv;
        std::condition_variable m_waitCv;
        std::atomic<bool> m_stop{false};
        std::atomic<size_t> m_activeTasks{0};
    };

    class HttpClient {
    public:
        static HttpClient& Instance();

        HttpResponse Get(const std::string& url, const HttpRequestOptions& options = HttpRequestOptions());
        HttpResponse Post(const std::string& url, const std::string& postData, const std::string& contentType = "application/json", const HttpRequestOptions& options = HttpRequestOptions());

        void SetGlobalUserAgent(const std::string& ua);
        void SetGlobalTimeout(int seconds);
        void SetGlobalProxy(const std::string& proxy);

        // Per-provider rate limiter lookup
        void RegisterRateLimiter(const std::string& host, int requestsPerMinute);
        void AcquireRateLimit(const std::string& host);

    private:
        HttpClient();
        ~HttpClient();

        std::string m_globalUserAgent{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) XIII-0S1nt/2.4"};
        int m_globalTimeoutSeconds{12};
        std::string m_globalProxy;
        void* m_hSession{nullptr}; // HINTERNET session

        std::mutex m_limiterMutex;
        std::map<std::string, std::shared_ptr<RateLimiter>> m_rateLimiters;

        HttpResponse ExecuteWinHttpRequest(
            const std::string& verb,
            const std::string& url,
            const std::string& body,
            const std::string& contentType,
            const HttpRequestOptions& options
        );

        std::string ExtractHost(const std::string& url);
    };

} // namespace XIII
