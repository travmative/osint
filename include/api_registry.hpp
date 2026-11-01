#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace XIII {

    enum class AuthType {
        None,             // No key required, completely public
        FreeKeyOptional,  // Works without key (rate-limited), enhanced with key
        FreeKeyRequired,  // Free tier requires free registration/key
        CommercialKey     // Paid / Enterprise key
    };

    struct ApiEndpointInfo {
        std::string id;
        std::string name;
        std::string category;
        std::string docUrl;
        AuthType authType;
        std::string envOrConfigKey;
        std::string freeTierLimits;
        std::string rateLimits;
        std::vector<std::string> supportedSearchTypes;
        std::string responseFormat;
        std::string errorHandlingNotes;
        std::string commercialUsage;
        bool isEnabled{true};
        bool isConfigured{false};
        bool isOperational{false};
        long long lastLatencyMs{-1};
        std::string testEndpointUrl;
    };

    class ApiRegistry {
    public:
        static ApiRegistry& Instance();

        void Initialize();
        const std::vector<ApiEndpointInfo>& GetAllEndpoints() const;
        ApiEndpointInfo* GetEndpoint(const std::string& id);
        void SetEndpointEnabled(const std::string& id, bool enabled);
        
        void RefreshAllStatuses();
        bool TestEndpoint(ApiEndpointInfo& endpoint);

    private:
        ApiRegistry();
        ~ApiRegistry() = default;

        void RegisterDefaults();
        std::vector<ApiEndpointInfo> m_endpoints;
    };

} // namespace XIII
