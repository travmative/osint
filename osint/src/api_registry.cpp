#include "api_registry.hpp"
#include "http_client.hpp"
#include "config_manager.hpp"

namespace XIII {

    ApiRegistry& ApiRegistry::Instance() {
        static ApiRegistry instance;
        return instance;
    }

    ApiRegistry::ApiRegistry() {
        Initialize();
    }

    void ApiRegistry::Initialize() {
        RegisterDefaults();
    }

    void ApiRegistry::RegisterDefaults() {
        m_endpoints.clear();

        // 1. IP-API
        m_endpoints.push_back({
            "ip_api", "IP-API Geolocation Engine", "IP Intelligence",
            "https://ip-api.com/docs/api:json",
            AuthType::None, "", "Free for non-commercial use", "45 requests/minute",
            {"IPv4", "IPv6", "ASN", "ISP"}, "JSON",
            "HTTP 429 when quota exceeded. Returns status: 'fail'.", "Non-commercial only (Pro key available)",
            true, true, true, 0, "http://ip-api.com/json/8.8.8.8"
        });

        // 2. ipwho.is
        m_endpoints.push_back({
            "ipwhois", "ipwho.is Threat & Geo API", "IP Intelligence",
            "https://ipwhois.io/documentation",
            AuthType::None, "", "10,000 requests/month free", "Rate limited per second",
            {"IP", "ASN", "Timezone", "Security flags"}, "JSON",
            "Returns success: false with message object.", "Permitted under free tier policy",
            true, true, true, 0, "https://ipwho.is/8.8.8.8"
        });

        // 3. BGPView
        m_endpoints.push_back({
            "bgpview", "BGPView Global Routing Engine", "Network Intelligence",
            "https://bgpview.docs.apiary.io/",
            AuthType::None, "", "Unlimited reasonable research queries", "Fair use",
            {"IP routing", "ASN details", "Peers", "Prefixes"}, "JSON",
            "Standard HTTP error codes. Status: 'ok' in JSON body.", "Open research and intelligence",
            true, true, true, 0, "https://api.bgpview.io/ip/8.8.8.8"
        });

        // 4. Google DNS-over-HTTPS
        m_endpoints.push_back({
            "google_doh", "Google DNS-over-HTTPS", "DNS Intelligence",
            "https://developers.google.com/speed/public-dns/docs/doh",
            AuthType::None, "", "Free public infrastructure", "Generous fair use",
            {"A", "AAAA", "MX", "TXT", "NS", "SOA", "PTR", "CAA"}, "JSON",
            "Returns Status field (RFC standard DNS RCODEs).", "Permitted for general queries",
            true, true, true, 0, "https://dns.google/resolve?name=example.com&type=A"
        });

        // 5. Cloudflare DNS-over-HTTPS
        m_endpoints.push_back({
            "cloudflare_doh", "Cloudflare 1.1.1.1 DoH", "DNS Intelligence",
            "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
            AuthType::None, "", "Free public infrastructure", "Generous fair use",
            {"All standard DNS record types"}, "application/dns-json",
            "Requires Accept: application/dns-json header.", "Permitted under terms",
            true, true, true, 0, "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
        });

        // 6. crt.sh (Certificate Transparency)
        m_endpoints.push_back({
            "crt_sh", "crt.sh Certificate Transparency Logs", "Domain Intelligence",
            "https://crt.sh/",
            AuthType::None, "", "Free open PostgreSQL web service", "Polite querying recommended",
            {"Domain", "Subdomains", "Wildcards", "SSL Certs"}, "JSON",
            "May return 504 on massive wildcards; retry with exact matches.", "Open Public Service",
            true, true, true, 0, "https://crt.sh/?q=example.com&output=json"
        });

        // 7. RDAP.org (ICANN / Regional Registries)
        m_endpoints.push_back({
            "rdap", "RDAP Universal Federation Gateway", "WHOIS / RDAP",
            "https://rdap.org/",
            AuthType::None, "", "Free open registry redirector", "Governed by target RIR",
            {"Domain registration", "Registrar", "Dates", "IP allocations"}, "JSON",
            "Follows HTTP 302/307 redirects to authoritative RIR/TLD.", "Official RFC 7484 Standard",
            true, true, true, 0, "https://rdap.org/domain/google.com"
        });

        // 8. URLhaus (abuse.ch)
        m_endpoints.push_back({
            "urlhaus", "abuse.ch URLhaus Threat Feed", "Threat Intelligence",
            "https://urlhaus.abuse.ch/api/",
            AuthType::None, "", "Completely free open community feed", "Fair use",
            {"Malicious URLs", "Payload tags", "Status", "Blacklist"}, "JSON",
            "Query status: 'ok', 'no_results', 'invalid_url'.", "Free security sharing",
            true, true, true, 0, "https://urlhaus-api.abuse.ch/v1/host/"
        });

        // 9. ThreatFox (abuse.ch)
        m_endpoints.push_back({
            "threatfox", "abuse.ch ThreatFox IOC Search", "Threat Intelligence",
            "https://threatfox.abuse.ch/api/",
            AuthType::None, "", "Completely free open intelligence", "Fair use",
            {"Indicators of Compromise", "Hashes", "Domains", "Malware families"}, "JSON",
            "POST JSON queries. Response contains query_status.", "Open community intelligence",
            true, true, true, 0, "https://threatfox-api.abuse.ch/v1/"
        });

        // 10. MalwareBazaar (abuse.ch)
        m_endpoints.push_back({
            "malwarebazaar", "abuse.ch MalwareBazaar Hash Lookup", "File Hash Intelligence",
            "https://bazaar.abuse.ch/api/",
            AuthType::None, "", "Free malware analysis repository", "Fair use",
            {"SHA256", "MD5", "SHA1", "Signature", "File type"}, "JSON",
            "POST form data query=get_info. Returns query_status: 'ok'.", "Permitted for defenders",
            true, true, true, 0, "https://mb-api.abuse.ch/api/v1/"
        });

        // 11. CIRCL Hashlookup
        m_endpoints.push_back({
            "circl_hash", "CIRCL Luxembourg Hashlookup", "File Hash Intelligence",
            "https://hashlookup.circl.lu/",
            AuthType::None, "", "Free European CERT service", "Polite querying",
            {"NSRL Known good files", "Known benign hashes"}, "JSON",
            "HTTP 404 when file hash is unknown.", "Open research and defense",
            true, true, true, 0, "https://hashlookup.circl.lu/lookup/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        });

        // 12. CISA KEV
        m_endpoints.push_back({
            "cisa_kev", "CISA Known Exploited Vulnerabilities", "Vulnerability Intelligence",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            AuthType::None, "", "US Government Public Dataset", "Unlimited",
            {"CVE identifiers", "Vendor", "Product", "Exploited in wild"}, "JSON",
            "Full JSON catalog refreshed daily.", "Public domain / US Federal",
            true, true, true, 0, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        });

        // 13. GitHub API
        m_endpoints.push_back({
            "github_api", "GitHub Public REST API", "Developer Intelligence",
            "https://docs.github.com/en/rest",
            AuthType::FreeKeyOptional, "GITHUB_TOKEN", "60 req/hr unauth, 5000 req/hr auth", "60/hr or 5k/hr",
            {"User profiles", "Public keys", "Repositories", "Organizations"}, "JSON",
            "Check X-RateLimit-Remaining header. Returns 404 on absent user.", "Permitted under terms",
            true, ConfigManager::Instance().HasApiKey("GITHUB_TOKEN"), true, 0, "https://api.github.com/users/octocat"
        });

        // 14. Hacker News Firebase
        m_endpoints.push_back({
            "hn_api", "Hacker News Official API", "Developer Intelligence",
            "https://github.com/HackerNews/API",
            AuthType::None, "", "Completely free open API", "Fair use",
            {"User handle", "Created timestamp", "Karma", "Bio/About"}, "JSON",
            "Returns 'null' literal when user is not found.", "Free community API",
            true, true, true, 0, "https://hacker-news.firebaseio.com/v0/user/jl.json"
        });

        // 15. Have I Been Pwned Passwords
        m_endpoints.push_back({
            "hibp_passwords", "HIBP Pwned Passwords (k-Anonymity)", "Data Breach Intelligence",
            "https://haveibeenpwned.com/API/v3#PwnedPasswords",
            AuthType::None, "", "Unlimited free k-anonymity protocol", "Fair use",
            {"SHA-1 password prefix (5 chars)"}, "Text (Hash suffixes and counts)",
            "Never sends complete passwords. 100% privacy preserving.", "Open privacy research",
            true, true, true, 0, "https://api.pwnedpasswords.com/range/21BD1"
        });

        // 16. Have I Been Pwned Account Breaches
        m_endpoints.push_back({
            "hibp_breaches", "HIBP Breached Account API", "Data Breach Intelligence",
            "https://haveibeenpwned.com/API/v3#BreachesForAccount",
            AuthType::FreeKeyRequired, "HIBP_API_KEY", "Paid / Authorized HIBP Key required", "1 request per 1.5s",
            {"Email address breach lookup"}, "JSON",
            "Requires hibp-api-key header. 404 = clean/no breaches.", "Requires individual license",
            true, ConfigManager::Instance().HasApiKey("HIBP_API_KEY"), false, 0, "https://haveibeenpwned.com/api/v3/breaches"
        });

        // 17. VirusTotal API
        m_endpoints.push_back({
            "virustotal", "VirusTotal Public API v3", "Threat Intelligence",
            "https://developers.virustotal.com/reference/overview",
            AuthType::FreeKeyRequired, "VIRUSTOTAL_API_KEY", "500 req/day, 4 req/min free", "4 requests/minute",
            {"File hash", "URL", "Domain", "IP Address"}, "JSON",
            "Requires x-apikey header. Returns 404 for unknown hashes.", "Non-commercial free tier",
            true, ConfigManager::Instance().HasApiKey("VIRUSTOTAL_API_KEY"), false, 0, "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
        });

        // 18. AbuseIPDB API
        m_endpoints.push_back({
            "abuseipdb", "AbuseIPDB Threat Check", "IP Intelligence",
            "https://docs.abuseipdb.com/",
            AuthType::FreeKeyRequired, "ABUSEIPDB_API_KEY", "1000 requests/day free tier", "Fair use",
            {"IP abuse confidence score", "Total reports", "Country"}, "JSON",
            "Requires Key header. Returns JSON object with data.", "Personal / non-commercial free",
            true, ConfigManager::Instance().HasApiKey("ABUSEIPDB_API_KEY"), false, 0, "https://api.abuseipdb.com/api/v2/check"
        });

        // 19. GreyNoise Community
        m_endpoints.push_back({
            "greynoise", "GreyNoise Community API", "Threat Intelligence",
            "https://docs.greynoise.io/reference/get_v3-community-ip",
            AuthType::FreeKeyRequired, "GREYNOISE_API_KEY", "Free community key available", "Rate limited",
            {"Mass-scanner classification", "Noise detection", "Riot IP"}, "JSON",
            "Requires key header. 404 = not internet background noise.", "Community use permitted",
            true, ConfigManager::Instance().HasApiKey("GREYNOISE_API_KEY"), false, 0, "https://api.greynoise.io/v3/community/8.8.8.8"
        });

        // 20. Internet Archive Wayback Machine
        m_endpoints.push_back({
            "wayback", "Internet Archive Wayback Availability", "Website Intelligence",
            "https://archive.org/help/wayback_api.php",
            AuthType::None, "", "Free open archival service", "Polite querying",
            {"Domain", "URL history", "Snapshot availability"}, "JSON",
            "Returns closest snapshot metadata.", "Public educational use",
            true, true, true, 0, "https://archive.org/wayback/available?url=example.com"
        });
    }

    const std::vector<ApiEndpointInfo>& ApiRegistry::GetAllEndpoints() const {
        return m_endpoints;
    }

    ApiEndpointInfo* ApiRegistry::GetEndpoint(const std::string& id) {
        for (auto& ep : m_endpoints) {
            if (ep.id == id) return &ep;
        }
        return nullptr;
    }

    void ApiRegistry::SetEndpointEnabled(const std::string& id, bool enabled) {
        ApiEndpointInfo* ep = GetEndpoint(id);
        if (ep) {
            ep->isEnabled = enabled;
        }
    }

    bool ApiRegistry::TestEndpoint(ApiEndpointInfo& endpoint) {
        if (endpoint.testEndpointUrl.empty()) return false;

        HttpRequestOptions opts;
        opts.timeoutSeconds = 6;
        opts.maxRetries = 0;

        if (endpoint.authType == AuthType::FreeKeyRequired || endpoint.authType == AuthType::FreeKeyOptional) {
            std::string key = ConfigManager::Instance().GetApiKey(endpoint.envOrConfigKey);
            if (!key.empty()) {
                if (endpoint.id == "virustotal") opts.headers["x-apikey"] = key;
                else if (endpoint.id == "hibp_breaches") opts.headers["hibp-api-key"] = key;
                else if (endpoint.id == "abuseipdb") opts.headers["Key"] = key;
                else if (endpoint.id == "greynoise") opts.headers["key"] = key;
                else if (endpoint.id == "github_api") opts.headers["Authorization"] = "token " + key;
                endpoint.isConfigured = true;
            } else {
                endpoint.isConfigured = false;
                if (endpoint.authType == AuthType::FreeKeyRequired) {
                    endpoint.isOperational = false;
                    endpoint.lastLatencyMs = -1;
                    return false;
                }
            }
        }

        if (endpoint.id == "cloudflare_doh") {
            opts.headers["Accept"] = "application/dns-json";
        }

        auto res = HttpClient::Instance().Get(endpoint.testEndpointUrl, opts);
        endpoint.lastLatencyMs = res.elapsedMilliseconds;
        endpoint.isOperational = (res.statusCode >= 200 && res.statusCode < 400);
        return endpoint.isOperational;
    }

    void ApiRegistry::RefreshAllStatuses() {
        for (auto& ep : m_endpoints) {
            if (ep.isEnabled) {
                TestEndpoint(ep);
            }
        }
    }

} // namespace XIII
