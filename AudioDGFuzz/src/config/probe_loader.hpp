#pragma once
#ifndef AUDIODGFUZZ_PROBE_LOADER_HPP
#define AUDIODGFUZZ_PROBE_LOADER_HPP

#include <string>
#include <vector>
#include <optional>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstdint>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// API type and mutation strategies for AudioDGFuzz probes
// -----------------------------------------------------------------------
enum class ApiType { WASAPI, APO };

enum class ParamStrategy : uint32_t {
    Fixed            = 0,
    BoundaryMin      = 1 << 0,
    BoundaryZero     = 1 << 1,
    BoundaryMax      = 1 << 2,
    NegativeValue    = 1 << 3,
    Random           = 1 << 4,
    BitFlip          = 1 << 5,
    ValidBase        = 1 << 6,
    MutateChannels   = 1 << 7,
    MutateBlockAlign = 1 << 8,
    MutateSampleRate = 1 << 9,
    MutateBitsPerSample = 1 << 10,
    WFXExtensible    = 1 << 11,
    RandomGarbage    = 1 << 12,
    AllZeros         = 1 << 13,
    AllFF            = 1 << 14,
    NanFloats        = 1 << 15,
    InfFloats        = 1 << 16,
    Denormals        = 1 << 17,
    BoundaryValues   = 1 << 18,
    WrongSize        = 1 << 19,
    All              = 0xFFFFFFFF
};

inline ParamStrategy operator|(ParamStrategy a, ParamStrategy b) {
    return static_cast<ParamStrategy>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool HasStrategy(ParamStrategy mask, ParamStrategy bit) {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(bit)) != 0;
}

// -----------------------------------------------------------------------
// Single parameter specification from YAML
// -----------------------------------------------------------------------
struct ParamSpec {
    std::string                name;
    std::string                type;
    std::optional<std::string> fixed_value;
    std::vector<ParamStrategy> strategies;
};

// -----------------------------------------------------------------------
// Full probe configuration
// -----------------------------------------------------------------------
struct ProbeConfig {
    std::string          name;
    ApiType              api{ApiType::WASAPI};
    std::string          interface_name;
    std::string          method;
    std::string          platform;
    std::string          description;
    std::vector<ParamSpec> params;
    std::vector<std::string> expect;
};

// -----------------------------------------------------------------------
// Minimal hand-rolled YAML parser — only scalar strings, lists, mappings
// Error on unsupported constructs
// -----------------------------------------------------------------------
namespace detail {

inline std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    return (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
}

inline std::string StripComment(const std::string& s) {
    auto pos = s.find('#');
    return (pos != std::string::npos) ? s.substr(0, pos) : s;
}

inline ApiType ParseApiType(const std::string& s) {
    if (s == "APO")   return ApiType::APO;
    return ApiType::WASAPI; // default
}

inline ParamStrategy ParseSingleStrategy(const std::string& s) {
    static const std::unordered_map<std::string, ParamStrategy> kMap = {
        {"Fixed",              ParamStrategy::Fixed},
        {"BoundaryMin",        ParamStrategy::BoundaryMin},
        {"BoundaryZero",       ParamStrategy::BoundaryZero},
        {"BoundaryMax",        ParamStrategy::BoundaryMax},
        {"NegativeValue",      ParamStrategy::NegativeValue},
        {"Random",             ParamStrategy::Random},
        {"BitFlip",            ParamStrategy::BitFlip},
        {"ValidBase",          ParamStrategy::ValidBase},
        {"MutateChannels",     ParamStrategy::MutateChannels},
        {"MutateBlockAlign",   ParamStrategy::MutateBlockAlign},
        {"MutateSampleRate",   ParamStrategy::MutateSampleRate},
        {"MutateBitsPerSample",ParamStrategy::MutateBitsPerSample},
        {"WFXExtensible",      ParamStrategy::WFXExtensible},
        {"RandomGarbage",      ParamStrategy::RandomGarbage},
        {"AllZeros",           ParamStrategy::AllZeros},
        {"AllFF",              ParamStrategy::AllFF},
        {"NanFloats",          ParamStrategy::NanFloats},
        {"InfFloats",          ParamStrategy::InfFloats},
        {"Denormals",          ParamStrategy::Denormals},
        {"BoundaryValues",     ParamStrategy::BoundaryValues},
        {"WrongSize",          ParamStrategy::WrongSize},
        {"All",                ParamStrategy::All},
    };
    auto it = kMap.find(s);
    if (it != kMap.end()) return it->second;
    throw std::runtime_error("Unknown strategy: " + s);
}

inline std::vector<ParamStrategy> ParseStrategyList(const std::string& val) {
    std::vector<ParamStrategy> result;
    // Strip [ ] wrapper if present
    std::string raw = val;
    if (!raw.empty() && raw.front() == '[') raw = raw.substr(1);
    if (!raw.empty() && raw.back() == ']') raw.pop_back();

    std::string token;
    std::istringstream ss(raw);
    while (std::getline(ss, token, ',')) {
        auto t = Trim(token);
        if (t.empty()) continue;
        result.push_back(ParseSingleStrategy(t));
    }
    return result;
}

} // namespace detail

// -----------------------------------------------------------------------
// ProbeLoader — load single .yml or all .yml from a directory
// -----------------------------------------------------------------------
class ProbeLoader {
public:
    static ProbeConfig Load(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open())
            throw std::runtime_error("Cannot open probe file: " + path);

        ProbeConfig cfg{};
        std::string line;
        ParamSpec cur_param{};
        bool in_params = false;
        bool in_expect = false;
        bool param_open = false;

        auto flush_param = [&] {
            if (param_open && !cur_param.name.empty()) {
                cfg.params.push_back(cur_param);
                cur_param = {};
            }
            param_open = false;
        };

        while (std::getline(f, line)) {
            line = detail::Trim(detail::StripComment(line));
            if (line.empty()) continue;

            // Section markers
            if (line == "params:") {
                flush_param();
                in_params = true; in_expect = false;
                continue;
            }
            if (line == "expect:") {
                flush_param();
                in_params = false; in_expect = true;
                continue;
            }

            // List item without key: (expect entries or new param dash)
            if (line[0] == '-' && line.find(':') == std::string::npos) {
                std::string val = detail::Trim(line.substr(1));
                if (in_expect)
                    cfg.expect.push_back(val);
                else if (in_params) {
                    flush_param();
                    param_open = true;
                }
                continue;
            }

            // key: value pair
            auto colon = line.find(':');
            if (colon == std::string::npos)
                continue; // unsupported construct — skip

            std::string key = detail::Trim(line.substr(0, colon));
            std::string val = detail::Trim(line.substr(colon + 1));

            if (val.empty()) {
                // Key with no value on this line (e.g. "description: >")
                // The next lines will be folded into it — for simplicity we just skip
                continue;
            }

            if (!in_params && !in_expect) {
                if      (key == "name")        cfg.name = val;
                else if (key == "api")         cfg.api = detail::ParseApiType(val);
                else if (key == "interface")   cfg.interface_name = val;
                else if (key == "method")      cfg.method = val;
                else if (key == "platform")    cfg.platform = val;
                else if (key == "description") cfg.description = val;
            } else if (in_params) {
                if      (key == "name")     { cur_param.name = val; param_open = true; }
                else if (key == "type")     cur_param.type = val;
                else if (key == "value")    cur_param.fixed_value = val;
                else if (key == "strategy") cur_param.strategies = detail::ParseStrategyList(val);
            }
        }
        flush_param();
        return cfg;
    }

    static std::vector<ProbeConfig> LoadDir(const std::string& dir_path) {
        std::vector<ProbeConfig> result;
        std::string pattern = dir_path + "\\*.yml";
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return result;
        do {
            try {
                result.push_back(Load(dir_path + "\\" + fd.cFileName));
            } catch (...) {}
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        return result;
    }
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_PROBE_LOADER_HPP
