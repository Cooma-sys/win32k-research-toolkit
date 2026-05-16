#pragma once

// =========================================================================
// ProbeLoader — загружает YAML конфиг и строит ProbeConfig
// Используем минимальный hand-rolled YAML парсер (без зависимостей)
// Формат намеренно простой — только то что нужно
// =========================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstdint>

namespace w32kfuzz {

// -----------------------------------------------------------------------
// Стратегии мутации для параметра
// -----------------------------------------------------------------------
enum class FuzzStrategy : uint32_t {
    None            = 0,
    IntegerOverflow = 1 << 0,   // MAX_INT, MAX_INT±1, MAX_UINT
    Underflow       = 1 << 1,   // 0, 1, -1, 2
    SignedUnsigned  = 1 << 2,   // (int)-1 = (uint)0xFFFFFFFF
    TruncationBait  = 1 << 3,   // значения где lower32 != full64
    KernelAddress   = 1 << 4,   // 0xFFFF800000000000 и окрестности
    NullPage        = 1 << 5,   // 0x1 - 0x1000
    GuardPage       = 1 << 6,   // MmUserProbeAddress ±1
    SizePlusOne     = 1 << 7,   // known_size + 1
    SizeTimesTwo    = 1 << 8,   // known_size * 2 (DPI-style)
    InvalidHandle   = 1 << 9,   // несуществующий HWND/HDC
    CrossSession    = 1 << 10,  // handle из другой сессии
    All             = 0xFFFFFFFF
};

inline FuzzStrategy operator|(FuzzStrategy a, FuzzStrategy b) {
    return static_cast<FuzzStrategy>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool HasStrategy(FuzzStrategy mask, FuzzStrategy bit) {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(bit)) != 0;
}

// -----------------------------------------------------------------------
// Описание одного параметра syscall'а
// -----------------------------------------------------------------------
struct ParamConfig {
    std::string   name;
    std::string   type;          // "INT", "UINT", "LPWSTR", "HWND", ...
    std::string   value;         // фиксированное значение или "valid_*" хелпер
    FuzzStrategy  strategy{ FuzzStrategy::None }; // что фаззим
    uint64_t      fixed_value{ 0 };
    bool          is_fuzz_target{ false };
};

// -----------------------------------------------------------------------
// Ожидаемые результаты
// -----------------------------------------------------------------------
enum class ExpectType {
    KernelWrite,        // запись в kernel адрес
    PoolCorruption,     // pool corruption event через ETW
    Crash,              // crash целевого потока
    UnexpectedStatus,   // нестандартный NTSTATUS
    OobRead,            // OOB чтение
    Any,                // любое аномальное поведение
};

// -----------------------------------------------------------------------
// Полный конфиг одного probe'а
// -----------------------------------------------------------------------
struct ProbeConfig {
    std::string              name;
    uint32_t                 syscall_id{ 0 };
    std::string              platform;
    std::string              description;
    std::string              cve_ref;        // опционально
    std::vector<ParamConfig> params;
    std::vector<ExpectType>  expect;
    bool                     monitor_etw{ true };
    std::vector<std::string> watch_hooks;
    std::vector<uint64_t>    watch_addresses;
};

// -----------------------------------------------------------------------
// Минимальный YAML парсер
// Поддерживает только flat структуру которая нам нужна
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

inline uint64_t ParseHexOrDec(const std::string& s) {
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return std::stoull(s, nullptr, 16);
    return std::stoull(s, nullptr, 10);
}

inline FuzzStrategy ParseStrategies(const std::string& val) {
    static const std::unordered_map<std::string, FuzzStrategy> kMap = {
        {"IntegerOverflow", FuzzStrategy::IntegerOverflow},
        {"Underflow",       FuzzStrategy::Underflow},
        {"SignedUnsigned",  FuzzStrategy::SignedUnsigned},
        {"TruncationBait",  FuzzStrategy::TruncationBait},
        {"KernelAddress",   FuzzStrategy::KernelAddress},
        {"NullPage",        FuzzStrategy::NullPage},
        {"GuardPage",       FuzzStrategy::GuardPage},
        {"SizePlusOne",     FuzzStrategy::SizePlusOne},
        {"SizeTimesTwo",    FuzzStrategy::SizeTimesTwo},
        {"InvalidHandle",   FuzzStrategy::InvalidHandle},
        {"CrossSession",    FuzzStrategy::CrossSession},
        {"All",             FuzzStrategy::All},
    };

    FuzzStrategy result = FuzzStrategy::None;
    std::string token;
    std::istringstream ss(val);
    while (std::getline(ss, token, ',')) {
        auto t = Trim(token);
        // убираем [ и ]
        t.erase(std::remove(t.begin(), t.end(), '['), t.end());
        t.erase(std::remove(t.begin(), t.end(), ']'), t.end());
        auto it = kMap.find(t);
        if (it != kMap.end())
            result = result | it->second;
    }
    return result;
}

inline ExpectType ParseExpect(const std::string& s) {
    if (s == "kernel_write")       return ExpectType::KernelWrite;
    if (s == "pool_corruption")    return ExpectType::PoolCorruption;
    if (s == "crash")              return ExpectType::Crash;
    if (s == "unexpected_status")  return ExpectType::UnexpectedStatus;
    if (s == "oob_read")           return ExpectType::OobRead;
    return ExpectType::Any;
}

} // namespace detail

// -----------------------------------------------------------------------
// Основной загрузчик
// -----------------------------------------------------------------------
class ProbeLoader {
public:
    // Загружает один YAML файл
    static ProbeConfig Load(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open())
            throw std::runtime_error("Cannot open probe file: " + path);

        ProbeConfig cfg;
        std::string line;
        ParamConfig cur_param;
        bool in_params = false;
        bool in_expect = false;
        bool in_hooks  = false;
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

            // Определяем секцию
            if (line == "params:") {
                flush_param();
                in_params = true; in_expect = false; in_hooks = false;
                continue;
            }
            if (line == "expect:") {
                flush_param();
                in_params = false; in_expect = true; in_hooks = false;
                continue;
            }
            if (line.rfind("watch_hooks:", 0) == 0) {
                flush_param();
                in_params = false; in_expect = false; in_hooks = true;
                continue;
            }
            if (line.rfind("monitor:", 0) == 0 ||
                line.rfind("watch_addresses:", 0) == 0) {
                flush_param();
                in_params = false; in_expect = false; in_hooks = false;
            }

            // Парсим key: value
            auto colon = line.find(':');
            if (colon == std::string::npos) {
                // list item: "  - something"
                if (line[0] == '-') {
                    std::string val = detail::Trim(line.substr(1));
                    if (in_expect)
                        cfg.expect.push_back(detail::ParseExpect(val));
                    else if (in_hooks)
                        cfg.watch_hooks.push_back(val);
                    else if (in_params) {
                        flush_param();
                        param_open = true;
                    }
                }
                continue;
            }

            std::string key = detail::Trim(line.substr(0, colon));
            std::string val = detail::Trim(line.substr(colon + 1));

            if (!in_params) {
                if      (key == "name")        cfg.name = val;
                else if (key == "syscall")     cfg.syscall_id = (uint32_t)detail::ParseHexOrDec(val);
                else if (key == "platform")    cfg.platform = val;
                else if (key == "description") cfg.description = val;
                else if (key == "cve_ref")     cfg.cve_ref = val;
                else if (key == "monitor")     cfg.monitor_etw = (val == "true");
            } else {
                // Внутри params секции
                if      (key == "name")     { cur_param.name = val; param_open = true; }
                else if (key == "type")     cur_param.type = val;
                else if (key == "value")    {
                    cur_param.value = val;
                    if (!val.empty() && val[0] != 'v') { // не "valid_*"
                        try { cur_param.fixed_value = detail::ParseHexOrDec(val); }
                        catch (...) {}
                    }
                }
                else if (key == "strategy") {
                    cur_param.strategy = detail::ParseStrategies(val);
                    cur_param.is_fuzz_target = (cur_param.strategy != FuzzStrategy::None);
                }
            }
        }
        flush_param();
        return cfg;
    }

    // Загружает все .yml файлы из директории
    static std::vector<ProbeConfig> LoadDir(const std::string& dir_path) {
        std::vector<ProbeConfig> result;
        // Используем WinAPI для листинга директории
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

} // namespace w32kfuzz
