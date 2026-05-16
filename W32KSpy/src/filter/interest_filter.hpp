#pragma once

#include "etw/etw_consumer.hpp"
#include <unordered_set>
#include <string>
#include <algorithm>
#include <cwctype>

namespace w32kspy {

// -----------------------------------------------------------------------
// Настройки фильтра — меняются из TUI
// -----------------------------------------------------------------------
struct FilterConfig {
    // Если не пусто — показываем только эти PID'ы
    std::unordered_set<ULONG> pid_whitelist;

    // Если не пусто — показываем только события содержащие эти подстроки
    std::vector<std::wstring> event_name_contains;

    // Минимальный уровень severity
    Severity min_severity = Severity::Info;

    // Показывать только процессы с SYSTEM токеном
    bool system_only = false;

    // Скрыть шумные системные процессы (dwm, csrss и т.д.)
    bool hide_noise = true;
};

// -----------------------------------------------------------------------
// Известные "шумные" процессы win32k — куча GUI событий но мало интереса
// -----------------------------------------------------------------------
static const std::unordered_set<std::wstring> kNoisyProcesses = {
    L"dwm.exe",
    L"explorer.exe",
    L"SearchHost.exe",
    L"ShellExperienceHost.exe",
    L"StartMenuExperienceHost.exe",
    L"TextInputHost.exe",
    L"fontdrvhost.exe",
    L"conhost.exe",
    L"RuntimeBroker.exe",
};

// -----------------------------------------------------------------------
// Процессы которые ВСЕГДА интересны если делают win32k вызовы
// -----------------------------------------------------------------------
static const std::unordered_set<std::wstring> kAlwaysInteresting = {
    L"lsass.exe",
    L"services.exe",
    L"svchost.exe",   // смотрим внимательно
    L"spoolsv.exe",
    L"winlogon.exe",
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"System",        // PID 4
};

// -----------------------------------------------------------------------
// Интересные паттерны в имени события
// -----------------------------------------------------------------------
static const std::vector<std::wstring> kInterestingEventPatterns = {
    L"Hook",        // SetWindowsHook*
    L"Inject",
    L"SendMessage",
    L"PostMessage",
    L"CallWndProc",
    L"CreateProcess",
    L"DuplicateHandle",
    L"AllocConsole",
    L"SetClipboard",
    L"GlobalHook",
    L"SetWinEvent",  // WinEvent hooks
    L"NtUserCall",   // generic kernel callback
};

// -----------------------------------------------------------------------
// Основной фильтр
// -----------------------------------------------------------------------
class InterestFilter {
public:
    explicit InterestFilter(FilterConfig cfg = {}) : cfg_(std::move(cfg)) {}

    void SetConfig(FilterConfig cfg) { cfg_ = std::move(cfg); }
    [[nodiscard]] const FilterConfig& config() const { return cfg_; }

    // Возвращает true если событие нужно показать
    [[nodiscard]] bool Pass(CapturedEvent& ev) const {

        // 1. PID whitelist
        if (!cfg_.pid_whitelist.empty() &&
            !cfg_.pid_whitelist.contains(ev.pid))
            return false;

        // 2. System only
        if (cfg_.system_only && !ev.is_system_token)
            return false;

        // 3. Фильтр по severity
        if (static_cast<int>(ev.severity) < static_cast<int>(cfg_.min_severity))
            return false;

        // 4. Подстрока в имени события
        if (!cfg_.event_name_contains.empty()) {
            bool found = false;
            for (auto& s : cfg_.event_name_contains) {
                if (ContainsCI(ev.event_name, s)) { found = true; break; }
            }
            if (!found) return false;
        }

        // 5. Убираем шум
        if (cfg_.hide_noise && kNoisyProcesses.contains(ev.process_name))
            return false;

        // 6. Повышаем severity для "всегда интересных" процессов
        if (kAlwaysInteresting.contains(ev.process_name)) {
            if (ev.severity == Severity::Info)
                ev.severity = Severity::Suspicious;
        }

        // 7. Повышаем severity если имя события совпадает с интересным паттерном
        for (auto& pat : kInterestingEventPatterns) {
            if (ContainsCI(ev.event_name, pat)) {
                if (ev.severity == Severity::Info)
                    ev.severity = Severity::Suspicious;
                break;
            }
        }

        return true;
    }

private:
    static bool ContainsCI(const std::wstring& str, const std::wstring& sub) {
        auto it = std::search(str.begin(), str.end(),
                              sub.begin(), sub.end(),
                              [](wchar_t a, wchar_t b) {
                                  return std::towlower(a) == std::towlower(b);
                              });
        return it != str.end();
    }

    FilterConfig cfg_;
};

} // namespace w32kspy
