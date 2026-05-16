#pragma once

#include "etw/etw_consumer.hpp"
#include "filter/interest_filter.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>

#include <deque>
#include <mutex>
#include <atomic>
#include <string>
#include <format>

namespace w32kspy {

using namespace ftxui;

// Максимум событий в буфере
static constexpr size_t kMaxEvents = 2000;

// -----------------------------------------------------------------------
// Цвета по severity
// -----------------------------------------------------------------------
inline Color SeverityColor(Severity s) {
    switch (s) {
        case Severity::Critical:   return Color::Red;
        case Severity::Suspicious: return Color::Yellow;
        default:                   return Color::GrayLight;
    }
}

inline std::wstring SeverityIcon(Severity s) {
    switch (s) {
        case Severity::Critical:   return L"🔴";
        case Severity::Suspicious: return L"⚠️ ";
        default:                   return L"   ";
    }
}

// wstring → string для FTXUI (UTF-8)
inline std::string W(const std::wstring& ws) {
    if (ws.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                                  static_cast<int>(ws.size()),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                         static_cast<int>(ws.size()),
                         s.data(), sz, nullptr, nullptr);
    return s;
}

// -----------------------------------------------------------------------
// Shared state между ETW потоком и UI потоком
// -----------------------------------------------------------------------
struct SharedState {
    std::deque<CapturedEvent> events;
    std::mutex                mtx;
    std::atomic<uint64_t>     total_events{ 0 };
    std::atomic<uint64_t>     filtered_events{ 0 };
    std::atomic<bool>         paused{ false };
    std::atomic<bool>         running{ true };

    void Push(CapturedEvent ev) {
        ++total_events;
        if (paused.load()) return;
        ++filtered_events;
        std::lock_guard lock(mtx);
        if (events.size() >= kMaxEvents)
            events.pop_front();
        events.push_back(std::move(ev));
    }

    std::deque<CapturedEvent> Snapshot() {
        std::lock_guard lock(mtx);
        return events;
    }

    void Clear() {
        std::lock_guard lock(mtx);
        events.clear();
        filtered_events = 0;
    }
};

// -----------------------------------------------------------------------
// Главный TUI класс
// -----------------------------------------------------------------------
class Dashboard {
public:
    explicit Dashboard(SharedState& state, InterestFilter& filter)
        : state_(state), filter_(filter) {}

    void Run() {
        auto screen = ScreenInteractive::Fullscreen();

        // ---- строка поиска ----
        std::string search_str;
        auto search_input = Input(&search_str, "Search event/process...");

        // ---- выбор severity ----
        int severity_idx = 0;
        std::vector<std::string> severity_opts = { "All", "Suspicious+", "Critical only" };
        auto severity_toggle = Toggle(&severity_opts, &severity_idx);

        // ---- чекбокс "hide noise" ----
        bool hide_noise = true;
        auto noise_cb = Checkbox("Hide noise", &hide_noise);

        // ---- чекбокс "system only" ----
        bool system_only = false;
        auto sysonly_cb = Checkbox("SYSTEM only", &system_only);

        // ---- scroll ----
        int scroll_pos = 0;

        auto controls = Container::Horizontal({
            search_input,
            severity_toggle,
            noise_cb,
            sysonly_cb,
        });

        auto renderer = Renderer(controls, [&] {
            // Обновляем фильтр
            FilterConfig cfg;
            cfg.hide_noise   = hide_noise;
            cfg.system_only  = system_only;
            cfg.min_severity = static_cast<Severity>(severity_idx);
            if (!search_str.empty()) {
                int sz = MultiByteToWideChar(CP_UTF8, 0,
                    search_str.c_str(), -1, nullptr, 0);
                std::wstring ws(sz, L'\0');
                MultiByteToWideChar(CP_UTF8, 0,
                    search_str.c_str(), -1, ws.data(), sz);
                cfg.event_name_contains.push_back(ws);
            }
            filter_.SetConfig(cfg);

            auto snapshot = state_.Snapshot();

            // --- Таблица событий ---
            Elements rows;

            // Header
            rows.push_back(
                hbox({
                    text("  ") | size(WIDTH, EQUAL, 3),
                    text("TIME    ") | size(WIDTH, EQUAL, 14) | bold,
                    text("PID  ")   | size(WIDTH, EQUAL, 7)  | bold,
                    text("PROCESS          ") | size(WIDTH, EQUAL, 22) | bold,
                    text("EVENT                    ") | size(WIDTH, EQUAL, 30) | bold,
                    text("DETAILS") | flex | bold,
                }) | color(Color::Cyan)
            );
            rows.push_back(separator());

            // Рассчитываем видимые строки
            int visible = 30;
            int total   = static_cast<int>(snapshot.size());
            int start   = std::max(0, total - visible - scroll_pos);
            int end     = std::max(0, total - scroll_pos);

            for (int i = start; i < end; ++i) {
                auto& ev = snapshot[i];
                Color c  = SeverityColor(ev.severity);
                std::string icon = W(SeverityIcon(ev.severity));

                rows.push_back(
                    hbox({
                        text(icon)                          | size(WIDTH, EQUAL, 3),
                        text(W(ev.timestamp))               | size(WIDTH, EQUAL, 14),
                        text(std::to_string(ev.pid))        | size(WIDTH, EQUAL, 7),
                        text(W(ev.process_name))            | size(WIDTH, EQUAL, 22),
                        text(W(ev.event_name))              | size(WIDTH, EQUAL, 30),
                        text(W(ev.details))                 | flex,
                    }) | color(c)
                );
            }

            // --- Статусбар ---
            std::string status = std::format(
                "  Total: {}  │  Shown: {}  │  {}",
                state_.total_events.load(),
                state_.filtered_events.load(),
                state_.paused ? "⏸ PAUSED" : "▶ LIVE"
            );

            return vbox({
                // Заголовок
                hbox({
                    text(" W32KSpy ") | bold | bgcolor(Color::Blue) | color(Color::White),
                    text(" │ win32k ETW Monitor │ Win11 ") | color(Color::GrayLight),
                    text(" SYSTEM ") | bgcolor(Color::Red) | color(Color::White) | bold,
                }) | size(HEIGHT, EQUAL, 1),

                separator(),

                // Контролы
                hbox({
                    text(" Search: "),
                    search_input->Render() | size(WIDTH, EQUAL, 25),
                    text("  Severity: "),
                    severity_toggle->Render(),
                    text("  "),
                    noise_cb->Render(),
                    text("  "),
                    sysonly_cb->Render(),
                }) | size(HEIGHT, EQUAL, 1),

                separator(),

                // Таблица
                vbox(std::move(rows)) | flex | frame,

                separator(),

                // Статусбар
                hbox({
                    text(status) | color(Color::GrayLight),
                    filler(),
                    text(" [F1]Clear  [Space]Pause  [Q]Quit ") | color(Color::GrayDark),
                }) | size(HEIGHT, EQUAL, 1),
            });
        });

        // Keyboard handler
        auto event_handler = CatchEvent(renderer, [&](Event event) {
            if (event == Event::Character('q') || event == Event::Character('Q')) {
                state_.running = false;
                screen.ExitLoopClosure()();
                return true;
            }
            if (event == Event::Character(' ')) {
                state_.paused = !state_.paused;
                return true;
            }
            if (event == Event::F1) {
                state_.Clear();
                return true;
            }
            // Scroll
            if (event == Event::ArrowUp) {
                scroll_pos = std::min(scroll_pos + 3,
                    static_cast<int>(state_.Snapshot().size()));
                return true;
            }
            if (event == Event::ArrowDown) {
                scroll_pos = std::max(0, scroll_pos - 3);
                return true;
            }
            return false;
        });

        // Таймер обновления — 100ms
        std::thread refresh([&] {
            while (state_.running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                screen.PostEvent(Event::Custom);
            }
        });

        screen.Loop(event_handler);
        refresh.join();
    }

private:
    SharedState&    state_;
    InterestFilter& filter_;
};

} // namespace w32kspy
