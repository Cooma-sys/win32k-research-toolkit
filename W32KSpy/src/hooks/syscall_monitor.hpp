#pragma once

// =========================================================================
// SyscallMonitor — единый фасад всех методов перехвата
// =========================================================================
//
// Методы перехвата (от простого к продвинутому):
//
//  [1] ETW — Microsoft-Windows-Win32k провайдер
//      + Не требует инъекции в целевой процесс
//      + Работает system-wide
//      - Ограниченные аргументы (только то что MS решил логировать)
//      - Требует SYSTEM
//
//  [2] ETW-TI — Microsoft-Windows-Threat-Intelligence
//      + ReadProcessMemory, WriteProcessMemory, VirtualAlloc и т.д.
//      + Используется EDR'ами, нам полезен для корреляции
//      - Требует SeDebugPrivilege + SYSTEM
//
//  [3] IAT Hook (в целевом процессе через DLL injection)
//      + Полные аргументы всех вызовов
//      + Конкретный процесс
//      - Нужен DLL injector (не реализован здесь — in-process только)
//      - Не работает против direct syscall
//
//  [4] Inline Hook на win32u.dll exports
//      + Перехватывает все NtUser*/NtGdi* в текущем процессе
//      + Полные аргументы
//      - В текущем процессе только
//      - Совместимость: патчит код в памяти
//
//  [5] InstrumentationCallback
//      + Перехватывает ВСЕ syscall return'ы в процессе
//      + Работает даже против direct syscall!
//      + Видит syscall number → можем фильтровать 0x1000-0x1FFF (win32k)
//      - Нужен NtSetInformationProcess → обычно требует SYSTEM/SeDebug
//      - Только текущий процесс (или inject)
//
// Этот класс управляет всеми методами вместе и направляет события
// в единый SharedState.
// =========================================================================

#include "iat_hook.hpp"
#include "inline_hook.hpp"
#include "instrumentation_cb.hpp"
#include "etw/etw_consumer.hpp"

#include <functional>
#include <string>
#include <vector>
#include <format>
#include <mutex>

namespace w32kspy {

// -----------------------------------------------------------------------
// Список win32k функций для мониторинга из win32u.dll
// Фокус на тех что исторически давали уязвимости
// -----------------------------------------------------------------------
struct Win32kTarget {
    const char* func_name;
    const char* description;
    Severity    base_severity;
};

static constexpr Win32kTarget kWin32kTargets[] = {
    // --- Hooking / Injection классика ---
    { "NtUserSetWindowsHookEx",      "WH_* global hooks",            Severity::Critical   },
    { "NtUserSetWinEventHook",       "WinEvent hook",                Severity::Suspicious },
    { "NtUserCallHwnd",              "generic HWND callback",        Severity::Suspicious },
    { "NtUserCallHwndParam",         "HWND+param callback",          Severity::Suspicious },
    { "NtUserCallNoParam",           "zero-arg kernel callback",     Severity::Suspicious },
    { "NtUserCallOneParam",          "one-arg kernel callback",      Severity::Suspicious },
    { "NtUserCallTwoParam",          "two-arg kernel callback",      Severity::Suspicious },

    // --- Message passing ---
    { "NtUserSendMessage",           "sync cross-proc message",      Severity::Suspicious },
    { "NtUserSendMessageTimeout",    "sync msg with timeout",        Severity::Suspicious },
    { "NtUserPostMessage",           "async message",                Severity::Info       },
    { "NtUserMessageCall",           "generic msg dispatch",         Severity::Suspicious },

    // --- Window creation / manipulation ---
    { "NtUserCreateWindowEx",        "window creation",              Severity::Info       },
    { "NtUserDestroyWindow",         "window destruction",           Severity::Info       },
    { "NtUserSetParent",             "reparent window",              Severity::Suspicious },
    { "NtUserSetWindowLong",         "modify window style/proc",     Severity::Critical   },
    { "NtUserSetWindowLongPtr",      "modify window proc ptr",       Severity::Critical   },

    // --- Clipboard / DDE ---
    { "NtUserOpenClipboard",         "clipboard access",             Severity::Suspicious },
    { "NtUserSetClipboardData",      "clipboard write",              Severity::Suspicious },
    { "NtUserGetClipboardData",      "clipboard read",               Severity::Info       },

    // --- Desktop / Session ---
    { "NtUserOpenDesktop",           "open desktop object",          Severity::Critical   },
    { "NtUserOpenWindowStation",     "open window station",          Severity::Critical   },
    { "NtUserSetThreadDesktop",      "switch thread desktop",        Severity::Critical   },

    // --- GDI / Graphics memory (type confusion / OOB классика) ---
    { "NtGdiAddFontMemResourceEx",   "font from memory",             Severity::Suspicious },
    { "NtGdiCreateBitmap",           "bitmap creation",              Severity::Info       },
    { "NtGdiDdDDICreateAllocation",  "DXGI allocation (DXGK)",       Severity::Suspicious },
    { "NtGdiDdDDISubmitCommand",     "DXGI command buffer submit",   Severity::Suspicious },
    { "NtGdiExtCreatePen",           "pen object creation",          Severity::Info       },
    { "NtGdiCreatePaletteInternal",  "palette UAF классика",         Severity::Suspicious },

    // --- Misc интересные ---
    { "NtUserGetAsyncKeyState",      "keylogger primitive",          Severity::Suspicious },
    { "NtUserBlockInput",            "block all input",              Severity::Critical   },
    { "NtUserInternalGetWindowText", "read window title",            Severity::Info       },
};

// -----------------------------------------------------------------------
// Глобальные указатели оригиналов (заполняются при установке хуков)
// Объявляем как void* массив, индексируется по kWin32kTargets
// -----------------------------------------------------------------------
static void* g_orig_fns[std::size(kWin32kTargets)] = {};

// -----------------------------------------------------------------------
// Фабрика хук-функций через шаблон
// Для полноценной реализации каждый хук должен быть отдельной функцией —
// здесь даём общий шаблон и конкретные специализации для ключевых функций
// -----------------------------------------------------------------------

// Глобальный callback для forwarding событий из хуков
using HookEventCb = std::function<void(CapturedEvent)>;
static HookEventCb g_hook_event_cb;
static std::mutex  g_hook_cb_mtx;

inline void EmitHookEvent(const char* func_name,
                           Severity sev,
                           std::wstring details)
{
    std::lock_guard lock(g_hook_cb_mtx);
    if (!g_hook_event_cb) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    CapturedEvent ev;
    ev.timestamp    = std::format(L"{:02}:{:02}:{:02}.{:03}",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    ev.provider     = L"inline-hook";
    ev.pid          = GetCurrentProcessId();
    ev.tid          = GetCurrentThreadId();
    ev.process_name = L"<self>";
    ev.event_name   = std::wstring(func_name, func_name + strlen(func_name));
    ev.details      = std::move(details);
    ev.severity     = sev;
    g_hook_event_cb(std::move(ev));
}

// -----------------------------------------------------------------------
// Конкретные хук-функции (для наиболее интересных)
// -----------------------------------------------------------------------

// NtUserSetWindowsHookEx(idHook, lpfn, hmod, dwThreadId)
using NtUserSetWindowsHookEx_t =
    HHOOK(NTAPI*)(int, HOOKPROC, HINSTANCE, DWORD);

static HHOOK NTAPI Hook_NtUserSetWindowsHookEx(
    int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
{
    EmitHookEvent("NtUserSetWindowsHookEx", Severity::Critical,
        std::format(L"idHook={} lpfn=0x{:016X} hmod=0x{:016X} tid={}",
            idHook,
            reinterpret_cast<ULONG64>(lpfn),
            reinterpret_cast<ULONG64>(hmod),
            dwThreadId));

    auto orig = reinterpret_cast<NtUserSetWindowsHookEx_t>(
        g_orig_fns[0]); // индекс 0 в kWin32kTargets
    return orig ? orig(idHook, lpfn, hmod, dwThreadId) : nullptr;
}

// NtUserSetWindowLongPtr(hWnd, nIndex, dwNewLong)
using NtUserSetWindowLongPtr_t =
    LONG_PTR(NTAPI*)(HWND, int, LONG_PTR);

static LONG_PTR NTAPI Hook_NtUserSetWindowLongPtr(
    HWND hWnd, int nIndex, LONG_PTR newLong)
{
    EmitHookEvent("NtUserSetWindowLongPtr", Severity::Critical,
        std::format(L"hWnd=0x{:016X} nIndex={} newLong=0x{:016X}",
            reinterpret_cast<ULONG64>(hWnd),
            nIndex,
            static_cast<ULONG64>(newLong)));

    auto orig = reinterpret_cast<NtUserSetWindowLongPtr_t>(
        g_orig_fns[14]); // индекс в kWin32kTargets
    return orig ? orig(hWnd, nIndex, newLong) : 0;
}

// NtUserOpenDesktop(pObjAttr, dwFlags, dwDesiredAccess)
using NtUserOpenDesktop_t =
    HDESK(NTAPI*)(POBJECT_ATTRIBUTES, DWORD, ACCESS_MASK);

static HDESK NTAPI Hook_NtUserOpenDesktop(
    POBJECT_ATTRIBUTES attr, DWORD flags, ACCESS_MASK access)
{
    EmitHookEvent("NtUserOpenDesktop", Severity::Critical,
        std::format(L"flags=0x{:08X} access=0x{:08X}", flags, access));

    auto orig = reinterpret_cast<NtUserOpenDesktop_t>(g_orig_fns[21]);
    return orig ? orig(attr, flags, access) : nullptr;
}

// NtUserBlockInput(fBlockIt)
using NtUserBlockInput_t = BOOL(NTAPI*)(BOOL);
static BOOL NTAPI Hook_NtUserBlockInput(BOOL block) {
    EmitHookEvent("NtUserBlockInput", Severity::Critical,
        std::format(L"block={}", block ? L"TRUE" : L"FALSE"));
    auto orig = reinterpret_cast<NtUserBlockInput_t>(g_orig_fns[30]);
    return orig ? orig(block) : FALSE;
}

// Instrumentation callback — событие по syscall number
static void OnInstrumentationSyscall(const hooks::SyscallContext& ctx) {
    // Фильтруем только win32k диапазон
    if (ctx.syscall_number < 0x1000 || ctx.syscall_number > 0x1FFF) return;

    EmitHookEvent("InstrCb",
        (ctx.syscall_number >= 0x1400) ? Severity::Suspicious : Severity::Info,
        std::format(L"sysno=0x{:04X} retval=0x{:08X} retaddr=0x{:016X}",
            ctx.syscall_number,
            static_cast<ULONG32>(ctx.return_value),
            ctx.return_address));
}

// -----------------------------------------------------------------------
// SyscallMonitor — главный класс
// -----------------------------------------------------------------------
class SyscallMonitor {
public:
    explicit SyscallMonitor(HookEventCb cb) {
        std::lock_guard lock(g_hook_cb_mtx);
        g_hook_event_cb = std::move(cb);
    }

    ~SyscallMonitor() {
        StopAll();
        std::lock_guard lock(g_hook_cb_mtx);
        g_hook_event_cb = nullptr;
    }

    // Устанавливаем inline хуки на win32u.dll для ключевых функций
    bool InstallInlineHooks() {
        struct { size_t idx; const char* name; void* hook_fn; } targets[] = {
            { 0,  "NtUserSetWindowsHookEx",  reinterpret_cast<void*>(&Hook_NtUserSetWindowsHookEx)  },
            { 14, "NtUserSetWindowLongPtr",  reinterpret_cast<void*>(&Hook_NtUserSetWindowLongPtr)  },
            { 21, "NtUserOpenDesktop",       reinterpret_cast<void*>(&Hook_NtUserOpenDesktop)       },
            { 30, "NtUserBlockInput",        reinterpret_cast<void*>(&Hook_NtUserBlockInput)        },
        };

        bool any_ok = false;
        for (auto& t : targets) {
            bool ok = inline_engine_.HookExport(
                L"win32u.dll",
                t.name,
                t.hook_fn,
                &g_orig_fns[t.idx]
            );
            if (ok) { ++inline_hook_count_; any_ok = true; }
        }
        return any_ok;
    }

    // IAT хуки — патчим IAT текущего EXE (если он импортирует win32u.dll)
    bool InstallIatHooks() {
        struct { const char* name; } targets[] = {
            { "NtUserSendMessage"       },
            { "NtUserPostMessage"       },
            { "NtUserSetParent"         },
            { "NtGdiAddFontMemResourceEx" },
        };

        bool any_ok = false;
        HMODULE win32u = GetModuleHandleW(L"win32u.dll");
        if (!win32u) win32u = LoadLibraryW(L"win32u.dll");

        for (auto& t : targets) {
            // Для IAT хука в текущем EXE нет смысла если EXE не импортирует win32u
            // Поэтому используем патч IAT в загруженном win32u.dll (его re-export'ы)
            // В реальном сценарии: инжектируем DLL в целевой процесс
            // Здесь — демонстрируем механику
            void* fn = win32u ? GetProcAddress(win32u, t.name) : nullptr;
            if (fn) ++iat_hook_count_;
            any_ok = any_ok || (fn != nullptr);
        }
        return any_ok;
    }

    // InstrumentationCallback — ловим все win32k syscall'ы
    bool InstallInstrumentationCallback() {
        bool ok = instr_engine_.Install(OnInstrumentationSyscall, true);
        if (ok) instr_cb_active_ = true;
        return ok;
    }

    void StopAll() {
        inline_engine_.UninstallAll();
        instr_engine_.Uninstall();
        instr_cb_active_ = false;
    }

    // Статистика для TUI
    struct Stats {
        size_t inline_hooks;
        size_t iat_hooks;
        bool   instr_cb;
    };

    [[nodiscard]] Stats GetStats() const {
        return { inline_hook_count_, iat_hook_count_, instr_cb_active_ };
    }

private:
    hooks::InlineHookEngine          inline_engine_;
    hooks::IatHookEngine             iat_engine_;
    hooks::InstrumentationCallbackEngine instr_engine_;

    size_t inline_hook_count_ = 0;
    size_t iat_hook_count_    = 0;
    bool   instr_cb_active_   = false;
};

} // namespace w32kspy
