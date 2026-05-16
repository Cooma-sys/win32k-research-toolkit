#include <windows.h>
#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "etw/etw_session.hpp"
#include "etw/etw_consumer.hpp"
#include "filter/interest_filter.hpp"
#include "hooks/syscall_monitor.hpp"
#include "ui/tui.hpp"

// -----------------------------------------------------------------------
// Привилегии
// -----------------------------------------------------------------------
static bool IsRunningAsSystem() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    bool is_system = false;

    if (GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        auto* user_info = reinterpret_cast<TOKEN_USER*>(buf.data());
        PSID system_sid = nullptr;
        SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&nt_auth, 1,
            SECURITY_LOCAL_SYSTEM_RID, 0,0,0,0,0,0,0, &system_sid)) {
            is_system = !!EqualSid(user_info->User.Sid, system_sid);
            FreeSid(system_sid);
        }
    }
    CloseHandle(token);
    return is_system;
}

static bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elev{};
    DWORD len = sizeof(elev);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elev, len, &len))
        elevated = elev.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

// Пытаемся включить SeSystemProfilePrivilege для EtwTi
static bool EnableProfilePrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_PROFILE_NAME,
        &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = !!AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(token);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"  ██╗    ██╗██████╗ ██████╗ ██╗  ██╗███████╗██████╗ ██╗   ██╗\n";
    std::wcout << L"  ██║    ██║╚════██╗╚════██╗██║ ██╔╝██╔════╝██╔══██╗╚██╗ ██╔╝\n";
    std::wcout << L"  ██║ █╗ ██║ █████╔╝ █████╔╝█████╔╝ ███████╗██████╔╝ ╚████╔╝ \n";
    std::wcout << L"  ██║███╗██║ ╚═══██╗██╔═══╝ ██╔═██╗ ╚════██║██╔═══╝   ╚██╔╝  \n";
    std::wcout << L"  ╚███╔███╔╝██████╔╝███████╗██║  ██╗███████║██║        ██║   \n";
    std::wcout << L"   ╚══╝╚══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝        ╚═╝   \n";
    std::wcout << L"  win32k ETW Monitor + Hooks  │  v2.0  │  Win11\n\n";
}

static void CheckAndReportPrivileges() {
    bool is_system  = IsRunningAsSystem();
    bool is_elevated = IsElevated();

    std::wcout << L"  Privileges:\n";
    std::wcout << L"    SYSTEM   : " << (is_system   ? L"✓ YES" : L"✗ NO") << L"\n";
    std::wcout << L"    Elevated : " << (is_elevated  ? L"✓ YES" : L"✗ NO") << L"\n";

    bool profile_ok = EnableProfilePrivilege();
    std::wcout << L"    SeSystemProfilePrivilege : "
               << (profile_ok ? L"✓ Enabled" : L"✗ Failed") << L"\n";

    if (!is_system && !is_elevated) {
        std::wcout << L"\n  [!] WARNING: Recommend running as SYSTEM:\n"
                   << L"      psexec -s -i W32KSpy.exe\n\n";
    } else if (!is_system) {
        std::wcout << L"\n  [i] Admin mode — EtwTi may have limited coverage.\n"
                   << L"      For full coverage: psexec -s -i W32KSpy.exe\n\n";
    } else {
        std::wcout << L"\n  [+] SYSTEM — full coverage available.\n\n";
    }
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    PrintBanner();
    CheckAndReportPrivileges();

    // ── Shared state ──────────────────────────────────────────────────
    w32kspy::SharedState   shared_state;
    w32kspy::InterestFilter filter;

    // ── ETW callback ──────────────────────────────────────────────────
    auto on_etw_event = [&](w32kspy::CapturedEvent ev) {
        if (filter.Pass(ev))
            shared_state.Push(std::move(ev));
    };

    // ── Hook callback — те же shared_state ────────────────────────────
    auto on_hook_event = [&](w32kspy::CapturedEvent ev) {
        if (filter.Pass(ev))
            shared_state.Push(std::move(ev));
    };

    // ── 1. ETW Session ────────────────────────────────────────────────
    w32kspy::EtwSession session;
    if (!session.Start()) {
        std::wcerr << L"[!] ETW session failed. Error: "
                   << session.last_error()
                   << L"\n    Run as SYSTEM: psexec -s -i W32KSpy.exe\n";
        return 1;
    }
    std::wcout << L"  [+] ETW  : win32k provider  ON\n";
    std::wcout << L"  [+] EtwTi: Threat-Intel     "
               << (session.IsEtwTiEnabled() ? L"ON" : L"OFF (need SYSTEM)") << L"\n";

    // ── 2. ETW Consumer (отдельный поток) ─────────────────────────────
    w32kspy::EtwConsumer consumer(on_etw_event);
    if (!consumer.Open(session.session_name())) {
        std::wcerr << L"[!] OpenTrace failed. Error: " << GetLastError() << L"\n";
        return 1;
    }

    std::thread etw_thread([&] { consumer.Process(); });

    // ── 3. SyscallMonitor (inline hooks + InstrCb) ────────────────────
    w32kspy::SyscallMonitor monitor(on_hook_event);

    bool inline_ok = monitor.InstallInlineHooks();
    std::wcout << L"  [+] Inline hooks : "
               << (inline_ok ? L"ON  (win32u.dll patched)" : L"OFF (win32u not loaded)") << L"\n";

    bool instr_ok = monitor.InstallInstrumentationCallback();
    std::wcout << L"  [+] InstrCb      : "
               << (instr_ok ? L"ON  (all win32k syscalls 0x1000-0x1FFF)" : L"OFF") << L"\n";

    bool iat_ok = monitor.InstallIatHooks();
    std::wcout << L"  [+] IAT hooks    : "
               << (iat_ok ? L"ON" : L"OFF (EXE doesn't import win32u directly)") << L"\n";

    auto stats = monitor.GetStats();
    std::wcout << L"\n  Active interception methods: "
               << stats.inline_hooks << L" inline  │  "
               << stats.iat_hooks    << L" IAT  │  InstrCb="
               << (stats.instr_cb ? L"yes" : L"no") << L"\n\n";

    std::wcout << L"  Launching TUI...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ── 4. TUI (блокирует до Q) ───────────────────────────────────────
    {
        w32kspy::Dashboard dashboard(shared_state, filter);
        dashboard.Run();
    }

    // ── Cleanup ───────────────────────────────────────────────────────
    shared_state.running = false;
    monitor.StopAll();
    consumer.Stop();
    session.Stop();

    if (etw_thread.joinable())
        etw_thread.join();

    std::wcout << L"\n  [+] W32KSpy stopped. Goodbye.\n";
    return 0;
}
