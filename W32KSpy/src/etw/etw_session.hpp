#pragma once

#include <windows.h>
#include <objbase.h>     // CoCreateGuid
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")   // CoCreateGuid

namespace w32kspy {

// ETW провайдеры интересные для win32k / GUI subsystem
// Microsoft-Windows-Win32k
static constexpr GUID kWin32kProviderGuid = {
    0x8c416c79, 0xd49b, 0x4f01,
    {0xa4, 0x67, 0xe5, 0x6d, 0x3a, 0xa8, 0x23, 0x4c}
};

// Microsoft-Windows-Kernel-Process (для фильтра по процессам)
static constexpr GUID kKernelProcessGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b,
    {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}
};

// Microsoft-Windows-RPC (ALPC/RPC к system сервисам)
static constexpr GUID kRpcProviderGuid = {
    0x6ad52b32, 0xd609, 0x4be9,
    {0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39}
};

// Microsoft-Windows-Threat-Intelligence (EtwTi)
// Требует SeSystemProfilePrivilege (SYSTEM даёт автоматически)
// Покрывает: VirtualAlloc/Protect, ReadProcessMemory, WriteProcessMemory,
//            CreateRemoteThread, QueueUserAPC, MapViewOfSection и др.
// Используется EDR'ами — нам полезен для корреляции с win32k событиями
static constexpr GUID kEtwTiProviderGuid = {
    0xf4e1897c, 0xbb5d, 0x5668,
    {0xf1, 0xd8, 0x94, 0x56, 0x1d, 0x28, 0x00, 0x00}
};

// Microsoft-Windows-Kernel-Audit-API-Calls
// Логирует: OpenProcess, OpenThread, TerminateProcess
// Отлично дополняет win32k мониторинг — видим кто открывает чужие процессы
static constexpr GUID kKernelAuditApiGuid = {
    0xe02a841c, 0x75a3, 0x4fa7,
    {0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}
};

// Microsoft-Windows-Security-Auditing (только для коррелляции)
// Даёт нам привилегии, logon events и т.д.
static constexpr GUID kSecurityAuditGuid = {
    0x54849625, 0x5478, 0x4994,
    {0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d}
};

static constexpr wchar_t kSessionName[] = L"W32KSpySession";

class EtwSession {
public:
    EtwSession() = default;
    ~EtwSession() { Stop(); }

    // Некопируемый
    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    bool Start() {
        // Размер буфера для EVENT_TRACE_PROPERTIES + имя сессии
        const size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES) +
                               sizeof(kSessionName) + sizeof(wchar_t);
        props_buf_.resize(bufSize, 0);

        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf_.data());
        props->Wnode.BufferSize    = static_cast<ULONG>(bufSize);
        props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1; // QPC clock — самый точный
        CoCreateGuid(&props->Wnode.Guid);

        props->LogFileMode  = EVENT_TRACE_REAL_TIME_MODE;
        props->MaximumFileSize = 0;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // Останавливаем старую сессию если осталась с прошлого запуска
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);

        // Пересоздаём буфер после ControlTrace (затирает данные)
        std::fill(props_buf_.begin(), props_buf_.end(), 0);
        props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf_.data());
        props->Wnode.BufferSize    = static_cast<ULONG>(bufSize);
        props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        CoCreateGuid(&props->Wnode.Guid);
        props->LogFileMode  = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = StartTraceW(&session_handle_, kSessionName, props);
        if (status != ERROR_SUCCESS) {
            last_error_ = status;
            return false;
        }

        // Включаем win32k провайдер — максимальный уровень, все keyword'ы
        status = EnableTraceEx2(
            session_handle_,
            &kWin32kProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0xFFFFFFFFFFFFFFFF, // все keyword'ы
            0,
            0,
            nullptr
        );
        if (status != ERROR_SUCCESS) {
            last_error_ = status;
            Stop();
            return false;
        }

        // Включаем kernel process провайдер
        EnableTraceEx2(
            session_handle_,
            &kKernelProcessGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0x10, // PROCESS keyword
            0, 0, nullptr
        );

        // Включаем EtwTi — Microsoft-Windows-Threat-Intelligence
        // Keywords для EtwTi (документировано частично):
        //   0x0001 — ReadVirtualMemory
        //   0x0002 — WriteVirtualMemory
        //   0x0004 — SetContextThread (thread hijack)
        //   0x0008 — AllocateVirtualMemory
        //   0x0010 — ProtectVirtualMemory
        //   0x0020 — MapViewOfSection
        //   0x0040 — QueueUserApc
        //   0x0080 — CreateRemoteThread
        //   0x8000 — все остальные
        etw_ti_ok_ = (ERROR_SUCCESS == EnableTraceEx2(
            session_handle_,
            &kEtwTiProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0x00FF,  // все перечисленные выше keywords
            0, 0, nullptr
        ));

        // Kernel Audit API — OpenProcess/Thread/TerminateProcess
        EnableTraceEx2(
            session_handle_,
            &kKernelAuditApiGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0xFFFFFFFFFFFFFFFF,
            0, 0, nullptr
        );

        return true;
    }

    [[nodiscard]] bool IsEtwTiEnabled() const { return etw_ti_ok_; }

    void Stop() {
        if (session_handle_ != 0) {
            auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf_.data());
            ControlTraceW(session_handle_, nullptr, props, EVENT_TRACE_CONTROL_STOP);
            session_handle_ = 0;
        }
    }

    [[nodiscard]] TRACEHANDLE handle() const { return session_handle_; }
    [[nodiscard]] ULONG last_error() const { return last_error_; }
    [[nodiscard]] const wchar_t* session_name() const { return kSessionName; }

private:
    TRACEHANDLE session_handle_ = 0;
    std::vector<BYTE> props_buf_;
    ULONG last_error_ = 0;
    bool  etw_ti_ok_  = false;
};

} // namespace w32kspy
