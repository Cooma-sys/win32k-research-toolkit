#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>

#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <format>
#include <span>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "psapi.lib")

namespace w32kspy {

// -----------------------------------------------------------------------
// Уровень интересности события
// -----------------------------------------------------------------------
enum class Severity {
    Info,       // обычное событие
    Suspicious, // стоит посмотреть ⚠️
    Critical    // точно интересно  🔴
};

// -----------------------------------------------------------------------
// Одно захваченное событие
// -----------------------------------------------------------------------
struct CapturedEvent {
    std::wstring    timestamp;
    std::wstring    provider;   // "win32k" / "kernel" / ...
    ULONG           pid{};
    ULONG           tid{};
    std::wstring    process_name;
    std::wstring    event_name;
    std::wstring    details;    // аргументы / поля
    Severity        severity{ Severity::Info };
    bool            is_system_token{ false };
};

using EventCallback = std::function<void(CapturedEvent)>;

// -----------------------------------------------------------------------
// Кэш имён процессов  pid → name
// -----------------------------------------------------------------------
class ProcessCache {
public:
    std::wstring Get(ULONG pid) {
        std::lock_guard lock(mtx_);
        auto it = cache_.find(pid);
        if (it != cache_.end()) return it->second;

        wchar_t buf[MAX_PATH]{};
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
                // Берём только имя файла
                std::wstring full(buf);
                auto pos = full.rfind(L'\\');
                std::wstring name = (pos != std::wstring::npos)
                    ? full.substr(pos + 1) : full;
                CloseHandle(h);
                cache_[pid] = name;
                return name;
            }
            CloseHandle(h);
        }
        cache_[pid] = L"<unknown>";
        return L"<unknown>";
    }

    void Invalidate(ULONG pid) {
        std::lock_guard lock(mtx_);
        cache_.erase(pid);
    }

private:
    std::unordered_map<ULONG, std::wstring> cache_;
    std::mutex mtx_;
};

// -----------------------------------------------------------------------
// Глобальный consumer state (ETW callback не может быть методом класса)
// -----------------------------------------------------------------------
struct ConsumerState {
    EventCallback   callback;
    ProcessCache    proc_cache;
};

static ConsumerState* g_state = nullptr; // инициализируется в EtwConsumer::Start()

// -----------------------------------------------------------------------
// Хелперы для чтения TDH полей
// -----------------------------------------------------------------------
inline std::wstring ReadTdhString(PEVENT_RECORD rec, PTRACE_EVENT_INFO info,
                                   ULONG prop_idx)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(
        reinterpret_cast<PBYTE>(info) + info->EventPropertyInfoArray[prop_idx].NameOffset);
    desc.ArrayIndex = 0;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size == 0)
        return {};

    std::vector<BYTE> buf(size);
    if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, buf.data()) != ERROR_SUCCESS)
        return {};

    // Определяем тип — возвращаем как wstring
    auto& pinfo = info->EventPropertyInfoArray[prop_idx];
    if (pinfo.nonStructType.InType == TDH_INTYPE_UNICODESTRING)
        return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
    if (pinfo.nonStructType.InType == TDH_INTYPE_ANSISTRING)
        return std::wstring(buf.begin(), buf.end());

    // Числовые — hex
    if (size == 4) {
        ULONG v{}; memcpy(&v, buf.data(), 4);
        return std::format(L"0x{:08X}", v);
    }
    if (size == 8) {
        ULONG64 v{}; memcpy(&v, buf.data(), 8);
        return std::format(L"0x{:016X}", v);
    }
    return std::format(L"[{} bytes]", size);
}

// -----------------------------------------------------------------------
// ETW callback
// -----------------------------------------------------------------------
static void WINAPI EventRecordCallback(PEVENT_RECORD rec)
{
    if (!g_state || !rec) return;
    if (rec->EventHeader.ProcessId == GetCurrentProcessId()) return;

    // Получаем метаданные через TDH
    ULONG info_size = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &info_size);
    if (info_size == 0) return;

    std::vector<BYTE> info_buf(info_size);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(info_buf.data());
    if (TdhGetEventInformation(rec, 0, nullptr, info, &info_size) != ERROR_SUCCESS)
        return;

    CapturedEvent ev;

    // Timestamp
    SYSTEMTIME st{};
    FileTimeToSystemTime(reinterpret_cast<FILETIME*>(
        &rec->EventHeader.TimeStamp), &st);
    ev.timestamp = std::format(L"{:02}:{:02}:{:02}.{:03}",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // PID / TID / Process name
    ev.pid = rec->EventHeader.ProcessId;
    ev.tid = rec->EventHeader.ThreadId;
    ev.process_name = g_state->proc_cache.Get(ev.pid);

    // Provider name
    if (info->ProviderNameOffset)
        ev.provider = reinterpret_cast<wchar_t*>(
            reinterpret_cast<PBYTE>(info) + info->ProviderNameOffset);

    // Event name
    if (info->EventNameOffset)
        ev.event_name = reinterpret_cast<wchar_t*>(
            reinterpret_cast<PBYTE>(info) + info->EventNameOffset);
    else
        ev.event_name = std::format(L"Event_{}", rec->EventHeader.EventDescriptor.Id);

    // Собираем первые N свойств как details
    std::wstring details;
    ULONG max_props = (std::min)(info->TopLevelPropertyCount, static_cast<ULONG>(6));
    for (ULONG i = 0; i < max_props; ++i) {
        if (info->EventPropertyInfoArray[i].NameOffset == 0) continue;
        std::wstring name = reinterpret_cast<wchar_t*>(
            reinterpret_cast<PBYTE>(info) + info->EventPropertyInfoArray[i].NameOffset);
        std::wstring val = ReadTdhString(rec, info, i);
        if (!val.empty())
            details += name + L"=" + val + L"  ";
    }
    ev.details = details.empty() ? L"—" : details;

    // Severity — базовая эвристика
    // SYSTEM token: PID 4 (System), lsass, csrss обычно не вызывают win32k напрямую
    ev.is_system_token = (ev.pid == 4);

    // Подозрительные event ID'ы win32k (неполный список — дополняй)
    // 0x1000+ обычно NtUser*, некоторые конкретные — известные классы багов
    USHORT eid = rec->EventHeader.EventDescriptor.Id;
    if (ev.is_system_token) {
        ev.severity = Severity::Critical;
    } else if (
        // Необычные вызовы SetWindowsHookEx, SendMessage к другим процессам
        eid == 0x0B01 || eid == 0x0B02 ||
        // Alloc в session space
        eid == 0x0A10 ||
        // Callback в usermode из kernel
        eid == 0x0C01
    ) {
        ev.severity = Severity::Suspicious;
    }

    g_state->callback(std::move(ev));
}

// -----------------------------------------------------------------------
// EtwConsumer — открывает real-time сессию и обрабатывает события
// -----------------------------------------------------------------------
class EtwConsumer {
public:
    explicit EtwConsumer(EventCallback cb) {
        // Один глобальный state (ETW callback — статическая функция)
        state_ = std::make_unique<ConsumerState>();
        state_->callback = std::move(cb);
        g_state = state_.get();
    }

    ~EtwConsumer() {
        Stop();
        g_state = nullptr;
    }

    bool Open(const wchar_t* session_name) {
        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName          = const_cast<LPWSTR>(session_name);
        logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                      PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = EventRecordCallback;

        trace_handle_ = OpenTraceW(&logfile);
        return trace_handle_ != INVALID_PROCESSTRACE_HANDLE;
    }

    // Блокирующий — вызывай из отдельного потока
    void Process() {
        ProcessTrace(&trace_handle_, 1, nullptr, nullptr);
    }

    void Stop() {
        if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(trace_handle_);
            trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
        }
    }

private:
    TRACEHANDLE trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    std::unique_ptr<ConsumerState> state_;
};

} // namespace w32kspy
