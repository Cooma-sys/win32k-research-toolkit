#pragma once

// =========================================================================
// SpyBridge — мост между W32KFuzz и W32KSpy
// Слушает ETW события во время вызова syscall'а и коррелирует результат
// =========================================================================

#include <windows.h>
#define WIN32_NO_STATUS
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <format>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace w32kfuzz {

// -----------------------------------------------------------------------
// Наблюдение которое поймал SpyBridge за время одного вызова
// -----------------------------------------------------------------------
enum class ObservationType {
    None,
    KernelAddressAccess,   // обращение к kernel VA
    PoolCorruption,        // ETW pool corruption event
    UnexpectedStatus,      // нестандартный NTSTATUS
    LargeAllocation,       // подозрительно большой alloc
    CrossProcessAccess,    // доступ к чужому процессу
    HookTriggered,         // сработал inline хук W32KSpy
};

struct Observation {
    ObservationType type{ ObservationType::None };
    std::string     description;
    uint64_t        address{ 0 };
    uint32_t        pid{ 0 };
    NTSTATUS        status{ 0 };
};

// -----------------------------------------------------------------------
// Результат наблюдения за одним вызовом
// -----------------------------------------------------------------------
struct MonitorResult {
    std::vector<Observation> observations;
    bool                     anomaly_detected{ false };
    std::string              summary;

    void Add(Observation obs) {
        anomaly_detected = true;
        summary += obs.description + "; ";
        observations.push_back(std::move(obs));
    }
};

// -----------------------------------------------------------------------
// SpyBridge
// -----------------------------------------------------------------------
class SpyBridge {
public:
    SpyBridge() = default;
    ~SpyBridge() { Stop(); }

    // Начинаем наблюдение (вызывать ДО syscall)
    void Begin() {
        std::lock_guard lock(mtx_);
        current_.observations.clear();
        current_.anomaly_detected = false;
        current_.summary.clear();
        active_ = true;
        call_start_ = std::chrono::steady_clock::now();
    }

    // Заканчиваем наблюдение (вызывать ПОСЛЕ syscall)
    MonitorResult End() {
        std::lock_guard lock(mtx_);
        active_ = false;
        return current_;
    }

    // Вызывается из ETW callback W32KSpy когда ловит событие
    // (SpyBridge регистрируется как listener в SharedState)
    void OnEvent(const std::string& event_name,
                 uint64_t           address,
                 NTSTATUS           status,
                 uint32_t           pid)
    {
        if (!active_) return;
        std::lock_guard lock(mtx_);

        Observation obs;
        obs.address = address;
        obs.status  = status;
        obs.pid     = pid;

        // Kernel address access
        if (address >= 0xFFFF800000000000ULL) {
            obs.type        = ObservationType::KernelAddressAccess;
            obs.description = std::format(
                "Kernel VA access: 0x{:016X} in {}", address, event_name);
            current_.Add(std::move(obs));
            return;
        }

        // Pool corruption — ловим через специфичные ETW event ID'ы
        if (event_name.find("PoolCorrupt") != std::string::npos ||
            event_name.find("HeapCorrupt") != std::string::npos) {
            obs.type        = ObservationType::PoolCorruption;
            obs.description = std::format("Pool corruption: {}", event_name);
            current_.Add(std::move(obs));
            return;
        }

        // Неожиданный статус (не SUCCESS и не типичные ошибки)
        if (status != 0 &&
            status != STATUS_INVALID_PARAMETER &&
            status != STATUS_ACCESS_DENIED &&
            status != static_cast<NTSTATUS>(0xC0000008L) && // STATUS_INVALID_HANDLE
            status != static_cast<NTSTATUS>(0xC000000DL))   // STATUS_INVALID_PARAMETER
        {
            obs.type        = ObservationType::UnexpectedStatus;
            obs.description = std::format(
                "Unexpected NTSTATUS: 0x{:08X} in {}", (uint32_t)status, event_name);
            current_.Add(std::move(obs));
        }
    }

    // Прямая проверка — можем ли мы записать по kernel адресу
    // (симулируем твой NtUserTransformPoint тест)
    static bool ProbeKernelWrite(uint64_t kernel_addr) {
        // VirtualProtect должен фейлиться на kernel VA
        DWORD old{};
        if (VirtualProtect(reinterpret_cast<void*>(kernel_addr),
                           1, PAGE_READWRITE, &old)) {
            VirtualProtect(reinterpret_cast<void*>(kernel_addr),
                           1, old, &old);
            return false; // usermode адрес — не интересно
        }
        return true; // kernel адрес — потенциальный target
    }

    void Stop() { active_ = false; }

private:
    std::mutex              mtx_;
    std::atomic<bool>       active_{ false };
    MonitorResult           current_;
    std::chrono::steady_clock::time_point call_start_;
};

} // namespace w32kfuzz
