#pragma once

// =========================================================================
// Classifier — определяет verdict по результатам вызова
// =========================================================================

#include "config/probe_loader.hpp"
#include "monitor/spy_bridge.hpp"
#include "caller/syscall_stub.hpp"
#include <string>
#include <format>

namespace w32kfuzz {

// -----------------------------------------------------------------------
// Вердикт
// -----------------------------------------------------------------------
enum class Verdict {
    ConfirmedWrite,       // 🔴 запись в kernel addr подтверждена
    ConfirmedCorruption,  // 🔴 pool/heap corruption
    ConfirmedCrash,       // 🔴 crash при вызове
    Suspicious,           // ⚠️  аномалия — нужен ручной анализ
    UnexpectedStatus,     // ⚠️  нестандартный NTSTATUS
    FalsePositive,        // ✅  всё ожидаемо
    NeedsManual,          // 🔍  неоднозначно
};

struct VerdictResult {
    Verdict     verdict{ Verdict::FalsePositive };
    std::string description;
    std::string test_case_desc;
    NTSTATUS    status{ 0 };
    bool        is_interesting() const {
        return verdict != Verdict::FalsePositive;
    }
};

// -----------------------------------------------------------------------
// Classifier
// -----------------------------------------------------------------------
class Classifier {
public:
    VerdictResult Classify(const ProbeConfig&  cfg,
                           const std::string&  test_desc,
                           const CallResult&   call,
                           const MonitorResult& mon)
    {
        VerdictResult r;
        r.test_case_desc = test_desc;
        r.status         = call.status;

        // 1. Crash при вызове
        if (call.crashed) {
            r.verdict     = Verdict::ConfirmedCrash;
            r.description = std::format(
                "CRASH: exception 0x{:08X} during syscall 0x{:04X}",
                (uint32_t)call.status, cfg.syscall_id);
            return r;
        }

        // 2. Kernel write подтверждён через наблюдение
        for (auto& obs : mon.observations) {
            if (obs.type == ObservationType::KernelAddressAccess) {
                if (IsExpected(cfg, ExpectType::KernelWrite)) {
                    r.verdict     = Verdict::ConfirmedWrite;
                    r.description = std::format(
                        "KERNEL WRITE CONFIRMED: {} | status=0x{:08X}",
                        obs.description, (uint32_t)call.status);
                    return r;
                }
                r.verdict     = Verdict::Suspicious;
                r.description = "Unexpected kernel address access: " + obs.description;
                return r;
            }

            if (obs.type == ObservationType::PoolCorruption) {
                r.verdict     = Verdict::ConfirmedCorruption;
                r.description = "POOL CORRUPTION: " + obs.description;
                return r;
            }
        }

        // 3. STATUS_SUCCESS на kernel addr = подозрительно само по себе
        //    (как твой NtUserTransformPoint — STATUS_SUCCESS на 0xFFFF...)
        if (call.status == STATUS_SUCCESS) {
            bool had_kernel_arg = false;
            // Проверяем — был ли в аргументах kernel адрес
            // (упрощённо: смотрим на description теста)
            if (test_desc.find("kernel") != std::string::npos ||
                test_desc.find("FFFF8") != std::string::npos ||
                test_desc.find("FFFFF") != std::string::npos) {
                r.verdict     = Verdict::ConfirmedWrite;
                r.description = std::format(
                    "STATUS_SUCCESS with kernel VA arg! syscall=0x{:04X}",
                    cfg.syscall_id);
                return r;
            }
        }

        // 4. Аномалии от монитора
        if (mon.anomaly_detected) {
            r.verdict     = Verdict::Suspicious;
            r.description = "Anomaly: " + mon.summary;
            return r;
        }

        // 5. Неожиданный NTSTATUS
        if (!IsExpectedStatus(call.status)) {
            r.verdict     = Verdict::UnexpectedStatus;
            r.description = std::format(
                "Unexpected status 0x{:08X} for syscall 0x{:04X}",
                (uint32_t)call.status, cfg.syscall_id);
            return r;
        }

        // 6. Всё ожидаемо
        r.verdict     = Verdict::FalsePositive;
        r.description = std::format("OK status=0x{:08X}", (uint32_t)call.status);
        return r;
    }

    static std::string VerdictIcon(Verdict v) {
        switch (v) {
            case Verdict::ConfirmedWrite:      return "[!!!] CONFIRMED KERNEL WRITE";
            case Verdict::ConfirmedCorruption: return "[!!!] CONFIRMED CORRUPTION";
            case Verdict::ConfirmedCrash:      return "[!!!] CONFIRMED CRASH";
            case Verdict::Suspicious:          return "[ ! ] SUSPICIOUS";
            case Verdict::UnexpectedStatus:    return "[ ? ] UNEXPECTED STATUS";
            case Verdict::NeedsManual:         return "[ ~ ] NEEDS MANUAL";
            case Verdict::FalsePositive:       return "[   ] ok";
        }
        return "[   ] ok";
    }

private:
    static bool IsExpected(const ProbeConfig& cfg, ExpectType t) {
        for (auto& e : cfg.expect)
            if (e == t || e == ExpectType::Any) return true;
        return false;
    }

    static bool IsExpectedStatus(NTSTATUS s) {
        // Типичные "нормальные" статусы для win32k
        static constexpr NTSTATUS kNormal[] = {
            static_cast<NTSTATUS>(0x00000000L), // STATUS_SUCCESS
            static_cast<NTSTATUS>(0xC000000DL), // STATUS_INVALID_PARAMETER
            static_cast<NTSTATUS>(0xC0000008L), // STATUS_INVALID_HANDLE
            static_cast<NTSTATUS>(0xC0000005L), // STATUS_ACCESS_VIOLATION
            static_cast<NTSTATUS>(0x80000005L), // STATUS_BUFFER_OVERFLOW
            static_cast<NTSTATUS>(0xC0000022L), // STATUS_ACCESS_DENIED
        };
        for (auto n : kNormal)
            if (s == n) return true;
        return false;
    }
};

} // namespace w32kfuzz
