#pragma once

// =========================================================================
// SmartMutator — генерирует умные граничные значения
// НЕ случайный фаззер — математически обоснованные тест-кейсы
// =========================================================================

#include "config/probe_loader.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <limits>
#include <format>

namespace w32kfuzz {

// -----------------------------------------------------------------------
// Один тест-кейс = набор значений для всех параметров syscall'а
// -----------------------------------------------------------------------
struct TestCase {
    std::string              description;   // что тестируем
    FuzzStrategy             strategy;      // какая стратегия применена
    std::vector<uint64_t>    args;          // значения параметров
    int                      fuzz_param_idx; // какой параметр мутирован
};

// -----------------------------------------------------------------------
// SmartMutator
// -----------------------------------------------------------------------
class SmartMutator {
public:
    // Генерируем все тест-кейсы для данного probe
    std::vector<TestCase> Generate(const ProbeConfig& cfg) {
        std::vector<TestCase> cases;

        // Базовые значения всех параметров (без мутации)
        std::vector<uint64_t> base = BuildBase(cfg);

        // Для каждого fuzz-target параметра
        for (int i = 0; i < (int)cfg.params.size(); ++i) {
            auto& p = cfg.params[i];
            if (!p.is_fuzz_target) continue;

            auto mutations = GenerateValues(p.strategy, p.fixed_value);
            for (auto& [desc, val] : mutations) {
                TestCase tc;
                tc.description    = std::format("[{}] {} = {}",
                    p.name, desc, FormatVal(val));
                tc.strategy       = p.strategy;
                tc.fuzz_param_idx = i;
                tc.args           = base;
                tc.args[i]        = val;
                cases.push_back(std::move(tc));
            }
        }

        return cases;
    }

private:
    using ValPair = std::pair<std::string, uint64_t>;

    // Строим базовые значения из config
    static std::vector<uint64_t> BuildBase(const ProbeConfig& cfg) {
        std::vector<uint64_t> base;
        for (auto& p : cfg.params) {
            if (p.value.starts_with("valid_")) {
                base.push_back(ResolveHelper(p.value, p.type));
            } else {
                base.push_back(p.fixed_value);
            }
        }
        return base;
    }

    // Резолвим "valid_*" хелперы в реальные значения
    static uint64_t ResolveHelper(const std::string& helper,
                                   const std::string& type) {
        if (helper == "valid_dc") {
            // Создаём совместимый DC
            HDC dc = GetDC(nullptr);
            return reinterpret_cast<uint64_t>(dc);
        }
        if (helper == "valid_hwnd") {
            return reinterpret_cast<uint64_t>(GetDesktopWindow());
        }
        if (helper == "valid_buffer_256") {
            // Статический буфер — живёт на протяжении программы
            static wchar_t buf[256] = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            return reinterpret_cast<uint64_t>(buf);
        }
        if (helper == "valid_buffer_48") {
            static uint8_t buf[48]{};
            return reinterpret_cast<uint64_t>(buf);
        }
        if (helper == "null") return 0;
        return 0;
    }

    // Генерируем значения по стратегии
    std::vector<ValPair> GenerateValues(FuzzStrategy mask,
                                         uint64_t base_val) {
        std::vector<ValPair> result;

        if (HasStrategy(mask, FuzzStrategy::IntegerOverflow)) {
            result.push_back({"INT32_MAX",         0x7FFFFFFF});
            result.push_back({"INT32_MAX+1",       0x80000000});
            result.push_back({"UINT32_MAX",        0xFFFFFFFF});
            result.push_back({"UINT32_MAX-1",      0xFFFFFFFE});
            result.push_back({"INT64_MAX",         0x7FFFFFFFFFFFFFFF});
            result.push_back({"UINT64_MAX",        0xFFFFFFFFFFFFFFFF});
            result.push_back({"0x80000000_x2",     0x100000000ULL});  // overflow при x2
        }

        if (HasStrategy(mask, FuzzStrategy::Underflow)) {
            result.push_back({"zero",              0});
            result.push_back({"one",               1});
            result.push_back({"minus_one_u32",     0xFFFFFFFF});
            result.push_back({"minus_one_u64",     0xFFFFFFFFFFFFFFFF});
            result.push_back({"two",               2});
        }

        if (HasStrategy(mask, FuzzStrategy::SignedUnsigned)) {
            result.push_back({"sign_boundary_32",  0x80000000});
            result.push_back({"sign_boundary_64",  0x8000000000000000ULL});
            result.push_back({"neg1_as_uint32",    0xFFFFFFFF});
        }

        if (HasStrategy(mask, FuzzStrategy::TruncationBait)) {
            // Значения где lower32 != полное значение → провоцируем truncation
            result.push_back({"trunc_hi_set_lo0",  0x100000000ULL});  // lower32=0
            result.push_back({"trunc_hi1_lo_max",  0x1FFFFFFFFULL});  // lower32=MAX
            result.push_back({"trunc_hi_ffff",     0xFFFF00000000ULL});
            result.push_back({"trunc_lo_neg",      0x000000080000000ULL}); // lower32 отрицательный как signed
        }

        if (HasStrategy(mask, FuzzStrategy::KernelAddress)) {
            result.push_back({"kernel_base",       0xFFFF800000000000ULL});
            result.push_back({"kernel_base+1",     0xFFFF800000000001ULL});
            result.push_back({"kernel_hal",        0xFFFFF80000000000ULL});
            result.push_back({"probe_addr",        GetMmUserProbeAddress()});
            result.push_back({"probe_addr+1",      GetMmUserProbeAddress() + 1});
            result.push_back({"probe_addr-1",      GetMmUserProbeAddress() - 1});
        }

        if (HasStrategy(mask, FuzzStrategy::NullPage)) {
            result.push_back({"null",              0x0});
            result.push_back({"near_null_1",       0x1});
            result.push_back({"near_null_fff",     0xFFF});
            result.push_back({"near_null_1000",    0x1000});
        }

        if (HasStrategy(mask, FuzzStrategy::GuardPage)) {
            uint64_t probe = GetMmUserProbeAddress();
            result.push_back({"guard_exact",       probe});
            result.push_back({"guard_minus1",      probe - 1});
            result.push_back({"guard_plus1",       probe + 1});
        }

        if (HasStrategy(mask, FuzzStrategy::SizePlusOne)) {
            result.push_back({"base+1",            base_val + 1});
            result.push_back({"base+7",            base_val + 7});
            result.push_back({"base+8",            base_val + 8});
            result.push_back({"48_buf+1",          49});  // классический 48-byte buf
            result.push_back({"48_buf_ptr6",       48});  // +6 ptr = +48 байт (твой баг)
        }

        if (HasStrategy(mask, FuzzStrategy::SizeTimesTwo)) {
            // DPI-style: значения которые после DPI transform дают нужный результат
            result.push_back({"size_x2",           base_val * 2});
            result.push_back({"size_x2_overflow",  (base_val * 2) + 1});
            result.push_back({"2047_controlled",   2047}); // твой securekernel баг
            result.push_back({"2048_boundary",     2048});
        }

        if (HasStrategy(mask, FuzzStrategy::InvalidHandle)) {
            result.push_back({"invalid_handle",    0xDEADBEEF});
            result.push_back({"closed_handle",     0x4});  // типичный закрытый handle
            result.push_back({"handle_minus1",     (uint64_t)-1});
            result.push_back({"handle_0",          0});
        }

        return result;
    }

    static uint64_t GetMmUserProbeAddress() {
        // На Win11 x64 обычно 0x7FFFFFFF0000
        // Читаем из ntdll если можем
        static uint64_t cached = 0;
        if (cached) return cached;
        // MmUserProbeAddress экспортируется как SharedUserData смежный адрес
        // Для точного значения — читаем через NtQuerySystemInformation
        // Упрощённо:
        cached = 0x7FFFFFFF0000ULL;
        return cached;
    }

    static std::string FormatVal(uint64_t v) {
        if (v > 0xFFFFFFFF)
            return std::format("0x{:016X}", v);
        return std::format("0x{:08X}", (uint32_t)v);
    }
};

} // namespace w32kfuzz
