#pragma once

// =========================================================================
// SyscallStub — прямые win32k syscall вызовы
// =========================================================================
// win32k syscalls живут в диапазоне 0x1000-0x1FFF
// Вызываются через win32u.dll stub'ы или прямо через syscall инструкцию
//
// Мы используем прямой syscall чтобы:
//   1. Не зависеть от IAT и импортов
//   2. Передавать точно те аргументы которые хотим
//   3. Байпасить любые usermode хуки на win32u.dll
// =========================================================================

#include <windows.h>
#define WIN32_NO_STATUS
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <vector>
#include <string>
#include <functional>
#include <chrono>
#include <format>

#pragma comment(lib, "ntdll.lib")

namespace w32kfuzz {

// -----------------------------------------------------------------------
// Результат одного вызова
// -----------------------------------------------------------------------
struct CallResult {
    NTSTATUS    status{ 0 };
    uint64_t    return_value{ 0 };
    bool        crashed{ false };
    bool        timed_out{ false };
    uint32_t    duration_ms{ 0 };
    std::string error_desc;
};

// -----------------------------------------------------------------------
// x64 direct syscall thunk — генерируется в runtime
//
// Stub:
//   mov r10, rcx
//   mov eax, <syscall_number>
//   syscall
//   ret
//
// До 16 аргументов (4 в регистрах + 12 на стеке через shadow space)
// -----------------------------------------------------------------------
class SyscallStub {
public:
    explicit SyscallStub(uint32_t syscall_id) : id_(syscall_id) {
        BuildThunk();
    }

    ~SyscallStub() {
        if (thunk_) VirtualFree(thunk_, 0, MEM_RELEASE);
    }

    // Вызов с до 8 аргументами (достаточно для win32k)
    CallResult Call(const std::vector<uint64_t>& args) {
        CallResult result;

        if (!thunk_) {
            result.error_desc = "Thunk not built";
            return result;
        }

        auto start = std::chrono::high_resolution_clock::now();

        // SEH вынесен в отдельную plain C функцию — C2712 фикс
        // (__try нельзя в функциях с C++ объектами-деструкторами)
        uint64_t ret_val  = 0;
        NTSTATUS exc_code = 0;
        bool     crashed  = false;
        InvokeThunkSEH(args, &ret_val, &exc_code, &crashed);

        result.return_value = ret_val;
        result.crashed      = crashed;
        if (crashed) {
            result.status     = exc_code;
            result.error_desc = std::format("Exception: 0x{:08X}",
                static_cast<uint32_t>(exc_code));
        } else {
            result.status = static_cast<NTSTATUS>(ret_val);
        }

        auto end = std::chrono::high_resolution_clock::now();
        result.duration_ms = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                end - start).count());

        return result;
    }

    [[nodiscard]] uint32_t id() const { return id_; }
    [[nodiscard]] bool     valid() const { return thunk_ != nullptr; }

private:
    uint32_t id_;
    void*    thunk_{ nullptr };

    void BuildThunk() {
        // x64 syscall stub:
        // 49 89 CA        mov r10, rcx
        // B8 xx xx xx xx  mov eax, <id>
        // 0F 05           syscall
        // C3              ret
        // Итого: 12 байт

        uint8_t code[] = {
            0x4C, 0x89, 0xD1,              // mov r10, rcx  (r10 = first arg)
            0xB8,
            static_cast<uint8_t>(id_),
            static_cast<uint8_t>(id_ >> 8),
            static_cast<uint8_t>(id_ >> 16),
            static_cast<uint8_t>(id_ >> 24), // mov eax, id
            0x0F, 0x05,                    // syscall
            0xC3                           // ret
        };

        thunk_ = VirtualAlloc(nullptr, sizeof(code),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!thunk_) return;

        memcpy(thunk_, code, sizeof(code));
        FlushInstructionCache(GetCurrentProcess(), thunk_, sizeof(code));
    }

    // SEH-обёртка: plain C функция без C++ деструкторов — избегаем C2712
    void InvokeThunkSEH(const std::vector<uint64_t>& args,
                        uint64_t* out_ret,
                        NTSTATUS* out_exc,
                        bool*     out_crashed) const
    {
        // Паддим до 8 аргументов (POD массив — SEH совместим)
        uint64_t a[8]{};
        for (size_t i = 0; i < args.size() && i < 8; ++i)
            a[i] = args[i];

        using Fn8 = uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t);
        auto fn = reinterpret_cast<Fn8>(thunk_);

        // SEH здесь легален — у нас только POD локальные переменные
        __try {
            *out_ret     = fn(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
            *out_crashed = false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            *out_ret     = 0;
            *out_exc     = GetExceptionCode();
            *out_crashed = true;
        }
    }
};

// -----------------------------------------------------------------------
// SyscallRegistry — кэш stub'ов по syscall ID
// -----------------------------------------------------------------------
class SyscallRegistry {
public:
    SyscallStub& Get(uint32_t id) {
        auto it = cache_.find(id);
        if (it != cache_.end()) return *it->second;
        auto stub = std::make_unique<SyscallStub>(id);
        auto& ref = *stub;
        cache_[id] = std::move(stub);
        return ref;
    }

    void Clear() { cache_.clear(); }

private:
    std::unordered_map<uint32_t, std::unique_ptr<SyscallStub>> cache_;
};

} // namespace w32kfuzz
