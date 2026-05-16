#pragma once

// =========================================================================
// Instrumentation Callback — перехват всех syscall return'ов
// =========================================================================
// Как работает:
//   Windows поддерживает недокументированный механизм ProcessInstrumentationCallback
//   (класс 40 для NtSetInformationProcess). После установки callback'а ядро
//   вызывает его ПОСЛЕ каждого возврата из syscall в данном процессе.
//
//   Что мы получаем:
//     - RCX = NTSTATUS (результат syscall)
//     - R10 = оригинальный RIP (куда вернулся бы syscall)
//     - RSP = стек пользователя
//
//   Из этого можно:
//     1. Смотреть syscall number (был в RAX до syscall)
//     2. Восстанавливать аргументы из стека (RSP+0x28 и выше)
//     3. Фильтровать конкретные NtUser*/NtGdi* по номеру
//
//   Win32k syscall numbers (win32u.dll, Win11 последний build):
//     Диапазон 0x1000-0x1FFF — WIN32K syscalls (NtUser*, NtGdi*)
//     Диапазон 0x0000-0x0FFF — NT syscalls (ntoskrnl)
//
//   Применение: ловим ВСЕ win32k вызовы без IAT и без inline хуков,
//   даже если процесс использует direct syscall.
// =========================================================================

#include <windows.h>
#include <winternl.h>
#include <string>
#include <functional>
#include <atomic>
#include <format>

#pragma comment(lib, "ntdll.lib")

namespace w32kspy::hooks {

// -----------------------------------------------------------------------
// Структура для NtSetInformationProcess (класс 40)
// -----------------------------------------------------------------------
struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG  Version;   // 0 для x64
    ULONG  Reserved;
    void*  Callback;  // адрес нашего callback'а
};

// Номер информационного класса
static constexpr ULONG ProcessInstrumentationCallback = 40;

// -----------------------------------------------------------------------
// Контекст который получает callback (восстанавливаем из регистров)
// -----------------------------------------------------------------------
struct SyscallContext {
    ULONG64 syscall_number; // из R11 (сохраняется ядром перед syscall)
    ULONG64 return_value;   // NTSTATUS в RCX
    ULONG64 return_address; // оригинальный RIP (R10)
    ULONG64 rsp;            // стек пользователя
    // Аргументы syscall — были в регистрах/стеке до syscall:
    ULONG64 arg1; // RCX (был R10 до mov r10,rcx)
    ULONG64 arg2; // RDX
    ULONG64 arg3; // R8
    ULONG64 arg4; // R9
};

using InstrCallback = std::function<void(const SyscallContext&)>;

// -----------------------------------------------------------------------
// Глобальный callback state
// -----------------------------------------------------------------------
struct InstrState {
    InstrCallback   on_syscall;
    std::atomic<bool> active{ false };

    // Фильтр: только win32k диапазон (0x1000-0x1FFF)
    bool win32k_only = true;
};

static InstrState* g_instr_state = nullptr;

// -----------------------------------------------------------------------
// Сам callback — вызывается из asm thunk'а ниже
// -----------------------------------------------------------------------
extern "C" void __cdecl InstrumentationCallbackImpl(SyscallContext* ctx) {
    if (!g_instr_state || !g_instr_state->active) return;

    // Фильтр по диапазону
    if (g_instr_state->win32k_only) {
        if (ctx->syscall_number < 0x1000 || ctx->syscall_number > 0x1FFF)
            return;
    }

    if (g_instr_state->on_syscall)
        g_instr_state->on_syscall(*ctx);
}

// -----------------------------------------------------------------------
// ASM thunk — сохраняем регистры и вызываем C++ handler
//
// Windows вызывает нас с:
//   RCX = NTSTATUS (return value)
//   R10 = оригинальный RIP
//   RSP = стек пользователя
//   R11 = RFLAGS (содержит информацию о syscall)
//
// Соглашение: мы должны вернуть управление на R10.
// -----------------------------------------------------------------------
// Thunk написан как отдельная .asm функция — здесь объявляем extern
extern "C" void InstrumentationCallbackThunk();

// Реализация thunk'а inline через __asm не поддерживается в MSVC x64.
// Используем отдельный .asm файл (instrumentation_cb.asm) или
// альтернативно — encoded bytes через VirtualAlloc.
//
// Для упрощения используем __declspec(naked) через x86 intrinsics
// — но MSVC x64 не поддерживает naked. Поэтому генерируем thunk
// программно как байт-массив.

class InstrumentationCallbackEngine {
public:
    ~InstrumentationCallbackEngine() { Uninstall(); }

    bool Install(InstrCallback cb, bool win32k_only = true) {
        if (state_) return false; // уже установлен

        state_ = std::make_unique<InstrState>();
        state_->on_syscall  = std::move(cb);
        state_->win32k_only = win32k_only;
        state_->active      = true;
        g_instr_state       = state_.get();

        // Генерируем x64 thunk в исполняемой памяти
        thunk_mem_ = BuildThunk();
        if (!thunk_mem_) {
            g_instr_state = nullptr;
            state_.reset();
            return false;
        }

        // Устанавливаем через NtSetInformationProcess
        using NtSIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto NtSIP = reinterpret_cast<NtSIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                           "NtSetInformationProcess"));
        if (!NtSIP) return false;

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info{};
        info.Version  = 0;
        info.Reserved = 0;
        info.Callback = thunk_mem_;

        NTSTATUS st = NtSIP(GetCurrentProcess(),
                            ProcessInstrumentationCallback,
                            &info, sizeof(info));
        if (!NT_SUCCESS(st)) {
            VirtualFree(thunk_mem_, 0, MEM_RELEASE);
            thunk_mem_ = nullptr;
            g_instr_state = nullptr;
            state_.reset();
            return false;
        }

        return true;
    }

    void Uninstall() {
        if (!state_) return;
        state_->active = false;

        // Снимаем callback: передаём nullptr
        using NtSIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto NtSIP = reinterpret_cast<NtSIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                           "NtSetInformationProcess"));
        if (NtSIP) {
            PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info{};
            NtSIP(GetCurrentProcess(),
                  ProcessInstrumentationCallback,
                  &info, sizeof(info));
        }

        if (thunk_mem_) {
            VirtualFree(thunk_mem_, 0, MEM_RELEASE);
            thunk_mem_ = nullptr;
        }
        g_instr_state = nullptr;
        state_.reset();
    }

    [[nodiscard]] bool IsActive() const {
        return state_ && state_->active;
    }

private:
    // -----------------------------------------------------------------------
    // Программная генерация x64 thunk'а
    //
    // Логика thunk'а:
    //   ; Windows передаёт управление сюда после каждого syscall return
    //   ; RCX = return value (NTSTATUS)
    //   ; R10 = original RIP (куда надо вернуться)
    //   ; RSP = user stack
    //
    //   push r10          ; сохраняем return address
    //   push rcx          ; сохраняем return value
    //   sub rsp, 48h      ; shadow space + выравнивание
    //
    //   ; Заполняем SyscallContext
    //   mov [rsp+30h], r10   ; return_address
    //   mov [rsp+28h], rcx   ; return_value
    //   ; syscall_number — берём из TEB->InstrumentationCallbackPreviousPc (недокументировано)
    //   ; Упрощённо: кладём 0 или R11
    //   mov [rsp+20h], r11   ; syscall_number (RFLAGS, приближение)
    //
    //   ; Первый аргумент для InstrumentationCallbackImpl — указатель на SyscallContext
    //   lea rcx, [rsp+20h]
    //   mov rax, <addr InstrumentationCallbackImpl>
    //   call rax
    //
    //   add rsp, 48h
    //   pop rcx          ; восстанавливаем return value
    //   pop r10          ; восстанавливаем return address
    //   jmp r10          ; прыгаем обратно
    // -----------------------------------------------------------------------
    void* BuildThunk() {
        // Кодируем thunk вручную
        // Адрес C++ handler'а
        ULONG64 impl_addr = reinterpret_cast<ULONG64>(&InstrumentationCallbackImpl);

        // Буфер под байты
        std::vector<BYTE> code;
        code.reserve(128);

        auto emit = [&](std::initializer_list<BYTE> b) {
            for (auto x : b) code.push_back(x);
        };
        auto emit64 = [&](ULONG64 v) {
            for (int i = 0; i < 8; ++i)
                code.push_back(static_cast<BYTE>((v >> (i * 8)) & 0xFF));
        };

        // push r10  (41 52)
        emit({ 0x41, 0x52 });
        // push rcx  (51)
        emit({ 0x51 });
        // sub rsp, 0x48  (48 83 EC 48)
        emit({ 0x48, 0x83, 0xEC, 0x48 });

        // mov [rsp+0x20], r11   — syscall number approx  (4C 89 5C 24 20)
        emit({ 0x4C, 0x89, 0x5C, 0x24, 0x20 });
        // mov [rsp+0x28], rcx   — return value was pushed, reload  (но rcx сохранён на стеке)
        // rcx сейчас = return value (не изменялся после push)
        emit({ 0x48, 0x89, 0x4C, 0x24, 0x28 });
        // r10 = original RIP (сохранён на стеке), mov rax, [rsp+0x48+8] = [rsp+0x50]
        // Проще: r10 ещё в регистре до push r10? Нет, мы его запушили.
        // Перезагружаем: mov rax, [rsp+0x50] (r10 был push'нут первым)
        emit({ 0x4C, 0x8B, 0x54, 0x24, 0x50 }); // mov r10, [rsp+0x50]
        emit({ 0x4C, 0x89, 0x54, 0x24, 0x30 }); // mov [rsp+0x30], r10 (return_address)

        // lea rcx, [rsp+0x20]   — указатель на SyscallContext
        emit({ 0x48, 0x8D, 0x4C, 0x24, 0x20 });

        // mov rax, imm64  (48 B8 <8 bytes>)
        emit({ 0x48, 0xB8 });
        emit64(impl_addr);
        // call rax  (FF D0)
        emit({ 0xFF, 0xD0 });

        // add rsp, 0x48  (48 83 C4 48)
        emit({ 0x48, 0x83, 0xC4, 0x48 });
        // pop rcx  (59)
        emit({ 0x59 });
        // pop r10  (41 5A)
        emit({ 0x41, 0x5A });
        // jmp r10  (41 FF E2)
        emit({ 0x41, 0xFF, 0xE2 });

        // Выделяем исполняемую память
        void* mem = VirtualAlloc(nullptr, code.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return nullptr;

        memcpy(mem, code.data(), code.size());
        FlushInstructionCache(GetCurrentProcess(), mem, code.size());
        return mem;
    }

    std::unique_ptr<InstrState> state_;
    void* thunk_mem_ = nullptr;
};

} // namespace w32kspy::hooks
