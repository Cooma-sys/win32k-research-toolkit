#pragma once

// =========================================================================
// Inline (Trampoline) Hook Engine — x64
// =========================================================================
// Как работает:
//   1. Читаем первые N байт целевой функции (>= 14 байт для abs jmp)
//   2. Создаём трамплин: скопированные байты + jmp обратно в оригинал+N
//   3. Патчим начало функции: FF 25 00000000 [абсолютный адрес хука]
//      (14-байтный абсолютный JMP через RIP-relative indirect)
//   4. При вызове оригинала — вызываем трамплин
//
// Для win32k:
//   win32u.dll содержит тонкие syscall stub'ы вида:
//       mov r10, rcx
//       mov eax, <syscall_number>
//       syscall
//       ret
//   Inline хук на эти stub'ы перехватывает ВСЕ вызовы NtUser*/NtGdi*
//   в любом процессе, даже если IAT уже не содержит прямой ссылки.
//
// ВАЖНО: Минимальная длина stub'а win32u = 14 байт → как раз хватает.
// =========================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <stdexcept>
#include <cstring>
#include <format>

namespace w32kspy::hooks {

// -----------------------------------------------------------------------
// x64 абсолютный JMP через memory indirect (14 байт)
//   FF 25 00 00 00 00       JMP QWORD PTR [RIP+0]
//   XX XX XX XX XX XX XX XX  <- 8-байтный адрес
// -----------------------------------------------------------------------
#pragma pack(push, 1)
struct AbsJmp64 {
    BYTE  opcode[6]  = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    void* target     = nullptr;
};
static_assert(sizeof(AbsJmp64) == 14);
#pragma pack(pop)

static constexpr size_t kJmpSize = sizeof(AbsJmp64);

// -----------------------------------------------------------------------
// Простой длиннологовый дизассемблер (только то что нужно нам)
// Возвращает длину инструкции начиная с p.
// Покрывает типичные win32u stub байты + пролог любой функции.
// Для production стоит заменить на Zydis/hde64.
// -----------------------------------------------------------------------
namespace detail {

// Минимальный length disassembler для x64
// Достаточен для типичных function prologue / syscall stub'ов
inline int InsnLen(const BYTE* p) {
    // REX prefix
    int off = 0;
    bool rex_w = false;
    if ((p[off] & 0xF0) == 0x40) { rex_w = (p[off] & 0x08) != 0; ++off; }

    BYTE op = p[off++];

    // 2-байтный префикс 0F
    if (op == 0x0F) {
        BYTE op2 = p[off++];
        // 0F 1F /r (NOP), 0F 84/85 Jcc rel32
        if (op2 == 0x1F) { BYTE modrm = p[off++]; if ((modrm >> 6) == 0x01) off += 1; else if ((modrm >> 6) == 0x02) off += 4; return off; }
        if (op2 == 0x84 || op2 == 0x85) return off + 4; // Jcc rel32
        if (op2 >= 0x90 && op2 <= 0x9F) return off; // SETcc
        return off; // остальные 0F xx — считаем 2 байта
    }

    // syscall (0F 05) — уже обработан выше через 0F
    // CALL rel32
    if (op == 0xE8) return off + 4;
    // JMP rel32
    if (op == 0xE9) return off + 4;
    // JMP rel8
    if (op == 0xEB) return off + 1;
    // RET
    if (op == 0xC3 || op == 0xC2) return off + (op == 0xC2 ? 2 : 0);
    // PUSH/POP reg (50-5F)
    if (op >= 0x50 && op <= 0x5F) return off;
    // MOV r/m64, imm32 (C7 /0) или MOV r64, imm64 (B8+r)
    if (op >= 0xB8 && op <= 0xBF) return off + (rex_w ? 8 : 4);
    if (op == 0xC7) { off++; return off + 4; } // /0 + imm32
    // MOV r10,rcx (49 8B D1) — типично в win32u stub
    if (op == 0x8B) { BYTE modrm = p[off++]; (void)modrm; return off; }
    // MOV eax, imm32 (B8) без REX
    // SUB/ADD rsp, imm8 (83 EC/C4 xx)
    if (op == 0x83) { off++; return off + 1; }
    // SUB rsp, imm32 (81 EC xx)
    if (op == 0x81) { off++; return off + 4; }
    // LEA r, [rip+disp32]
    if (op == 0x8D) { off++; return off + 4; }
    // FF /4 = JMP r/m64, FF /2 = CALL r/m64
    if (op == 0xFF) { off++; return off; }
    // NOP
    if (op == 0x90) return off;
    // XOR r,r (33 C0 etc)
    if (op == 0x33 || op == 0x31) { off++; return off; }
    // INT3
    if (op == 0xCC) return off;

    // Fallback — 1 байт (не идеально но не крашится)
    return off;
}

// Копируем минимум >= min_bytes байт, выравниваясь по инструкциям
// Возвращает реальное кол-во скопированных байт
inline size_t CopyInsns(const BYTE* src, BYTE* dst, size_t min_bytes) {
    size_t copied = 0;
    while (copied < min_bytes) {
        int len = InsnLen(src + copied);
        if (len <= 0) len = 1; // safety
        memcpy(dst + copied, src + copied, len);
        copied += len;
    }
    return copied;
}

} // namespace detail

// -----------------------------------------------------------------------
// Запись о хуке
// -----------------------------------------------------------------------
struct InlineHookEntry {
    std::string  func_name;
    void*        target_fn   = nullptr;  // адрес пропатченной функции
    void*        trampoline  = nullptr;  // исполняемый трамплин
    size_t       stolen_bytes = 0;
    BYTE         original_bytes[32]{};  // резервная копия
    bool         active = false;
};

// -----------------------------------------------------------------------
// Движок inline хуков
// -----------------------------------------------------------------------
class InlineHookEngine {
public:
    ~InlineHookEngine() { UninstallAll(); }

    // target_fn   — адрес функции для хука (GetProcAddress("win32u.dll","NtUserXxx"))
    // hook_fn     — наша функция
    // out_tramp   — [out] адрес трамплина для вызова оригинала
    bool Install(const char* func_name,
                 void* target_fn,
                 void* hook_fn,
                 void** out_tramp = nullptr)
    {
        if (!target_fn || !hook_fn) return false;

        // 1. Выделяем исполняемую память под трамплин
        //    stolen_bytes + abs jmp обратно = максимум 32 + 14 = 46 байт
        void* tramp_mem = VirtualAlloc(nullptr, 64,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp_mem) return false;

        // 2. Копируем украденные байты в трамплин
        auto* src = reinterpret_cast<BYTE*>(target_fn);
        auto* tramp = reinterpret_cast<BYTE*>(tramp_mem);

        size_t stolen = detail::CopyInsns(src, tramp, kJmpSize);

        // 3. В конец трамплина добавляем JMP обратно в target+stolen
        auto* jmp_back = reinterpret_cast<AbsJmp64*>(tramp + stolen);
        jmp_back->target = src + stolen;

        // Делаем трамплин исполняемым (уже EXECUTE_READWRITE, но flush icache)
        FlushInstructionCache(GetCurrentProcess(), tramp_mem, stolen + kJmpSize);

        // 4. Сохраняем оригинальные байты
        InlineHookEntry entry;
        entry.func_name    = func_name;
        entry.target_fn    = target_fn;
        entry.trampoline   = tramp_mem;
        entry.stolen_bytes = stolen;
        memcpy(entry.original_bytes, src, stolen);

        // 5. Патчим начало target_fn: ставим AbsJmp64 на hook_fn
        DWORD old_prot{};
        if (!VirtualProtect(target_fn, kJmpSize, PAGE_EXECUTE_READWRITE, &old_prot)) {
            VirtualFree(tramp_mem, 0, MEM_RELEASE);
            return false;
        }

        auto* jmp = reinterpret_cast<AbsJmp64*>(target_fn);
        jmp->target = hook_fn;
        memcpy(jmp, jmp, sizeof(AbsJmp64)); // убеждаемся что memcpy не оптимизируется
        // Правильно:
        AbsJmp64 patch;
        patch.target = hook_fn;
        memcpy(target_fn, &patch, sizeof(patch));

        VirtualProtect(target_fn, kJmpSize, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), target_fn, kJmpSize);

        entry.active = true;
        if (out_tramp) *out_tramp = tramp_mem;

        std::lock_guard lock(mtx_);
        hooks_[func_name] = entry;
        return true;
    }

    bool Uninstall(const char* func_name) {
        std::lock_guard lock(mtx_);
        auto it = hooks_.find(func_name);
        if (it == hooks_.end() || !it->second.active) return false;

        auto& e = it->second;
        DWORD old_prot{};
        VirtualProtect(e.target_fn, e.stolen_bytes, PAGE_EXECUTE_READWRITE, &old_prot);
        memcpy(e.target_fn, e.original_bytes, e.stolen_bytes);
        VirtualProtect(e.target_fn, e.stolen_bytes, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), e.target_fn, e.stolen_bytes);

        VirtualFree(e.trampoline, 0, MEM_RELEASE);
        e.active = false;
        return true;
    }

    void UninstallAll() {
        std::lock_guard lock(mtx_);
        for (auto& [name, e] : hooks_) {
            if (!e.active) continue;
            DWORD old_prot{};
            VirtualProtect(e.target_fn, e.stolen_bytes, PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy(e.target_fn, e.original_bytes, e.stolen_bytes);
            VirtualProtect(e.target_fn, e.stolen_bytes, old_prot, &old_prot);
            FlushInstructionCache(GetCurrentProcess(), e.target_fn, e.stolen_bytes);
            VirtualFree(e.trampoline, 0, MEM_RELEASE);
            e.active = false;
        }
    }

    // Хелпер: хукаем экспорт конкретной DLL по имени
    bool HookExport(const wchar_t* dll_name,
                    const char* func_name,
                    void* hook_fn,
                    void** out_tramp = nullptr)
    {
        HMODULE mod = GetModuleHandleW(dll_name);
        if (!mod) mod = LoadLibraryW(dll_name);
        if (!mod) return false;

        void* fn = GetProcAddress(mod, func_name);
        if (!fn) return false;

        return Install(func_name, fn, hook_fn, out_tramp);
    }

    [[nodiscard]] void* GetTrampoline(const char* func_name) const {
        std::lock_guard lock(mtx_);
        auto it = hooks_.find(func_name);
        if (it != hooks_.end() && it->second.active)
            return it->second.trampoline;
        return nullptr;
    }

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, InlineHookEntry> hooks_;
};

} // namespace w32kspy::hooks
