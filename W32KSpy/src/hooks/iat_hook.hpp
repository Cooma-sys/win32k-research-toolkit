#pragma once

// =========================================================================
// IAT Hook Engine
// =========================================================================
// Как работает:
//   1. Парсим PE заголовок целевого модуля (обычно текущий процесс)
//   2. Ищем Import Directory → нужную DLL → нужную функцию
//   3. Снимаем PAGE_READONLY с IAT страницы через VirtualProtect
//   4. Заменяем указатель на наш хук
//   5. При unhook восстанавливаем оригинал
//
// Применение для win32k:
//   Процессы вызывают NtUser*/NtGdi* через win32u.dll (Win8.1+)
//   или напрямую через ntdll.dll syscall stub'ы.
//   IAT хук на win32u.dll перехватит все вызовы конкретной функции
//   в ДАННОМ процессе с полными аргументами.
// =========================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <format>

namespace w32kspy::hooks {

// -----------------------------------------------------------------------
// Одна запись о хуке
// -----------------------------------------------------------------------
struct IatHookEntry {
    std::string  module_name;   // "win32u.dll"
    std::string  func_name;     // "NtUserSendMessage"
    void**       iat_slot;      // указатель на слот в таблице IAT
    void*        original_fn;   // оригинальная функция
    void*        hook_fn;       // наша замена
    bool         active{ false };
};

// -----------------------------------------------------------------------
// Вспомогательные функции разбора PE
// -----------------------------------------------------------------------
namespace detail {

inline PIMAGE_NT_HEADERS NtHeaders(HMODULE mod) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

// Ищем слот IAT для конкретной DLL + функции в модуле target_mod
// Возвращает указатель на IAT slot или nullptr
inline void** FindIatSlot(HMODULE target_mod,
                           const char* import_dll,
                           const char* func_name)
{
    auto* nt = NtHeaders(target_mod);
    if (!nt) return nullptr;

    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0) return nullptr;

    auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(target_mod) + import_dir.VirtualAddress);

    for (; desc->Name != 0; ++desc) {
        const char* dll_name = reinterpret_cast<const char*>(
            reinterpret_cast<BYTE*>(target_mod) + desc->Name);

        if (_stricmp(dll_name, import_dll) != 0) continue;

        // Нашли нужную DLL
        auto* thunk_orig = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(target_mod) + desc->OriginalFirstThunk);
        auto* thunk_iat = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(target_mod) + desc->FirstThunk);

        for (; thunk_orig->u1.AddressOfData != 0; ++thunk_orig, ++thunk_iat) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal)) continue;

            auto* import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                reinterpret_cast<BYTE*>(target_mod) +
                thunk_orig->u1.AddressOfData);

            if (_stricmp(import_by_name->Name, func_name) == 0) {
                return reinterpret_cast<void**>(&thunk_iat->u1.Function);
            }
        }
    }
    return nullptr;
}

// Патчим память IAT (снимаем защиту, пишем, восстанавливаем)
inline bool PatchPtr(void** slot, void* new_val) {
    DWORD old_protect{};
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old_protect))
        return false;
    *slot = new_val;
    VirtualProtect(slot, sizeof(void*), old_protect, &old_protect);
    return true;
}

} // namespace detail

// -----------------------------------------------------------------------
// Главный движок IAT хуков
// -----------------------------------------------------------------------
class IatHookEngine {
public:
    // Ставим хук:
    //   target_mod   — модуль в котором патчим IAT (nullptr = текущий .exe)
    //   import_dll   — "win32u.dll" или "ntdll.dll"
    //   func_name    — "NtUserSendMessage"
    //   hook_fn      — наша функция-замена
    //   out_original — [out] оригинальный указатель (для вызова из хука)
    bool Install(HMODULE target_mod,
                 const char* import_dll,
                 const char* func_name,
                 void* hook_fn,
                 void** out_original = nullptr)
    {
        if (!target_mod)
            target_mod = GetModuleHandleW(nullptr); // текущий EXE

        void** slot = detail::FindIatSlot(target_mod, import_dll, func_name);
        if (!slot) return false;

        IatHookEntry entry;
        entry.module_name = import_dll;
        entry.func_name   = func_name;
        entry.iat_slot    = slot;
        entry.original_fn = *slot;
        entry.hook_fn     = hook_fn;

        if (!detail::PatchPtr(slot, hook_fn)) return false;

        entry.active = true;
        if (out_original) *out_original = entry.original_fn;

        std::lock_guard lock(mtx_);
        std::string key = std::string(import_dll) + "!" + func_name;
        hooks_[key] = entry;
        return true;
    }

    // Снимаем хук
    bool Uninstall(const char* import_dll, const char* func_name) {
        std::string key = std::string(import_dll) + "!" + func_name;
        std::lock_guard lock(mtx_);
        auto it = hooks_.find(key);
        if (it == hooks_.end() || !it->second.active) return false;

        auto& e = it->second;
        detail::PatchPtr(e.iat_slot, e.original_fn);
        e.active = false;
        return true;
    }

    void UninstallAll() {
        std::lock_guard lock(mtx_);
        for (auto& [key, e] : hooks_) {
            if (e.active) {
                detail::PatchPtr(e.iat_slot, e.original_fn);
                e.active = false;
            }
        }
    }

    ~IatHookEngine() { UninstallAll(); }

    [[nodiscard]] size_t HookCount() const {
        std::lock_guard lock(mtx_);
        size_t n = 0;
        for (auto& [k, e] : hooks_) if (e.active) ++n;
        return n;
    }

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, IatHookEntry> hooks_;
};

} // namespace w32kspy::hooks
