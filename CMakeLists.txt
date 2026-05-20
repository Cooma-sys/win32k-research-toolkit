cmake_minimum_required(VERSION 3.20)
project(W32KSpy VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── FTXUI ─────────────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG        v5.0.0
)
FetchContent_MakeAvailable(ftxui)

# ── Sources ───────────────────────────────────────────────────────────────
add_executable(W32KSpy
    src/main.cpp
    # Header-only modules — перечислены для IDE/intellisense
    src/etw/etw_session.hpp
    src/etw/etw_consumer.hpp
    src/filter/interest_filter.hpp
    src/hooks/iat_hook.hpp
    src/hooks/inline_hook.hpp
    src/hooks/instrumentation_cb.hpp
    src/hooks/syscall_monitor.hpp
    src/ui/tui.hpp
)

# ── Include dirs ──────────────────────────────────────────────────────────
target_include_directories(W32KSpy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ── Link ──────────────────────────────────────────────────────────────────
target_link_libraries(W32KSpy PRIVATE
    ftxui::screen
    ftxui::dom
    ftxui::component
    tdh.lib
    ntdll.lib
    advapi32.lib
    psapi.lib
    # win32u нам нужна только для GetProcAddress — не линкуем явно,
    # она подгружается через LoadLibrary в runtime
)

# ── Definitions ───────────────────────────────────────────────────────────
target_compile_definitions(W32KSpy PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    # Включаем полные заголовки ntdll
    _AMD64_
)

# ── Compile options (MSVC) ────────────────────────────────────────────────
if(MSVC)
    target_compile_options(W32KSpy PRIVATE
        /W4             # высокий уровень предупреждений
        /WX-            # не превращаем warnings в errors (для undoc API)
        /MP             # параллельная компиляция
        /Zi             # полные отладочные символы
        /GS-            # отключаем stack cookies (мешают naked-подобным трюкам)
        /permissive-    # строгий режим C++20
    )

    # Release — оптимизация + символы
    target_compile_options(W32KSpy PRIVATE
        $<$<CONFIG:Release>:/O2 /Ob2 /DNDEBUG>
    )

    # Linker: manifest с requireAdministrator + /DEBUG для символов
    set_target_properties(W32KSpy PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /DEBUG"
    )
endif()

# ── AudioDGFuzz ────────────────────────────────────────────────────────────
add_subdirectory(AudioDGFuzz)

# ── Post-build: копируем PDB рядом с EXE (удобно для WinDbg) ─────────────
if(MSVC)
    add_custom_command(TARGET W32KSpy POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "[W32KSpy] Build complete: $<TARGET_FILE:W32KSpy>"
    )
endif()
