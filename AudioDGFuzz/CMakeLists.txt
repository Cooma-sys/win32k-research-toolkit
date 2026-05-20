cmake_minimum_required(VERSION 3.20)
project(AudioDGFuzz VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Sources ───────────────────────────────────────────────────────────────
add_executable(AudioDGFuzz
    src/main.cpp
    src/config/probe_loader.hpp
    src/config/probe_loader.cpp
    src/com/wasapi_client.hpp
    src/com/wasapi_client.cpp
    src/com/apo_harness.hpp
    src/com/apo_harness.cpp
    src/mutator/format_mutator.hpp
    src/mutator/format_mutator.cpp
    src/mutator/pcm_mutator.hpp
    src/mutator/pcm_mutator.cpp
    src/monitor/audiodg_monitor.hpp
    src/monitor/audiodg_monitor.cpp
    src/verdict/classifier.hpp
    src/verdict/classifier.cpp
)

# ── Include dirs ──────────────────────────────────────────────────────────
target_include_directories(AudioDGFuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ── Link (Windows SDK audio / COM libraries) ─────────────────────────────
target_link_libraries(AudioDGFuzz PRIVATE
    ole32.lib
    oleaut32.lib
    mmdevapi.lib
    avrt.lib
    uuid.lib
)

# ── Definitions ───────────────────────────────────────────────────────────
target_compile_definitions(AudioDGFuzz PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _AMD64_
)

# ── Compile options (MSVC) ────────────────────────────────────────────────
if(MSVC)
    target_compile_options(AudioDGFuzz PRIVATE
        /W4             # high warning level
        /WX-            # don't treat warnings as errors (undoc APIs used)
        /MP             # parallel compilation
        /Zi             # full debug symbols
        /permissive-    # strict C++20 mode
        /EHa            # async SEH exceptions (__try/__except needed for AV safety)
    )

    # Release — optimization + symbols
    target_compile_options(AudioDGFuzz PRIVATE
        $<$<CONFIG:Release>:/O2 /Ob2 /DNDEBUG>
    )

    # Linker: requireAdministrator + /DEBUG for symbols
    set_target_properties(AudioDGFuzz PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /DEBUG"
    )
endif()

# ── Post-build: confirm build completed ──────────────────────────────────
if(MSVC)
    add_custom_command(TARGET AudioDGFuzz POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "[AudioDGFuzz] Build complete: $<TARGET_FILE:AudioDGFuzz>"
    )
endif()
