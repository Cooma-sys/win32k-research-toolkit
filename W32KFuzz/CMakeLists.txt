cmake_minimum_required(VERSION 3.20)
project(W32KFuzz VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(W32KFuzz
    src/main.cpp
    src/config/probe_loader.hpp
    src/mutator/smart_mutator.hpp
    src/caller/syscall_stub.hpp
    src/monitor/spy_bridge.hpp
    src/verdict/classifier.hpp
)

target_include_directories(W32KFuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(W32KFuzz PRIVATE
    tdh.lib
    ntdll.lib
    advapi32.lib
)

target_compile_definitions(W32KFuzz PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _AMD64_
)

if(MSVC)
    target_compile_options(W32KFuzz PRIVATE
        /W4 /WX- /MP /Zi /permissive-
        $<$<CONFIG:Release>:/O2 /DNDEBUG>
    )
    set_target_properties(W32KFuzz PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /DEBUG"
    )
endif()
