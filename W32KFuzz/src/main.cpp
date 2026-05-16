#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <format>
#include <filesystem>

#include "config/probe_loader.hpp"
#include "mutator/smart_mutator.hpp"
#include "caller/syscall_stub.hpp"
#include "monitor/spy_bridge.hpp"
#include "verdict/classifier.hpp"

using namespace w32kfuzz;
namespace fs = std::filesystem;

// -----------------------------------------------------------------------
// Цвета для консоли
// -----------------------------------------------------------------------
static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
static void ResetColor() { SetColor(7); }

static void PrintVerdict(const VerdictResult& v) {
    switch (v.verdict) {
        case Verdict::ConfirmedWrite:
        case Verdict::ConfirmedCorruption:
        case Verdict::ConfirmedCrash:
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            break;
        case Verdict::Suspicious:
        case Verdict::UnexpectedStatus:
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            break;
        default:
            SetColor(8); // grey
    }
    std::cout << "  " << Classifier::VerdictIcon(v.verdict)
              << "  " << v.test_case_desc << "\n";
    if (v.verdict != Verdict::FalsePositive)
        std::cout << "         " << v.description << "\n";
    ResetColor();
}

// -----------------------------------------------------------------------
// Banner
// -----------------------------------------------------------------------
static void PrintBanner() {
    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "\n";
    std::cout << "  ██╗    ██╗██████╗ ██████╗ ██╗  ██╗███████╗██╗   ██╗███████╗███████╗\n";
    std::cout << "  ██║    ██║╚════██╗╚════██╗██║ ██╔╝██╔════╝██║   ██║╚════███║╚════  |\n";
    std::cout << "  ██║ █╗ ██║ █████╔╝ █████╔╝█████╔╝ █████╗  ██║   ██║    ███╔╝    █  |\n";
    std::cout << "  ██║███╗██║ ╚═══██╗██╔═══╝ ██╔═██╗ ██╔══╝  ██║   ██║   ███╔╝    █  |\n";
    std::cout << "  ╚███╔███╔╝██████╔╝███████╗██║  ██╗██║     ╚██████╔╝  ███████╗  █  |\n";
    std::cout << "   ╚══╝╚══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝   ╚══════╝  ╚═╝\n";
    ResetColor();
    std::cout << "  Targeted win32k Syscall Verifier  |  v1.0  |  Win11\n\n";
}

// -----------------------------------------------------------------------
// Запуск одного probe файла
// -----------------------------------------------------------------------
static int RunProbe(const std::string& probe_path) {
    ProbeConfig cfg;
    try {
        cfg = ProbeLoader::Load(probe_path);
    } catch (const std::exception& e) {
        std::cerr << "[!] Failed to load probe: " << e.what() << "\n";
        return 1;
    }

    SetColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "\n[*] Probe: " << cfg.name << "\n";
    ResetColor();
    std::cout << "    Syscall : 0x" << std::hex << cfg.syscall_id
              << std::dec << "\n";
    std::cout << "    Platform: " << cfg.platform << "\n";
    if (!cfg.description.empty())
        std::cout << "    Desc    : " << cfg.description << "\n";
    if (!cfg.cve_ref.empty())
        std::cout << "    Ref     : " << cfg.cve_ref << "\n";
    std::cout << "\n";

    // Генерируем тест-кейсы
    SmartMutator    mutator;
    SyscallRegistry registry;
    SpyBridge       bridge;
    Classifier      classifier;

    auto& stub = registry.Get(cfg.syscall_id);
    if (!stub.valid()) {
        std::cerr << "[!] Failed to build syscall stub for 0x"
                  << std::hex << cfg.syscall_id << "\n";
        return 1;
    }

    auto cases = mutator.Generate(cfg);
    std::cout << "    Generated " << cases.size() << " test cases\n\n";

    int confirmed = 0;
    int suspicious = 0;

    for (auto& tc : cases) {
        bridge.Begin();
        auto call_result = stub.Call(tc.args);
        auto mon_result  = bridge.End();

        auto verdict = classifier.Classify(cfg, tc.description,
                                            call_result, mon_result);
        PrintVerdict(verdict);

        if (verdict.verdict == Verdict::ConfirmedWrite   ||
            verdict.verdict == Verdict::ConfirmedCrash   ||
            verdict.verdict == Verdict::ConfirmedCorruption)
            ++confirmed;
        else if (verdict.verdict == Verdict::Suspicious  ||
                 verdict.verdict == Verdict::UnexpectedStatus)
            ++suspicious;

        // Пауза если нашли — дать время юзеру увидеть
        if (verdict.is_interesting())
            Sleep(50);
    }

    std::cout << "\n";
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    if (confirmed > 0)
        std::cout << "  [!!!] CONFIRMED: " << confirmed << " case(s)\n";
    ResetColor();
    if (suspicious > 0) {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [ ! ] Suspicious: " << suspicious << " case(s)\n";
        ResetColor();
    }
    if (confirmed == 0 && suspicious == 0) {
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [   ] No anomalies found\n";
        ResetColor();
    }

    return 0;
}

// -----------------------------------------------------------------------
// Usage
// -----------------------------------------------------------------------
static void Usage(const char* exe) {
    std::cout << "\nUsage:\n";
    std::cout << "  " << exe << " <probe.yml>         -- run single probe\n";
    std::cout << "  " << exe << " --dir <probes_dir>  -- run all probes\n";
    std::cout << "  " << exe << " --list <probes_dir> -- list available probes\n\n";
    std::cout << "Examples:\n";
    std::cout << "  W32KFuzz.exe probes\\NtUserTransformPoint.yml\n";
    std::cout << "  W32KFuzz.exe --dir probes\\\n\n";
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    PrintBanner();

    if (argc < 2) {
        Usage(argv[0]);
        return 1;
    }

    std::string arg1 = argv[1];

    // -- list mode
    if (arg1 == "--list" && argc >= 3) {
        auto probes = ProbeLoader::LoadDir(argv[2]);
        std::cout << "Available probes in " << argv[2] << ":\n\n";
        for (auto& p : probes) {
            std::cout << "  [0x" << std::hex << p.syscall_id << std::dec
                      << "] " << p.name;
            if (!p.cve_ref.empty())
                std::cout << "  (" << p.cve_ref << ")";
            std::cout << "\n";
        }
        return 0;
    }

    // -- dir mode
    if (arg1 == "--dir" && argc >= 3) {
        auto probes = ProbeLoader::LoadDir(argv[2]);
        if (probes.empty()) {
            std::cerr << "[!] No probe files found in " << argv[2] << "\n";
            return 1;
        }
        std::cout << "Running " << probes.size() << " probe(s)...\n";
        int total_confirmed = 0;
        for (auto& p : probes) {
            // Пересоздаём runner для каждого probe
            SmartMutator    mutator;
            SyscallRegistry registry;
            SpyBridge       bridge;
            Classifier      classifier;

            SetColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "\n[*] " << p.name
                      << " (0x" << std::hex << p.syscall_id
                      << std::dec << ")\n";
            ResetColor();

            auto& stub  = registry.Get(p.syscall_id);
            auto  cases = mutator.Generate(p);
            for (auto& tc : cases) {
                bridge.Begin();
                auto cr = stub.Call(tc.args);
                auto mr = bridge.End();
                auto vr = classifier.Classify(p, tc.description, cr, mr);
                if (vr.is_interesting()) {
                    PrintVerdict(vr);
                    if (vr.verdict == Verdict::ConfirmedWrite   ||
                        vr.verdict == Verdict::ConfirmedCrash   ||
                        vr.verdict == Verdict::ConfirmedCorruption)
                        ++total_confirmed;
                }
            }
        }
        std::cout << "\n";
        if (total_confirmed > 0) {
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "  [!!!] Total confirmed: " << total_confirmed << "\n";
            ResetColor();
        }
        return 0;
    }

    // -- single probe mode
    return RunProbe(arg1);
}
