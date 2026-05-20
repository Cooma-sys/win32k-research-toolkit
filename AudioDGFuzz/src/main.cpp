#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <format>
#include <filesystem>

#include "config/probe_loader.hpp"
#include "com/wasapi_client.hpp"
#include "com/apo_harness.hpp"
#include "mutator/format_mutator.hpp"
#include "mutator/pcm_mutator.hpp"
#include "monitor/audiodg_monitor.hpp"
#include "verdict/classifier.hpp"

using namespace audiodgfuzz;
namespace fs = std::filesystem;

// -----------------------------------------------------------------------
// Console color helpers
// -----------------------------------------------------------------------
static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
static void ResetColor() { SetColor(7); }

// -----------------------------------------------------------------------
// PrintVerdict — colored single-line result
// -----------------------------------------------------------------------
static void PrintVerdict(const VerdictResult& v) {
    switch (v.verdict) {
    case Verdict::AudiodgCrash:
    case Verdict::AccessViolation:
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        break;
    case Verdict::AudiodgRestart:
    case Verdict::Suspicious:
    case Verdict::UnexpectedHR:
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        break;
    default:
        SetColor(8); // grey
    }

    std::cout << "  " << Classifier::Icon(v.verdict)
              << "  " << v.test_case_desc << "\n";
    if (v.verdict != Verdict::Clean)
        std::cout << "         " << v.description << "\n";
    ResetColor();
}

// -----------------------------------------------------------------------
// Banner — green ASCII art
// -----------------------------------------------------------------------
static void PrintBanner() {
    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << R"(
     ██████╗ ███████╗██████╗  █████╗ ██╗   ██╗██╗      ██████╗ ███╗   ███╗
    ██╔═══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██║     ██╔═══██╗████╗ ████║
    ██║   ██║███████╗██████╔╝███████║██║   ██║██║     ██║   ██║██╔████╔██║
    ██║   ██║╚══███╔╝██╔═══╝ ██╔══██║██║   ██║██║     ██║   ██║██║╚██╔╝██║
    ╚██████╔╝███████╗██║     ██║  ██║╚██████╔╝██████╗╚██████╔╝██║ ╚═╝ ██║
     ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝
)" << "\n";
    ResetColor();
    std::cout << "  Windows AudioDG Rendering Pipeline Fuzzer  |  v1.0  |  Win11 24H2\n\n";
}

// -----------------------------------------------------------------------
// Run a WASAPI-type probe (IAudioClient / IAudioRenderClient)
// -----------------------------------------------------------------------
static int RunWasapiProbe(const ProbeConfig& cfg) {
    WasapiClient     client;
    FormatMutator    fmt_mutator;
    PcmMutator       pcm_mutator;
    AudiodgMonitor   monitor;
    Classifier       classifier;

    if (!client.Init()) {
        std::cerr << "[!] Failed to initialize WASAPI client\n";
        return 1;
    }

    // Find format param spec and generate format mutations
    std::vector<FormatTestCase> fmt_cases;

    // Build base args from fixed params, then apply mutations
    WasapiCallArgs base_args;
    base_args.share_mode = AUDCLNT_SHAREMODE_SHARED;

    for (const auto& param : cfg.params) {
        if (param.type == "WAVEFORMATEX") {
            fmt_cases = fmt_mutator.Generate(param);
            if (!fmt_cases.empty())
                base_args.format = std::make_unique<WAVEFORMATEXTENSIBLE>(fmt_cases[0].fmt);
        }
    }

    bool is_init   = (cfg.method == "Initialize");
    bool is_buffer = (cfg.method == "GetBuffer");
    bool is_format = (cfg.method == "IsFormatSupported");

    int confirmed   = 0;
    int suspicious  = 0;
    int total_tests = 0;

    // --- IAudioClient::Initialize path ---
    if (is_init) {
        static const REFERENCE_TIME kPeriods[] = {
            0,                              // BoundaryZero
            1,                              // BoundaryMin
            10000,                          // ~1ms (reasonable min)
            3000000,                        // 300ms (typical default)
            MAXLONGLONG,                    // BoundaryMax
            static_cast<REFERENCE_TIME>(-1), // NegativeValue
        };

        size_t period_idx = 0;
        for (const auto& fmt_tc : fmt_cases) {
            WasapiCallArgs args = base_args;
            args.format = std::make_unique<WAVEFORMATEXTENSIBLE>(fmt_tc.fmt);
            args.description = fmt_tc.description;
            args.buffer_duration = kPeriods[period_idx % std::size(kPeriods)];
            ++period_idx;

            monitor.Begin();
            CallResult cr{};
            cr = client.TestInitialize(args);

            bool crashed   = monitor.DetectedCrash();
            bool restarted = monitor.DetectedRestart();

            auto vr = classifier.Classify(cfg, args.description, cr,
                                          crashed, restarted);
            PrintVerdict(vr);
            ++total_tests;

            if (vr.verdict == Verdict::AudiodgCrash ||
                vr.verdict == Verdict::AccessViolation)
                ++confirmed;
            else if (vr.is_interesting())
                ++suspicious;

            if (vr.is_interesting())
                Sleep(50);
        }
    }
    // --- GetBuffer/ReleaseBuffer path ---
    else if (is_buffer) {
        static const UINT32 kFrameVals[] = {0, 1, UINT32_MAX, 65535};

        for (auto fmt_tc : fmt_cases) {
            for (UINT32 req_frames : kFrameVals) {
                for (UINT32 write_frames : kFrameVals) {
                    WasapiCallArgs args = base_args;
                    args.format = std::make_unique<WAVEFORMATEXTENSIBLE>(fmt_tc.fmt);
                    args.num_frames_requested = req_frames;
                    args.num_frames_written = write_frames;
                    args.description = std::string("GetBuffer(") +
                        std::to_string(req_frames) + ")/ReleaseBuffer(" +
                        std::to_string(write_frames) + ") [" +
                        fmt_tc.description + "]";

                    monitor.Begin();
                    auto cr = client.TestBufferCycle(args);
                    bool crashed   = monitor.DetectedCrash();
                    bool restarted = monitor.DetectedRestart();

                    auto vr = classifier.Classify(cfg, args.description, cr,
                                                  crashed, restarted);
                    PrintVerdict(vr);
                    ++total_tests;

                    if (vr.verdict == Verdict::AudiodgCrash ||
                        vr.verdict == Verdict::AccessViolation)
                        ++confirmed;
                    else if (vr.is_interesting())
                        ++suspicious;

                    if (vr.is_interesting())
                        Sleep(50);
                }
            }
        }
    }
    // --- IsFormatSupported path ---
    else if (is_format) {
        for (const auto& fmt_tc : fmt_cases) {
            WasapiCallArgs args = base_args;
            args.description = fmt_tc.description;

            monitor.Begin();
            auto cr = client.TestFormatSupport(fmt_tc.fmt);
            bool crashed   = monitor.DetectedCrash();
            bool restarted = monitor.DetectedRestart();

            auto vr = classifier.Classify(cfg, args.description, cr,
                                          crashed, restarted);
            PrintVerdict(vr);
            ++total_tests;

            if (vr.verdict == Verdict::AudiodgCrash ||
                vr.verdict == Verdict::AccessViolation)
                ++confirmed;
            else if (vr.is_interesting())
                ++suspicious;

            if (vr.is_interesting())
                Sleep(50);
        }
    }

    client.Shutdown();

    // Summary
    std::cout << "\n";
    if (confirmed > 0) {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "  [!!!] CONFIRMED: " << confirmed << " anomaly(s)\n";
        ResetColor();
    }
    if (suspicious > 0) {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [ ! ] Suspicious: " << suspicious << " finding(s)\n";
        ResetColor();
    }
    if (confirmed == 0 && suspicious == 0) {
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [   ] No anomalies found in " << total_tests << " tests\n";
        ResetColor();
    }

    return 0;
}

// -----------------------------------------------------------------------
// Run an APO-type probe (direct APO loading + APOProcess)
// -----------------------------------------------------------------------
static int RunApoProbe(const ProbeConfig& cfg) {
    ApoHarness       apo;
    FormatMutator    fmt_mutator;
    PcmMutator       pcm_mutator;
    AudiodgMonitor   monitor;
    Classifier       classifier;

    HRESULT hr_com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr_com) && hr_com != RPC_E_CHANGED_MODE) {
        std::cerr << "[!] COM init failed for APO harness: 0x"
                  << std::hex << hr_com << std::dec << "\n";
        return 1;
    }

    // Try known system APO CLSIDs
    static const wchar_t* kKnownApoClsids[] = {
        L"{F8512E00-1207-11CF-A796-0004AC9B0028}",  // Microsoft AEC APO
        L"{636A25B7-6F06-4FC0-88AE-CDAA14D1738F}",  // AudioLFX
        nullptr
    };

    bool loaded = false;
    for (const wchar_t** clsid = &kKnownApoClsids[0]; *clsid; ++clsid) {
        if (apo.LoadByClsid(*clsid)) {
            loaded = true;
            std::wcerr << L"[apo] Loaded APO with CLSID: " << *clsid << L"\n";
            break;
        }
    }

    if (!loaded) {
        std::cerr << "[!] No suitable APO found on this system\n";
        CoUninitialize();
        return 1;
    }

    WAVEFORMATEXTENSIBLE base_fmt{};
    base_fmt.Format.wFormatTag      = WAVE_FORMAT_EXTENSIBLE;
    base_fmt.Format.nChannels       = 2;
    base_fmt.Format.nSamplesPerSec  = 48000;
    base_fmt.Format.wBitsPerSample  = 32;
    base_fmt.Format.nBlockAlign     = 8;
    base_fmt.Format.nAvgBytesPerSec= 384000;
    base_fmt.Format.cbSize          = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    base_fmt.dwChannelMask          = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
    base_fmt.SubFormat              = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;

    std::vector<FormatTestCase> fmt_cases;
    for (const auto& param : cfg.params) {
        if (param.type == "WAVEFORMATEX")
            fmt_cases = fmt_mutator.Generate(param);
    }
    if (fmt_cases.empty())
        fmt_cases.push_back({"default", base_fmt});

    int confirmed   = 0;
    int suspicious  = 0;
    int total_tests = 0;
    UINT32 num_frames = 256;

    for (const auto& fmt_tc : fmt_cases) {
        hr_com = apo.Initialize(fmt_tc.fmt);

        auto pcm_cases = pcm_mutator.Generate(num_frames, fmt_tc.fmt);

        for (const auto& pcm_tc : pcm_cases) {
            monitor.Begin();

            ApoCallResult apo_result = apo.Process(
                pcm_tc.data, num_frames, fmt_tc.fmt);

            CallResult call{};
            call.hr = apo_result.hr_process;
            call.audiodg_alive = true; // APO is in-process, not audiodg
            call.error_detail = apo_result.returned_normally
                ? ("APOProcess HR=0x" + ([&]() -> std::string {
                      std::ostringstream ss; ss << std::hex << apo_result.hr_process;
                      return ss.str(); })())
                : apo_result.exception_info;

            bool crashed   = monitor.DetectedCrash();
            bool restarted = monitor.DetectedRestart();

            if (!apo_result.returned_normally)
                call.audiodg_alive = false;

            auto vr = classifier.Classify(cfg,
                fmt_tc.description + " | " + pcm_tc.description,
                call, crashed, restarted);

            if (!apo_result.returned_normally && vr.verdict == Verdict::Clean) {
                vr.verdict = Verdict::AccessViolation;
                vr.description = "In-process SEH during APOProcess: " +
                    apo_result.exception_info;
            }

            PrintVerdict(vr);
            ++total_tests;

            if (vr.verdict == Verdict::AudiodgCrash ||
                vr.verdict == Verdict::AccessViolation)
                ++confirmed;
            else if (vr.is_interesting())
                ++suspicious;

            if (vr.is_interesting())
                Sleep(50);
        }
    }

    apo.Unload();
    CoUninitialize();

    std::cout << "\n";
    if (confirmed > 0) {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "  [!!!] CONFIRMED: " << confirmed << " anomaly(s)\n";
        ResetColor();
    }
    if (suspicious > 0) {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [ ! ] Suspicious: " << suspicious << " finding(s)\n";
        ResetColor();
    }
    if (confirmed == 0 && suspicious == 0) {
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [   ] No anomalies found in " << total_tests << " tests\n";
        ResetColor();
    }

    return 0;
}

// -----------------------------------------------------------------------
// Run a single probe file — dispatch by ApiType
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
    std::cout << "    API       : " << (cfg.api == ApiType::APO ? "APO" : "WASAPI")
              << "\n";
    std::cout << "    Interface : " << cfg.interface_name
              << "::" << cfg.method << "\n";
    std::cout << "    Platform  : " << cfg.platform << "\n";
    if (!cfg.description.empty())
        std::cout << "    Desc      : " << cfg.description << "\n";
    std::cout << "\n";

    switch (cfg.api) {
    case ApiType::WASAPI: return RunWasapiProbe(cfg);
    case ApiType::APO:    return RunApoProbe(cfg);
    default:
        std::cerr << "[!] Unknown API type\n";
        return 1;
    }
}

// -----------------------------------------------------------------------
// Usage
// -----------------------------------------------------------------------
static void Usage(const char* exe) {
    std::cout << "\nUsage:\n";
    std::cout << "  " << exe << " <probe.yml>         -- run single probe\n";
    std::cout << "  " << exe << " --dir <probes_dir>  -- run all probes in directory\n";
    std::cout << "  " << exe << " --list <probes_dir> -- list available probes\n\n";
    std::cout << "Examples:\n";
    std::cout << "  AudioDGFuzz.exe probes\\IAudioClient_init.yml\n";
    std::cout << "  AudioDGFuzz.exe --dir probes\\\n";
    std::cout << "  AudioDGFuzz.exe --list probes\\\n\n";
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

    // --list mode
    if (arg1 == "--list" && argc >= 3) {
        auto probes = ProbeLoader::LoadDir(argv[2]);
        std::cout << "Available probes in " << argv[2] << ":\n\n";
        for (auto& p : probes) {
            std::cout << "  [" << (p.api == ApiType::APO ? "APO" : "WASAPI")
                      << "] " << p.interface_name << "::" << p.method
                      << "  \u2014 " << p.name << "\n";
        }
        return 0;
    }

    // --dir mode: enumerate .yml files and run each
    if (arg1 == "--dir" && argc >= 3) {
        std::string dir_path = argv[2];
        std::string pattern = dir_path + "\\*.yml";
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] No probe files found in " << dir_path << "\n";
            return 1;
        }

        std::vector<std::string> files;
        do { files.push_back(dir_path + "\\" + fd.cFileName); }
        while (FindNextFileA(h, &fd));
        FindClose(h);

        std::cout << "Running " << files.size() << " probe(s)...\n";
        for (auto& f : files) {
            SetColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "\n[*] Running: " << f << "\n";
            ResetColor();
            RunProbe(f); // each probe prints its own summary
        }

        return 0;
    }

    // Single probe mode
    return RunProbe(arg1);
}
