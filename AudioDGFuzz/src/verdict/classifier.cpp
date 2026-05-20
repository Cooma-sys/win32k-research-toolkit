#include "verdict/classifier.hpp"

#include <algorithm>
#include <sstream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// is_interesting — anything that's not Clean is worth reporting
// -----------------------------------------------------------------------
bool VerdictResult::is_interesting() const {
    return verdict != Verdict::Clean;
}

// -----------------------------------------------------------------------
// Icon — single-character verdict indicator for terminal output
// -----------------------------------------------------------------------
std::string VerdictResult::Icon(Verdict v) {
    switch (v) {
    case Verdict::Clean:           return "✓";
    case Verdict::UnexpectedHR:    return "?";
    case Verdict::AccessViolation: return "⚡";
    case Verdict::AudiodgCrash:    return "💥";
    case Verdict::AudiodgRestart:  return "🔄";
    case Verdict::Suspicious:      return "⚠";
    default:                       return " ";
    }
}

// -----------------------------------------------------------------------
// IsExpectedHresult — check if HRESULT (or its string name) is in expect list
// -----------------------------------------------------------------------
bool Classifier::IsExpectedHresult(ProbeConfig cfg, HRESULT hr) {
    // Build string representations of common HRESULTs to match against
    auto hr_to_name = [](HRESULT h) -> std::string {
        switch (h) {
        case S_OK:      return "S_OK";
        case S_FALSE:   return "S_FALSE";
        case E_POINTER: return "E_POINTER";
        case E_INVALIDARG: return "E_INVALIDARG";
        case E_FAIL:    return "E_FAIL";
        case E_UNEXPECTED: return "E_UNEXPECTED";
        case 0x80070057: return "E_INVALIDARG"; // alias
        default:
            if (HRESULT_FACILITY(hr) == FACILITY_AUDCLNT) {
                // AUDCLNT errors
                switch (hr) {
                case 0x88890001: return "AUDCLNT_E_NOT_INITIALIZED";
                case 0x88890002: return "AUDCLNT_E_ALREADY_INITIALIZED";
                case 0x88890003: return "AUDCLNT_E_WRONG_ENDPOINT_TYPE";
                case 0x88890004: return "AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED";
                case 0x88890005: return "AUDCLNT_E_BUFFER_SIZE_ERROR";
                case 0x88890006: return "AUDCLNT_E_CPUUSAGE_EXCEEDED";
                case 0x88890007: return "AUDCLNT_E_EVENTHANDLE_NOT_SET";
                case 0x88890008: return "AUDCLNT_E_DEVICE_INVALIDATED";
                case 0x88890009: return "AUDCLNT_E_SERVICE_NOT_RUNNING";
                case 0x8889000A: return "AUDCLNT_E_UNSUPPORTED_FORMAT";
                default:
                    std::ostringstream ss;
                    ss << "0x" << std::hex << hr;
                    return ss.str();
                }
            }
            // Generic unexpected
            std::ostringstream ss;
            ss << "0x" << std::hex << hr;
            return ss.str();
        }
    };

    std::string name = hr_to_name(hr);
    for (const auto& expected : cfg.expect) {
        if (expected == name || expected == "unexpected_hresult" ||
            expected == "process_crash" || expected == "access_violation")
            return true; // these are catch-all categories
        if (expected.find("0x") == 0 && name == expected)
            return true;
    }

    return false;
}

// -----------------------------------------------------------------------
// Classify — main classification logic
// -----------------------------------------------------------------------
VerdictResult Classifier::Classify(const ProbeConfig& cfg,
                                    const std::string& test_desc,
                                    const CallResult& call,
                                    bool audiodg_crashed,
                                    bool audiodg_restarted) {
    VerdictResult result{};
    result.hr = call.hr;
    result.test_case_desc = test_desc;

    // Highest priority: crash detection
    if (audiodg_crashed) {
        result.verdict = Verdict::AudiodgCrash;
        result.description = "audiodg.exe crashed! HR=0x" +
            ([&]() -> std::string {
                std::ostringstream ss; ss << std::hex << call.hr; return ss.str();
            })() +
            " Detail=" + call.error_detail;
        return result;
    }

    // Restart detection (possible panic recovery)
    if (audiodg_restarted) {
        result.verdict = Verdict::AudiodgRestart;
        result.description = "audiodg.exe was force-restarted. HR=0x" +
            ([&]() -> std::string {
                std::ostringstream ss; ss << std::hex << call.hr; return ss.str();
            })();
        return result;
    }

    // SEH exception caught during call (access violation in our process)
    if (!call.audiodg_alive && FAILED(call.hr)) {
        // Check error detail for SEH indicators
        if (call.error_detail.find("SEH") != std::string::npos ||
            call.error_detail.find("exception") != std::string::npos ||
            call.hr == E_UNEXPECTED) {
            result.verdict = Verdict::AccessViolation;
            result.description = call.error_detail;
            return result;
        }
    }

    // Check if HRESULT is expected
    if (FAILED(call.hr)) {
        if (IsExpectedHresult(cfg, call.hr)) {
            result.verdict = Verdict::Clean;
            result.description = "Expected failure: " + call.error_detail;
        } else {
            result.verdict = Verdict::UnexpectedHR;
            result.description = "Unexpected HRESULT: " + call.error_detail;
        }
        return result;
    }

    // Success when we expected a failure — suspicious
    if (SUCCEEDED(call.hr)) {
        bool expects_success = false;
        for (const auto& e : cfg.expect) {
            if (e == "S_OK" || e == "S_FALSE") { expects_success = true; break; }
        }
        if (!expects_success && !cfg.expect.empty()) {
            result.verdict = Verdict::Suspicious;
            result.description = "Succeeded unexpectedly (expected failure)";
            return result;
        }
    }

    // Default: clean
    result.verdict = Verdict::Clean;
    result.description = call.error_detail.empty()
        ? "OK"
        : call.error_detail;
    return result;
}

} // namespace audiodgfuzz
