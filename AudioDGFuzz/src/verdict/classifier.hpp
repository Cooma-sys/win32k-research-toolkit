#pragma once
#ifndef AUDIODGFUZZ_CLASSIFIER_HPP
#define AUDIODGFUZZ_CLASSIFIER_HPP

#include <windows.h>
#include <string>
#include <vector>

#include "config/probe_loader.hpp"
#include "com/wasapi_client.hpp"

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Verdict classification
// -----------------------------------------------------------------------
enum class Verdict {
    Clean,           // expected HRESULT, audiodg alive — boring
    UnexpectedHR,    // HRESULT not in expect list
    AccessViolation, // SEH AV caught during call
    AudiodgCrash,    // audiodg.exe died
    AudiodgRestart,  // audiodg force-restarted (panic recovery)
    Suspicious       // unexpected but not definitive crash
};

// -----------------------------------------------------------------------
// Result of classifying a single test case
// -----------------------------------------------------------------------
struct VerdictResult {
    Verdict   verdict = Verdict::Clean;
    std::string test_case_desc;
    std::string description;
    HRESULT   hr = S_OK;

    bool is_interesting() const;
    static std::string Icon(Verdict v);
};

// -----------------------------------------------------------------------
// Classifier — maps CallResult + monitor state to a Verdict
// -----------------------------------------------------------------------
class Classifier {
public:
    // Classify a single test case result against probe expectations
    VerdictResult Classify(const ProbeConfig& cfg,
                           const std::string& test_desc,
                           const CallResult& call,
                           bool audiodg_crashed,
                           bool audiodg_restarted);

private:
    bool IsExpectedHresult(ProbeConfig cfg, HRESULT hr);
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_CLASSIFIER_HPP
