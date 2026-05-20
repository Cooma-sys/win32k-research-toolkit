#pragma once
#ifndef AUDIODGFUZZ_FORMAT_MUTATOR_HPP
#define AUDIODGFUZZ_FORMAT_MUTATOR_HPP

#include <windows.h>
#include <mmreg.h>
#include <string>
#include <vector>
#include <memory>
#include <random>

#include "config/probe_loader.hpp"

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// A single WAVEFORMATEXTENSIBLE test case with description
// -----------------------------------------------------------------------
struct FormatTestCase {
    std::string          description;
    WAVEFORMATEXTENSIBLE fmt{};
};

// -----------------------------------------------------------------------
// FormatMutator — generates WAVEFORMATEX test cases from ParamStrategy
// -----------------------------------------------------------------------
class FormatMutator {
public:
    explicit FormatMutator();

    // Generate test cases for all strategies in the given param spec
    std::vector<FormatTestCase> Generate(const ParamSpec& spec);

private:
    // Base valid formats
    FormatTestCase ValidBase_PCM_Stereo44100();
    FormatTestCase ValidBase_Float_Stereo48000();

    // Mutation strategies
    std::vector<FormatTestCase> MutateChannels(const WAVEFORMATEXTENSIBLE& base);
    std::vector<FormatTestCase> MutateBlockAlign(const WAVEFORMATEXTENSIBLE& base);
    std::vector<FormatTestCase> MutateSampleRate(const WAVEFORMATEXTENSIBLE& base);
    std::vector<FormatTestCase> MutateBitsPerSample(const WAVEFORMATEXTENSIBLE& base);

    // Special cases
    FormatTestCase WFXExtensible_Mismatched();  // dwChannelMask bits > nChannels
    FormatTestCase RandomGarbage();              // memset with random data

    // Helpers
    static WAVEFORMATEXTENSIBLE MakeWFX(WORD channels, DWORD sample_rate,
                                         WORD bits_per_sample, WORD format_tag);
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_FORMAT_MUTATOR_HPP
