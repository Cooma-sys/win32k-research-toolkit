#pragma once
#ifndef AUDIODGFUZZ_PCM_MUTATOR_HPP
#define AUDIODGFUZZ_PCM_MUTATOR_HPP

#include <windows.h>
#include <mmreg.h>
#include <string>
#include <vector>
#include <cstdint>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// A single PCM buffer test case
// -----------------------------------------------------------------------
struct PcmTestCase {
    std::string       description;
    std::vector<BYTE> data;      // raw PCM bytes
    UINT32            num_frames = 0;
};

// -----------------------------------------------------------------------
// PcmMutator — generates mutated PCM buffers for APOProcess fuzzing
// -----------------------------------------------------------------------
class PcmMutator {
public:
    explicit PcmMutator();

    // Generate PCM buffer mutations for given frame count and format
    std::vector<PcmTestCase> Generate(UINT32 num_frames,
                                      const WAVEFORMATEXTENSIBLE& fmt);

private:
    // Individual strategies
    PcmTestCase AllZeros(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase AllFF(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase NanFloats(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase InfFloats(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase Denormals(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase RandomBytes(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase BoundaryValues(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase Alternating(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase WrongSize_Smaller(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);
    PcmTestCase WrongSize_Larger(UINT32 num_frames, const WAVEFORMATEXTENSIBLE& fmt);

    static size_t BytesPerFrame(const WAVEFORMATEXTENSIBLE& fmt);
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_PCM_MUTATOR_HPP
