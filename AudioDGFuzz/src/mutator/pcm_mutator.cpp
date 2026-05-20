#include "mutator/pcm_mutator.hpp"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Constructor — seed RNG
// -----------------------------------------------------------------------
PcmMutator::PcmMutator() {
    static bool seeded = false;
    if (!seeded) {
        srand(static_cast<unsigned int>(GetTickCount64()));
        seeded = true;
    }
}

// -----------------------------------------------------------------------
// Generate — produce all PCM mutation test cases
// -----------------------------------------------------------------------
std::vector<PcmTestCase> PcmMutator::Generate(UINT32 num_frames,
                                               const WAVEFORMATEXTENSIBLE& fmt) {
    std::vector<PcmTestCase> results;

    results.push_back(AllZeros(num_frames, fmt));
    results.push_back(AllFF(num_frames, fmt));
    results.push_back(NanFloats(num_frames, fmt));
    results.push_back(InfFloats(num_frames, fmt));
    results.push_back(Denormals(num_frames, fmt));
    results.push_back(RandomBytes(num_frames, fmt));
    results.push_back(BoundaryValues(num_frames, fmt));
    results.push_back(Alternating(num_frames, fmt));
    results.push_back(WrongSize_Smaller(num_frames, fmt));
    results.push_back(WrongSize_Larger(num_frames, fmt));

    return results;
}

// -----------------------------------------------------------------------
// BytesPerFrame — compute bytes needed for one audio frame
// -----------------------------------------------------------------------
size_t PcmMutator::BytesPerFrame(const WAVEFORMATEXTENSIBLE& fmt) {
    if (fmt.Format.nBlockAlign > 0)
        return static_cast<size_t>(fmt.Format.nBlockAlign);
    // Fallback: channels * (bits/8 rounded up)
    WORD bps = fmt.Format.wBitsPerSample;
    return static_cast<size_t>(fmt.Format.nChannels) *
           ((bps / 8) + ((bps % 8) ? 1 : 0));
}

// -----------------------------------------------------------------------
// All zeros
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::AllZeros(UINT32 num_frames,
                                  const WAVEFORMATEXTENSIBLE& fmt) {
    size_t total = num_frames * BytesPerFrame(fmt);
    std::vector<BYTE> data(total, 0);
    return {"PCM: all zeros", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// All 0xFF
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::AllFF(UINT32 num_frames,
                               const WAVEFORMATEXTENSIBLE& fmt) {
    size_t total = num_frames * BytesPerFrame(fmt);
    std::vector<BYTE> data(total, 0xFF);
    return {"PCM: all 0xFF", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// NaN floats — quiet NaN pattern for IEEE float
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::NanFloats(UINT32 num_frames,
                                   const WAVEFORMATEXTENSIBLE& fmt) {
    // IEEE 754 quiet NaN: sign=0, exponent=all 1s (0xFF), mantissa != 0
    uint32_t nan_pattern = 0x7FC00000;
    size_t total = num_frames * BytesPerFrame(fmt);

    std::vector<BYTE> data(total);
    const BYTE* nan_bytes = reinterpret_cast<const BYTE*>(&nan_pattern);
    for (size_t i = 0; i + 3 < total; i += 4) {
        data[i]     = nan_bytes[0];
        data[i + 1] = nan_bytes[1];
        data[i + 2] = nan_bytes[2];
        data[i + 3] = nan_bytes[3];
    }

    return {"PCM: NaN floats (IEEE)", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// +/- Infinity floats
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::InfFloats(UINT32 num_frames,
                                   const WAVEFORMATEXTENSIBLE& fmt) {
    // Positive infinity: 0x7F800000, negative: 0xFF800000
    uint32_t pos_inf = 0x7F800000;
    uint32_t neg_inf = 0xFF800000;
    size_t total = num_frames * BytesPerFrame(fmt);

    std::vector<BYTE> data(total);
    const BYTE* pos_b = reinterpret_cast<const BYTE*>(&pos_inf);
    const BYTE* neg_b = reinterpret_cast<const BYTE*>(&neg_inf);
    for (size_t i = 0; i + 7 < total; i += 8) {
        data[i]     = pos_b[0]; data[i+1] = pos_b[1];
        data[i+2]   = pos_b[2]; data[i+3] = pos_b[3];  // +inf
        data[i+4]   = neg_b[0]; data[i+5] = neg_b[1];
        data[i+6]   = neg_b[2]; data[i+7] = neg_b[3];  // -inf
    }

    return {"PCM: +/-Inf floats", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// Denormals — smallest representable float values
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::Denormals(UINT32 num_frames,
                                   const WAVEFORMATEXTENSIBLE& fmt) {
    // Smallest denormal: 0x00000001
    uint32_t denorm = 0x00000001;
    size_t total = num_frames * BytesPerFrame(fmt);

    std::vector<BYTE> data(total);
    const BYTE* dbytes = reinterpret_cast<const BYTE*>(&denorm);
    for (size_t i = 0; i + 3 < total; i += 4) {
        data[i]     = dbytes[0];
        data[i + 1] = dbytes[1];
        data[i + 2] = dbytes[2];
        data[i + 3] = dbytes[3];
    }

    return {"PCM: denormal floats", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// Random bytes
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::RandomBytes(UINT32 num_frames,
                                     const WAVEFORMATEXTENSIBLE& fmt) {
    size_t total = num_frames * BytesPerFrame(fmt);
    std::vector<BYTE> data(total);
    for (auto& b : data)
        b = static_cast<BYTE>(rand() & 0xFF);
    return {"PCM: random bytes", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// Boundary integer values for PCM formats
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::BoundaryValues(UINT32 num_frames,
                                        const WAVEFORMATEXTENSIBLE& fmt) {
    size_t total = num_frames * BytesPerFrame(fmt);
    std::vector<BYTE> data(total, 0);
    WORD bps = fmt.Format.wBitsPerSample;

    if (bps == 16 || bps <= 16) {
        // INT16_MAX / INT16_MIN alternating per frame
        int16_t max_val = INT16_MAX;
        int16_t min_val = INT16_MIN;
        auto max_b = reinterpret_cast<const BYTE*>(&max_val);
        auto min_b = reinterpret_cast<const BYTE*>(&min_val);
        for (size_t i = 0; i + 3 < total; i += 4) {
            data[i]   = max_b[0]; data[i+1] = max_b[1];  // INT16_MAX
            data[i+2] = min_b[0]; data[i+3] = min_b[1];  // INT16_MIN
        }
    } else {
        // INT32_MAX / INT32_MIN
        int32_t max_val = INT32_MAX;
        int32_t min_val = INT32_MIN;
        auto max_b = reinterpret_cast<const BYTE*>(&max_val);
        auto min_b = reinterpret_cast<const BYTE*>(&min_val);
        for (size_t i = 0; i + 7 < total; i += 8) {
            data[i]   = max_b[0]; data[i+1] = max_b[1];
            data[i+2] = max_b[2]; data[i+3] = max_b[3];
            data[i+4] = min_b[0]; data[i+5] = min_b[1];
            data[i+6] = min_b[2]; data[i+7] = min_b[3];
        }
    }

    return {"PCM: boundary integers (INT_MIN/MAX)", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// Alternating 0x00/0xFF per byte
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::Alternating(UINT32 num_frames,
                                     const WAVEFORMATEXTENSIBLE& fmt) {
    size_t total = num_frames * BytesPerFrame(fmt);
    std::vector<BYTE> data(total);
    for (size_t i = 0; i < total; ++i)
        data[i] = static_cast<BYTE>((i % 2 == 0) ? 0x00 : 0xFF);
    return {"PCM: alternating 0x00/0xFF", std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// WrongSize — buffer smaller than expected (triggers OOB read in APO)
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::WrongSize_Smaller(UINT32 num_frames,
                                           const WAVEFORMATEXTENSIBLE& fmt) {
    size_t correct_size = num_frames * BytesPerFrame(fmt);
    size_t small_size = (correct_size > 1) ? (correct_size / 2) : 0;
    std::vector<BYTE> data(small_size, 0xAB); // fill with sentinel
    return {"PCM: undersized buffer (" +
            std::to_string(small_size) + "/" +
            std::to_string(correct_size) + " bytes)",
            std::move(data), num_frames};
}

// -----------------------------------------------------------------------
// WrongSize — buffer larger than expected
// -----------------------------------------------------------------------
PcmTestCase PcmMutator::WrongSize_Larger(UINT32 num_frames,
                                          const WAVEFORMATEXTENSIBLE& fmt) {
    size_t correct_size = num_frames * BytesPerFrame(fmt);
    size_t large_size = correct_size * 2;
    std::vector<BYTE> data(large_size, 0xCD); // different sentinel
    return {"PCM: oversized buffer (" +
            std::to_string(large_size) + "/" +
            std::to_string(correct_size) + " bytes)",
            std::move(data), num_frames};
}

} // namespace audiodgfuzz
