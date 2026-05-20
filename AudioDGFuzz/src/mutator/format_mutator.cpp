#include "mutator/format_mutator.hpp"
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------
FormatMutator::FormatMutator() {
    // Seed RNG once
    static bool seeded = false;
    if (!seeded) {
        srand(static_cast<unsigned int>(GetTickCount64()));
        seeded = true;
    }
}

// -----------------------------------------------------------------------
// Generate — dispatch based on strategies in spec
// -----------------------------------------------------------------------
std::vector<FormatTestCase> FormatMutator::Generate(const ParamSpec& spec) {
    std::vector<FormatTestCase> results;

    // Get a valid base to mutate from
    auto base_pcm  = ValidBase_PCM_Stereo44100();
    auto base_flt  = ValidBase_Float_Stereo48000();

    for (auto strategy : spec.strategies) {
        switch (strategy) {
        case ParamStrategy::ValidBase:
            results.push_back(base_pcm);
            results.push_back(base_flt);
            break;

        case ParamStrategy::MutateChannels: {
            auto cases = MutateChannels(base_pcm.fmt);
            results.insert(results.end(), cases.begin(), cases.end());
            break;
        }

        case ParamStrategy::MutateBlockAlign: {
            auto cases = MutateBlockAlign(base_pcm.fmt);
            results.insert(results.end(), cases.begin(), cases.end());
            break;
        }

        case ParamStrategy::MutateSampleRate: {
            auto cases = MutateSampleRate(base_pcm.fmt);
            results.insert(results.end(), cases.begin(), cases.end());
            break;
        }

        case ParamStrategy::MutateBitsPerSample: {
            auto cases = MutateBitsPerSample(base_pcm.fmt);
            results.insert(results.end(), cases.begin(), cases.end());
            break;
        }

        case ParamStrategy::WFXExtensible:
            results.push_back(WFXExtensible_Mismatched());
            break;

        case ParamStrategy::RandomGarbage:
            // Generate a few random-garbage variants
            for (int i = 0; i < 5; ++i)
                results.push_back(RandomGarbage());
            break;

        default:
            // Other strategies not applicable to format mutation — skip
            break;
        }
    }

    return results;
}

// -----------------------------------------------------------------------
// Valid base formats
// -----------------------------------------------------------------------
FormatTestCase FormatMutator::ValidBase_PCM_Stereo44100() {
    return {"ValidBase: PCM 16-bit stereo 44100 Hz",
            MakeWFX(2, 44100, 16, WAVE_FORMAT_PCM)};
}

FormatTestCase FormatMutator::ValidBase_Float_Stereo48000() {
    return {"ValidBase: Float 32-bit stereo 48000 Hz",
            MakeWFX(2, 48000, 32, WAVE_FORMAT_IEEE_FLOAT)};
}

// -----------------------------------------------------------------------
// MutateChannels — extreme channel counts
// -----------------------------------------------------------------------
std::vector<FormatTestCase> FormatMutator::MutateChannels(const WAVEFORMATEXTENSIBLE& base) {
    static const WORD kChannelValues[] = {0, 1, 2, 3, 16, 32, 255};
    std::vector<FormatTestCase> results;

    for (WORD ch : kChannelValues) {
        WAVEFORMATEXTENSIBLE wfx = base;
        wfx.Format.nChannels = ch;
        // Recalculate block align and bytes/sec for sanity (or intentionally wrong)
        if (ch > 0) {
            wfx.Format.nBlockAlign = ch * (wfx.Format.wBitsPerSample / 8);
            wfx.Format.nAvgBytesPerSec = wfx.Format.nSamplesPerSec * wfx.Format.nBlockAlign;
        } else {
            wfx.Format.nBlockAlign = 0;
            wfx.Format.nAvgBytesPerSec = 0;
        }
        std::ostringstream ss;
        ss << "Channels=" << ch;
        results.push_back({ss.str(), wfx});
    }

    return results;
}

// -----------------------------------------------------------------------
// MutateBlockAlign — incorrect block alignment values
// -----------------------------------------------------------------------
std::vector<FormatTestCase> FormatMutator::MutateBlockAlign(const WAVEFORMATEXTENSIBLE& base) {
    static const DWORD kBadAlign[] = {0, 1, 2, 3, 65534, 65535};
    std::vector<FormatTestCase> results;

    for (DWORD ba : kBadAlign) {
        WAVEFORMATEXTENSIBLE wfx = base;
        wfx.Format.nBlockAlign = static_cast<WORD>(ba);
        std::ostringstream ss;
        ss << "BlockAlign=" << ba;
        results.push_back({ss.str(), wfx});
    }

    // nChannels * wBitsPerSample/8 ± 1
    WORD correct_align = base.Format.nChannels * (base.Format.wBitsPerSample / 8);
    if (correct_align > 0) {
        for (int delta : {-1, 1}) {
            WAVEFORMATEXTENSIBLE wfx = base;
            wfx.Format.nBlockAlign = static_cast<WORD>(correct_align + delta);
            std::ostringstream ss;
            ss << "BlockAlign=" << (correct_align + delta) << " (off by " << delta << ")";
            results.push_back({ss.str(), wfx});
        }
    }

    return results;
}

// -----------------------------------------------------------------------
// MutateSampleRate — boundary and unusual sample rates
// -----------------------------------------------------------------------
std::vector<FormatTestCase> FormatMutator::MutateSampleRate(const WAVEFORMATEXTENSIBLE& base) {
    static const DWORD kRates[] = {
        0, 1, 7999, 8000, 11025, 16000, 22050,
        44100, 48000, 96000, 192000, 384000, MAXDWORD
    };
    std::vector<FormatTestCase> results;

    for (DWORD rate : kRates) {
        WAVEFORMATEXTENSIBLE wfx = base;
        wfx.Format.nSamplesPerSec = rate;
        wfx.Format.nAvgBytesPerSec = rate * wfx.Format.nBlockAlign;
        std::ostringstream ss;
        ss << "SampleRate=" << rate;
        results.push_back({ss.str(), wfx});
    }

    return results;
}

// -----------------------------------------------------------------------
// MutateBitsPerSample — unusual bit depths
// -----------------------------------------------------------------------
std::vector<FormatTestCase> FormatMutator::MutateBitsPerSample(const WAVEFORMATEXTENSIBLE& base) {
    static const WORD kBps[] = {0, 1, 7, 8, 15, 16, 23, 24, 31, 32, 33, 64, 128, 255};
    std::vector<FormatTestCase> results;

    for (WORD bps : kBps) {
        WAVEFORMATEXTENSIBLE wfx = base;
        wfx.Format.wBitsPerSample = bps;
        if (wfx.Format.nChannels > 0)
            wfx.Format.nBlockAlign = wfx.Format.nChannels * (bps / 8 + ((bps % 8) ? 1 : 0));
        wfx.Format.nAvgBytesPerSec = wfx.Format.nSamplesPerSec * wfx.Format.nBlockAlign;
        std::ostringstream ss;
        ss << "BitsPerSample=" << bps;
        results.push_back({ss.str(), wfx});
    }

    return results;
}

// -----------------------------------------------------------------------
// WFXExtensible_Mismatched — dwChannelMask has more bits than nChannels
// -----------------------------------------------------------------------
FormatTestCase FormatMutator::WFXExtensible_Mismatched() {
    WAVEFORMATEXTENSIBLE wfx{};
    wfx.Format.wFormatTag      = WAVE_FORMAT_EXTENSIBLE;
    wfx.Format.nChannels       = 2;          // only 2 channels...
    wfx.Format.nSamplesPerSec  = 48000;
    wfx.Format.nAvgBytesPerSec = 384000;
    wfx.Format.nBlockAlign     = 8;
    wfx.Format.wBitsPerSample  = 32;
    wfx.Format.cbSize          = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    wfx.dwChannelMask          = 0x3F;       // ...but mask claims 6 channels!
    wfx.SubFormat              = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;

    return {"WFXExtensible: channel mask (0x3F=6ch) vs nChannels(2) mismatch", wfx};
}

// -----------------------------------------------------------------------
// RandomGarbage — completely random bytes cast to WFX
// -----------------------------------------------------------------------
FormatTestCase FormatMutator::RandomGarbage() {
    WAVEFORMATEXTENSIBLE wfx{};
    // Fill with random non-zero data
    BYTE* raw = reinterpret_cast<BYTE*>(&wfx);
    for (size_t i = 0; i < sizeof(wfx); ++i)
        raw[i] = static_cast<BYTE>(rand() & 0xFF);

    std::ostringstream ss;
    ss << "RandomGarbage: first bytes = 0x"
       << std::hex << (raw[0] | (raw[1] << 8))
       << " tag=0x" << wfx.Format.wFormatTag << std::dec;
    return {ss.str(), wfx};
}

// -----------------------------------------------------------------------
// Helper — construct WAVEFORMATEXTENSIBLE with common fields
// -----------------------------------------------------------------------
WAVEFORMATEXTENSIBLE FormatMutator::MakeWFX(WORD channels, DWORD sample_rate,
                                             WORD bits_per_sample, WORD format_tag) {
    WAVEFORMATEXTENSIBLE wfx{};

    wfx.Format.wFormatTag      = format_tag;
    wfx.Format.nChannels       = channels;
    wfx.Format.nSamplesPerSec  = sample_rate;
    wfx.Format.wBitsPerSample  = bits_per_sample;
    wfx.Format.nBlockAlign     = channels * (bits_per_sample / 8);
    wfx.Format.nAvgBytesPerSec = sample_rate * wfx.Format.nBlockAlign;

    if (format_tag == WAVE_FORMAT_IEEE_FLOAT || bits_per_sample > 16) {
        wfx.Format.wFormatTag     = WAVE_FORMAT_EXTENSIBLE;
        wfx.Format.cbSize         = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
        wfx.dwChannelMask         = (channels <= 2) ? (channels == 1 ?
                                    SPEAKER_FRONT_CENTER :
                                    SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT) :
                                    static_cast<DWORD>((1ULL << channels) - 1);
        wfx.SubFormat             = (format_tag == WAVE_FORMAT_IEEE_FLOAT ||
                                      format_tag == WAVE_FORMAT_EXTENSIBLE) ?
                                      KSDATAFORMAT_SUBTYPE_IEEE_FLOAT :
                                      KSDATAFORMAT_SUBTYPE_PCM;
    } else {
        wfx.Format.cbSize = 0;
        wfx.dwChannelMask = 0;
        memset(&wfx.SubFormat, 0, sizeof(GUID));
    }

    return wfx;
}

} // namespace audiodgfuzz
