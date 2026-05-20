#include "com/apo_harness.hpp"

#include <iostream>
#include <sstream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Known system APO CLSIDs to try (in order of availability)
// -----------------------------------------------------------------------
static const wchar_t* kKnownApoClsids[] = {
    L"{F8512E00-1207-11CF-A796-0004AC9B0028}",  // Microsoft AEC APO
    L"{62F1E513-853A-4E64-96DB-872C910D0CBC}",  // MsApoFxProxy
    L"{636A25B7-6F06-4FC0-88AE-CDAA14D1738F}",  // AudioLFX (bass boost / loudness eq)
    nullptr
};

ApoHarness::ApoHarness() = default;

ApoHarness::~ApoHarness() {
    Unload();
}

// -----------------------------------------------------------------------
// LoadByClsid — CoCreateInstance for IAudioProcessingObject, then QI for RT
// -----------------------------------------------------------------------
bool ApoHarness::LoadByClsid(const std::wstring& clsid_str) {
    Unload();

    CLSID clsid = {};
    HRESULT hr = CLSIDFromString(clsid_str.c_str(), &clsid);
    if (FAILED(hr)) {
        std::cerr << "[apo] CLSIDFromString failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }

    __try {
        hr = CoCreateInstance(clsid, nullptr, CLSCTX_ALL,
                              __uuidof(IAudioProcessingObject),
                              reinterpret_cast<void**>(&apo_));
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "[apo] SEH during CoCreateInstance: 0x"
                  << std::hex << GetExceptionCode() << std::dec << "\n";
        return false;
    }

    if (!apo_ || FAILED(hr)) {
        std::cerr << "[apo] CoCreateInstance IAudioProcessingObject failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }

    // Query for RT interface
    hr = apo_->QueryInterface(__uuidof(IAudioProcessingObjectRT),
                              reinterpret_cast<void**>(&apo_rt_));
    if (!apo_rt_ || FAILED(hr)) {
        std::cerr << "[apo] QueryInterface IAudioProcessingObjectRT failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        Unload();
        return false;
    }

    return true;
}

void ApoHarness::Unload() {
    if (apo_rt_) { apo_rt_->Release(); apo_rt_ = nullptr; }
    if (apo_)   { apo_->Release();   apo_   = nullptr; }
    if (dll_handle_) { FreeLibrary(dll_handle_); dll_handle_ = nullptr; }
}

// -----------------------------------------------------------------------
// Initialize — set up APO with the target format
// -----------------------------------------------------------------------
HRESULT ApoHarness::Initialize(const WAVEFORMATEXTENSIBLE& fmt) {
    if (!IsLoaded()) return E_POINTER;

    auto fmt_ptr = const_cast<WAVEFORMATEX*>(
        reinterpret_cast<const WAVEFORMATEX*>(&fmt));

    UINT32 max_frames = 0;
    HRESULT hr = S_OK;

    __try {
        hr = apo_->Initialize(UINT32_MAX, fmt_ptr, &max_frames);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return HRESULT_FROM_WIN32(GetExceptionCode());
    }

    return hr;
}

// -----------------------------------------------------------------------
// Process — feed PCM through APOProcess with fuzz data
// -----------------------------------------------------------------------
ApoCallResult ApoHarness::Process(const std::vector<BYTE>& mutated_pcm,
                                   UINT32 num_frames,
                                   const WAVEFORMATEXTENSIBLE& fmt) {
    ApoCallResult result{};

    if (!IsLoaded()) {
        result.returned_normally = false;
        result.exception_info = "APO not loaded";
        return result;
    }

    // Set up input/output buffer pointers for APOProcess
    // We pass the mutated buffer as both input and output (in-place)
    BYTE* input_ptr  = const_cast<BYTE*>(mutated_pcm.data());
    BYTE* output_ptr = const_cast<BYTE*>(mutated_pcm.data());

    auto fmt_ptr = const_cast<WAVEFORMATEX*>(
        reinterpret_cast<const WAVEFORMATEX*>(&fmt));

    APO_CONNECTION_PROPERTY input_prop{};
    input_prop.pBuffer              = reinterpret_cast<UINT_PTR>(const_cast<BYTE*>(mutated_pcm.data()));
    input_prop.u32ValidFrameCount   = num_frames;
    input_prop.u32BufferFlags       = BUFFER_VALID;

    APO_CONNECTION_PROPERTY output_prop{};
    output_prop.pBuffer             = reinterpret_cast<UINT_PTR>(const_cast<BYTE*>(mutated_pcm.data()));
    output_prop.u32ValidFrameCount  = 0;
    output_prop.u32BufferFlags      = BUFFER_SILENT;

    __try {
        // APOProcess returns void, takes 4 params: (numIn, pIn, numOut, pOut)
        apo_rt_->APOProcess(1, &input_prop, 1, &output_prop);
        result.hr_process = S_OK;
        result.returned_normally = true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        result.returned_normally = false;
        result.exception_info = "SEH exception during APOProcess: 0x" +
            std::to_string(GetExceptionCode());
        result.hr_process = HRESULT_FROM_WIN32(GetExceptionCode());
    }

    return result;
}

} // namespace audiodgfuzz
