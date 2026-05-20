#pragma once
#ifndef AUDIODGFUZZ_APO_HARNESS_HPP
#define AUDIODGFUZZ_APO_HARNESS_HPP

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioprocessingobject.h>
#include <audioapotypes.h>
#include <string>
#include <vector>
#include <memory>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Result of an APO call (Initialize / APOProcess)
// -----------------------------------------------------------------------
struct ApoCallResult {
    bool returned_normally = true;  // false if SEH exception caught
    std::string exception_info;
    HRESULT hr_initialize = S_OK;
    HRESULT hr_process = S_OK;
};

// -----------------------------------------------------------------------
// ApoHarness — loads a system APO DLL by CLSID and exposes
// IAudioProcessingObject + IAudioProcessingObjectRT for direct fuzzing.
// Bypasses audiosrv isolation by loading APO in-process.
// -----------------------------------------------------------------------
class ApoHarness {
public:
    ApoHarness();
    ~ApoHarness();

    // Load an APO by CLSID string from registry / CoCreateInstance
    bool LoadByClsid(const std::wstring& clsid_str);
    void Unload();

    // Initialize APO with a given format
    HRESULT Initialize(const WAVEFORMATEXTENSIBLE& fmt);

    // Feed PCM buffer through APOProcess; mutated_pcm contains fuzz data
    ApoCallResult Process(const std::vector<BYTE>& mutated_pcm,
                          UINT32 num_frames,
                          const WAVEFORMATEXTENSIBLE& fmt);

    bool IsLoaded() const { return apo_ != nullptr && apo_rt_ != nullptr; }

private:
    IAudioProcessingObject*     apo_     = nullptr;
    IAudioProcessingObjectRT*   apo_rt_  = nullptr;
    HMODULE                     dll_handle_ = nullptr;
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_APO_HARNESS_HPP
