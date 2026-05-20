#pragma once
#ifndef AUDIODGFUZZ_WASAPI_CLIENT_HPP
#define AUDIODGFUZZ_WASAPI_CLIENT_HPP

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <avrt.h>
#include <memory>
#include <string>
#include <vector>
#include <optional>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Materialized argument set for a single WASAPI test case
// -----------------------------------------------------------------------
struct WasapiCallArgs {
    std::string description;
    AUDCLNT_SHAREMODE share_mode = AUDCLNT_SHAREMODE_SHARED;
    DWORD stream_flags = 0;
    REFERENCE_TIME buffer_duration = 0;
    REFERENCE_TIME periodicity = 0;
    std::unique_ptr<WAVEFORMATEXTENSIBLE> format; // nullptr = null-format test

    // For GetBuffer/ReleaseBuffer tests:
    UINT32 num_frames_requested = 0;
    UINT32 num_frames_written = 0;
};

// -----------------------------------------------------------------------
// Result of a single WASAPI call
// -----------------------------------------------------------------------
struct CallResult {
    HRESULT hr = S_OK;
    bool audiodg_alive = true;
    std::string error_detail;
};

// -----------------------------------------------------------------------
// WasapiClient — wraps COM initialization, device enumeration,
// and IAudioClient / IAudioRenderClient method invocation.
// All COM calls are wrapped in SEH __try/__except for AV safety.
// -----------------------------------------------------------------------
class WasapiClient {
public:
    WasapiClient();
    ~WasapiClient();

    // Initialize COM + MMDeviceEnumerator, get default render endpoint
    bool Init();
    void Shutdown();

    // Get fresh IAudioClient on current endpoint (reinitializes each call)
    bool AcquireClient();
    void ReleaseClient();

    // Run IAudioClient::Initialize with mutated args
    CallResult TestInitialize(const WasapiCallArgs& args);

    // Run GetBuffer/ReleaseBuffer sequence with mutated frame counts
    CallResult TestBufferCycle(const WasapiCallArgs& args);

    // Run IsFormatSupported with mutated WAVEFORMATEX
    CallResult TestFormatSupport(const WAVEFORMATEXTENSIBLE& fmt);

private:
    IMMDeviceEnumerator* enumerator_ = nullptr;
    IMMDevice*           device_     = nullptr;
    IAudioClient*        client_     = nullptr;
    IAudioRenderClient*  render_     = nullptr;
    bool                 com_initialized_ = false;

    // SEH-safe wrapper for any function that returns HRESULT
    template<typename Fn>
    CallResult SehCall(Fn&& fn, const char* op_name);

    // Check if audiodg.exe is alive via snapshot
    bool IsAudiodgAlive();
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_WASAPI_CLIENT_HPP
