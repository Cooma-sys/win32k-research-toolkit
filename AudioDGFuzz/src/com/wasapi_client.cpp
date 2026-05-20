#include "com/wasapi_client.hpp"
#include "monitor/audiodg_monitor.hpp"

#include <iostream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Constructor / Destructor
// -----------------------------------------------------------------------
WasapiClient::WasapiClient() = default;

WasapiClient::~WasapiClient() {
    Shutdown();
}

// -----------------------------------------------------------------------
// Init — COM + device enumerator + default render endpoint
// -----------------------------------------------------------------------
bool WasapiClient::Init() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::cerr << "[wasapi] CoInitializeEx failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }
    com_initialized_ = SUCCEEDED(hr) || (hr == RPC_E_CHANGED_MODE);

    hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void**>(&enumerator_));
    if (FAILED(hr) || !enumerator_) {
        std::cerr << "[wasapi] CoCreateInstance MMDeviceEnumerator failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }

    hr = enumerator_->GetDefaultAudioEndpoint(eRender, eConsole, &device_);
    if (FAILED(hr) || !device_) {
        std::cerr << "[wasapi] GetDefaultAudioEndpoint failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }

    return true;
}

void WasapiClient::Shutdown() {
    ReleaseClient();
    if (render_) { render_->Release(); render_ = nullptr; }
    if (device_)  { device_->Release();  device_  = nullptr; }
    if (enumerator_) { enumerator_->Release(); enumerator_ = nullptr; }
    if (com_initialized_) { CoUninitialize(); com_initialized_ = false; }
}

// -----------------------------------------------------------------------
// Acquire / Release IAudioClient
// -----------------------------------------------------------------------
bool WasapiClient::AcquireClient() {
    ReleaseClient();
    if (!device_) return false;

    HRESULT hr = device_->Activate(
        __uuidof(IAudioClient), CLSCTX_ALL, nullptr,
        reinterpret_cast<void**>(&client_));
    if (FAILED(hr) || !client_) {
        std::cerr << "[wasapi] Activate IAudioClient failed: 0x"
                  << std::hex << hr << std::dec << "\n";
        return false;
    }

    // Also acquire IAudioRenderClient for buffer tests
    client_->GetService(__uuidof(IAudioRenderClient),
                        reinterpret_cast<void**>(&render_));
    // render_ may remain nullptr if not yet initialized — that's OK

    return true;
}

void WasapiClient::ReleaseClient() {
    if (render_) { render_->Release(); render_ = nullptr; }
    if (client_) { client_->Release(); client_ = nullptr; }
}

// -----------------------------------------------------------------------
// SEH-safe call wrapper
// -----------------------------------------------------------------------
template<typename Fn>
CallResult WasapiClient::SehCall(Fn&& fn, const char* op_name) {
    CallResult result{};
    result.audiodg_alive = IsAudiodgAlive();

    __try {
        result.hr = fn();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        result.hr = E_UNEXPECTED;
        result.error_detail = std::string(op_name) + ": SEH exception 0x" +
            std::to_string(GetExceptionCode());
        result.audiodg_alive = IsAudiodgAlive();
        return result;
    }

    result.audiodg_alive = IsAudiodgAlive();

    if (FAILED(result.hr)) {
        result.error_detail = std::string(op_name) + ": HRESULT 0x" +
            std::to_string(result.hr);
    }
    return result;
}

// -----------------------------------------------------------------------
// TestInitialize — IAudioClient::Initialize with mutated args
// -----------------------------------------------------------------------
CallResult WasapiClient::TestInitialize(const WasapiCallArgs& args) {
    if (!AcquireClient()) {
        return {E_POINTER, IsAudiodgAlive(), "Failed to acquire IAudioClient"};
    }

    WAVEFORMATEX* pFmt = args.format
        ? reinterpret_cast<WAVEFORMATEX*>(args.format.get())
        : nullptr;

    return SehCall([&]() -> HRESULT {
        return client_->Initialize(
            args.share_mode,
            args.stream_flags,
            args.buffer_duration,
            args.periodicity,
            pFmt,
            GUID_NULL);
    }, "IAudioClient::Initialize");
}

// -----------------------------------------------------------------------
// TestBufferCycle — GetBuffer / ReleaseBuffer with mutated frame counts
// -----------------------------------------------------------------------
CallResult WasapiClient::TestBufferCycle(const WasapiCallArgs& args) {
    if (!AcquireClient()) {
        return {E_POINTER, IsAudiodgAlive(), "Failed to acquire IAudioClient"};
    }

    // First we need a valid initialization for buffer operations
    WAVEFORMATEX* pFmt = args.format
        ? reinterpret_cast<WAVEFORMATEX*>(args.format.get())
        : nullptr;

    // Try to initialize with given format — may fail, that's a valid test case too
    CallResult init_result = SehCall([&]() -> HRESULT {
        return client_->Initialize(
            args.share_mode, args.stream_flags,
            args.buffer_duration, args.periodicity,
            pFmt, GUID_NULL);
    }, "IAudioClient::Initialize (buffer preflight)");

    if (FAILED(init_result.hr)) {
        init_result.error_detail = "BufferCycle preflight Initialize failed: " +
            init_result.error_detail;
        return init_result;
    }

    // Re-acquire render client now that Initialize succeeded
    if (render_) { render_->Release(); render_ = nullptr; }
    HRESULT hr_svc = client_->GetService(__uuidof(IAudioRenderClient),
                                         reinterpret_cast<void**>(&render_));
    if (FAILED(hr_svc) || !render_) {
        CallResult r{};
        r.hr = hr_svc;
        r.audiodg_alive = IsAudiodgAlive();
        r.error_detail = "GetService IAudioRenderClient failed after Initialize";
        return r;
    }

    // Now try GetBuffer with mutated frame count
    BYTE* buffer = nullptr;
    CallResult get_result = SehCall([&]() -> HRESULT {
        return render_->GetBuffer(args.num_frames_requested, &buffer);
    }, "IAudioRenderClient::GetBuffer");

    if (FAILED(get_result.hr)) {
        get_result.error_detail = "GetBuffer failed: " + get_result.error_detail;
        return get_result;
    }

    // If GetBuffer succeeded, try ReleaseBuffer with mismatched count
    CallResult release_result = SehCall([&]() -> HRESULT {
        return render_->ReleaseBuffer(args.num_frames_written, 0);
    }, "IAudioRenderClient::ReleaseBuffer");

    release_result.error_detail =
        "GetBuffer(" + std::to_string(args.num_frames_requested) +
        ") -> ReleaseBuffer(" + std::to_string(args.num_frames_written) +
        ") = 0x" + std::to_string(release_result.hr);
    return release_result;
}

// -----------------------------------------------------------------------
// TestFormatSupport — IsFormatSupported with mutated format
// -----------------------------------------------------------------------
CallResult WasapiClient::TestFormatSupport(const WAVEFORMATEXTENSIBLE& fmt) {
    if (!AcquireClient()) {
        return {E_POINTER, IsAudiodgAlive(), "Failed to acquire IAudioClient"};
    }

    WAVEFORMATEX* closest = nullptr;
    auto fmt_ptr = const_cast<WAVEFORMATEX*>(
        reinterpret_cast<const WAVEFORMATEX*>(&fmt));

    return SehCall([&]() -> HRESULT {
        return client_->IsFormatSupported(
            AUDCLNT_SHAREMODE_SHARED, fmt_ptr, &closest);
    }, "IAudioClient::IsFormatSupported");
}

// -----------------------------------------------------------------------
// Audiodg liveness check via process snapshot
// -----------------------------------------------------------------------
bool WasapiClient::IsAudiodgAlive() {
    AudiodgMonitor mon;
    return mon.FindProcess();
}

} // namespace audiodgfuzz
