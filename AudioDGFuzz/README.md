# AudioDGFuzz

Windows-native **AudioDG Rendering Pipeline Fuzzer** — targets `audiodg.exe` via WASAPI COM interfaces and direct APO (Audio Processing Object) loading.

## What is audiodg.exe?

`audiodg.exe` (Audio Device Graph) is a Windows system process running as **SYSTEM** with elevated privileges inside an isolated session (Session 0). It hosts:

- The **audio engine** (`audioeng.dll`) — shared-mode and exclusive-mode stream management
- **System APOs** — Audio Processing Objects for effects like bass boost, loudness equalization, room correction, and acoustic echo cancellation
- **Endpoint processing pipelines** — format conversion, sample rate conversion, channel mixing

Because it runs at SYSTEM privilege level and processes untrusted audio data from user-mode applications, its attack surface is significant:

| Surface | Target | Risk |
|---|---|---|
| `IAudioClient::Initialize` | WAVEFORMATEX validation in audioeng.dll | Format parsing bugs, integer overflow in buffer sizing |
| `IAudioRenderClient::GetBuffer/ReleaseBuffer` | Shared ring buffer frame accounting | Off-by-one, buffer over/under-read |
| `IAudioClient::IsFormatSupported` | Format negotiation path | Inconsistent state from malformed formats |
| `IAudioProcessingObjectRT::APOProcess` | Signal processing code in APO DLLs | NaN/denormal handling crashes, OOB on malformed PCM |

## Build

Requires **Visual Studio 2019+** with the Windows 10/11 SDK.

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

Output: `build\Release\AudioDGFuzz.exe`

### Prerequisites

- Windows 10 1903+ or Windows 11 (24H2 recommended)
- Windows SDK with MMDevice API headers
- Administrator elevation (for audiodg crash detection via process snapshot)

## Usage

### Run a single probe
```
AudioDGFuzz.exe probes\IAudioClient_init.yml
```

### Run all probes in directory
```
AudioDGFuzz.exe --dir probes\
```
### List available probes
```
AudioDGFuzz.exe --list probes\
```

## Verdict meanings

After each test case, AudioDGFuzz classifies the result:

| Icon | Verdict | Meaning |
|---|---|---|
| ✓ | **Clean** | Expected HRESULT returned, audiodg still alive |
| ? | **UnexpectedHR** | HRESULT not in the probe's expected list |
| ⚡ | **AccessViolation** | SEH exception caught during the COM call |
| 💥 | **AudiodgCrash** | `audiodg.exe` terminated (crashed) during the test |
| 🔄 | **AudiodgRestart** | audiodg PID changed — likely restarted by audiosrv after panic |
| ⚠ | **Suspicious** | Unexpected behavior but not a definitive crash |

Any verdict other than `Clean` is reported in color. Confirmed crashes (💥, ⚡) are highlighted red.

## Probe architecture

Each probe is a YAML file describing:

1. **What to call** — WASAPI interface + method, or APO method
2. **What to mutate** — parameter specs with strategy lists
3. **What's acceptable** — expected HRESULTs / outcomes

The pipeline for each test case:
```
ProbeConfig → FormatMutator/PcmMutator → WasapiClient/ApoHarness
    → AudiodgMonitor.Begin() → COM/APO call → AudiodgMonitor.DetectedCrash()
    → Classifier.Classify() → VerdictResult → PrintVerdict()
```

## Adding new probes

1. Create a `.yml` file in `probes/`
2. Set `api:`, `interface:`, `method:` to identify the target
3. Define `params:` with type + strategy for each parameter you want to fuzz
4. List `expect:` outcomes (the classifier uses these for Clean vs Suspicious decisions)
5. Run with `--dir probes\` or single-file mode

### Example: fuzzing a new WASAPI method

```yaml
name: "My custom probe"
api: WASAPI
interface: IAudioClient
method: GetDevicePeriod
platform: "Win11 24H2"
params:
  - name: SomeParam
    type: REFERENCE_TIME
    strategy: [BoundaryMin, BoundaryMax, NegativeValue]
expect:
  - S_OK
  - unexpected_hresult
  - process_crash
```

## Project structure

```
AudioDGFuzz/
├── CMakeLists.txt              # MSVC build config
├── README.md                   # This file
├── probes/                     # YAML probe definitions
│   ├── IAudioClient_init.yml   # IAudioClient::Initialize format/period fuzzing
│   ├── IAudioClient_buffer.yml # GetBuffer/ReleaseBuffer size fuzzing
│   ├── WAVEFORMATEX_negotiation.yml # IsFormatSupported exhaustive fuzzing
│   └── APO_chain.yml           # Direct APO APOProcess PCM fuzzing
└── src/
    ├── main.cpp                # CLI entry point, orchestrator
    ├── config/
    │   ├── probe_loader.hpp    # Minimal YAML parser + ProbeConfig struct
    │   └── probe_loader.cpp
    ├── com/
    │   ├── wasapi_client.hpp/.cpp   # WASAPI init, IAudioClient wrapper
    │   └── apo_harness.hpp/.cpp     # Direct APO CoCreateInstance + APOProcess
    ├── mutator/
    │   ├── format_mutator.hpp/.cpp  # WAVEFORMATEXTENSIBLE mutation engine
    │   └── pcm_mutator.hpp/.cpp     # Raw PCM buffer mutation engine
    ├── monitor/
    │   └── audiodg_monitor.hpp/.cpp # audiodg.exe lifecycle tracking
    └── verdict/
        └── classifier.hpp/.cpp     # Result classification logic
```

All code lives under `namespace audiodgfuzz`. No external dependencies beyond Windows SDK.
