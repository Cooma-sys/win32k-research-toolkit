# win32k Research Toolkit

> **Real-time win32k kernel monitoring + hypothesis-driven syscall verification.**  
> Two tools. One goal: find kernel bugs before they find you.

---

## Tools

### W32KSpy — Real-time win32k Event Monitor

Captures **everything** win32k does system-wide through four simultaneous interception layers:

| Layer | What it catches |
|-------|----------------|
| ETW `Microsoft-Windows-Win32k` | System-wide GUI subsystem events |
| ETW `Microsoft-Windows-Threat-Intelligence` | VirtualAlloc, WriteProcessMemory, APC, thread injection |
| Inline hooks on `win32u.dll` | Full argument dump for every `NtUser*` / `NtGdi*` call |
| `InstrumentationCallback` | **All** win32k syscalls 0x1000–0x1FFF, including direct syscall bypasses |

The `InstrumentationCallback` layer is the critical one — it catches callers who bypass the IAT entirely (think `SysWhispers`, manual syscall stubs, or shellcode).

```
psexec -s -i W32KSpy.exe
```

TUI updates in real-time. Filter by process, severity, event type, or keyword.  
`SYSTEM` token events are flagged 🔴 immediately.

---

### W32KFuzz — Hypothesis-Driven Syscall Verifier

**Not a blind fuzzer.** You write a probe YAML describing *what you think is broken*.  
W32KFuzz confirms or denies your hypothesis using mathematically-grounded boundary values.

```yaml
# probes/NtUserTransformPoint.yml
name: "NtUserTransformPoint kernel R/W primitive"
syscall: 0x15AD
platform: "Win11 24H2 (26100.x)"
description: >
  Probe validation uses redirected puVar2 but actual memory access
  uses original param_1. Passing kernel VA bypasses probe and results
  in 8-byte kernel read+write with DPI-scaled value.

params:
  - name: param_1
    type: LPPOINT
    value: "0"
    strategy: [KernelAddress, GuardPage, NullPage]

  - name: param_2
    type: UINT
    value: 0

expect:
  - kernel_write
  - unexpected_status
```

```
W32KFuzz.exe probes\NtUserTransformPoint.yml
W32KFuzz.exe --dir probes\
```

Output:
```
[!!!] CONFIRMED KERNEL WRITE  NtUserTransformPoint (0x15AD)
      STATUS_SUCCESS with kernel VA arg! param_1=0xFFFF800012340000
      Duration: 12ms
```

The mutator covers: `KernelAddress`, `GuardPage`, `NullPage`, `IntegerOverflow`,  
`Underflow`, `SignedUnsigned`, `SizePlusOne` — the exact boundary classes that  
produce real kernel primitives.

---

## Included Probes

| Probe | Syscall | Bug class | Platform |
|-------|---------|-----------|----------|
| `NtUserTransformPoint.yml` | 0x15AD | probe-then-use mismatch | Win11 24H2 |
| `NtGdiExtTextOutW.yml` | 0x1324 | dead check + integer overflow | Win11 24H2 26100.8246 |
| `NtGdiExtTextOutW_truncation.yml` | 0x1324 | size truncation | Win11 24H2 |
| `securekernel_sscall_0x2.yml` | 0x2 | missing bounds check | SecureKernel |
| `gpu_migration_ioctl.yml` | IOCTL | integer truncation | DXGK Live Migration |

---

## Build

**Requirements:** Windows 11, Visual Studio 2022+/2025+/2026+, CMake 3.20+, run as SYSTEM.

```batch
:: W32KSpy
cmake -B W32KSpy/build -S W32KSpy -G "Visual Studio 18 2026" -A x64
cmake --build W32KSpy/build --config Release

:: W32KFuzz
cmake -B W32KFuzz/build -S W32KFuzz -G "Visual Studio 18 2026" -A x64
cmake --build W32KFuzz/build --config Release
```

Or just run `build_all.bat` after setting up VS environment.

> Tested with MSVC 19.50 (VS2026 Preview). The VS generator version depends on your install:
> `Visual Studio 17 2022` / `Visual Studio 18 2026` — check with `cmake --help`.

---

## Architecture

```
W32KSpy
├── src/etw/
│   ├── etw_session.hpp      — ETW session management (win32k + EtwTi + KernelAudit)
│   └── etw_consumer.hpp     — Real-time event consumer + TDH property extraction
├── src/hooks/
│   ├── iat_hook.hpp         — IAT hook for win32u.dll exports
│   ├── inline_hook.hpp      — Trampoline-based inline hook
│   ├── instrumentation_cb.hpp — InstrumentationCallback (catches direct syscalls)
│   └── syscall_monitor.hpp  — Syscall range filter (0x1000–0x1FFF)
├── src/filter/
│   └── interest_filter.hpp  — Severity heuristics + process/event filters
└── src/ui/
    └── tui.hpp              — FTXUI-based real-time terminal UI

W32KFuzz
├── src/config/
│   └── probe_loader.hpp     — YAML probe parser
├── src/mutator/
│   └── smart_mutator.hpp    — Boundary value generator
├── src/caller/
│   └── syscall_stub.hpp     — Direct x64 syscall thunk (no IAT dependency)
├── src/monitor/
│   └── spy_bridge.hpp       — ETW correlation during call
├── src/verdict/
│   └── classifier.hpp       — Result classification (ConfirmedWrite/Crash/Suspicious)
└── probes/                  — YAML hypothesis files
```

---

## Design Philosophy

Most kernel fuzzers throw random bytes at syscalls and wait for a crash.  
**That's not how you find the interesting bugs.**

Real win32k vulnerabilities are subtle:
- A probe uses one pointer, the actual read/write uses another (probe-then-use)
- A bounds check fires on a derived value, not the original attacker-controlled size (dead check)  
- A 32-bit truncation happens 3 function calls deep before the memcpy

W32KFuzz starts from a *hypothesis* — a specific structural weakness you've identified through static analysis or code review. It then systematically verifies whether that weakness produces a usable primitive.

W32KSpy provides the observability layer: you see *exactly* what happens in the kernel during each call — which ETW events fire, which hooks trigger, what the NTSTATUS is.

Together they form a research loop:
```
Static analysis → Form hypothesis → W32KFuzz probe → W32KSpy correlation → Confirm/Deny
```

---

## Usage Notes

- Must run as **SYSTEM**: `psexec -s -i <tool>.exe`
- EtwTi provider requires `SeSystemProfilePrivilege` (SYSTEM has it)
- InstrumentationCallback is process-wide — set it before any suspicious code runs
- W32KFuzz uses direct syscalls — bypasses any usermode hooks on win32u.dll
- Test on a VM. Some probes will trigger BSODs on vulnerable builds.

---

## Related

Dataset of Chain-of-Thought reasoning examples for training LLMs on kernel vulnerability analysis:  
→ **[win32k-cot-dataset](https://github.com/Cooma-sys/win32k-cot-dataset)**

---

## License

MIT — use freely, star if useful, credit appreciated.

---

*For legitimate security research and bug bounty only.*  
*All included probes target publicly known or already-patched vulnerability classes.*
