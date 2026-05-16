# W32KFuzz

Targeted win32k syscall verifier. You describe the hypothesis in YAML — it confirms or denies.

Not a blind fuzzer. Not a monitor. A **verifier**.

---

## Concept

```
You:   "I think NtGdiExtTextOutW overflows pool when cbCount = INT32_MAX"
Tool:  calls syscall with 12 boundary values around INT32_MAX
       monitors ETW + kernel VA access in real-time
       outputs: [!!!] CONFIRMED POOL CORRUPTION / [ ] ok
```

---

## Usage

```bash
# Run as SYSTEM
psexec -s -i W32KFuzz.exe

# Single probe
W32KFuzz.exe probes\NtUserTransformPoint.yml

# All probes
W32KFuzz.exe --dir probes\

# List available probes
W32KFuzz.exe --list probes\
```

---

## Probe Format

```yaml
name: "NtUserTransformPoint kernel R/W primitive"
syscall: 0x15AD
platform: "Win11 24H2"
description: >
  probe-then-use mismatch: puVar2 for probe, param_1 for actual R/W

params:
  - name: param_1
    type: LPPOINT
    value: "0"
    strategy: [KernelAddress, GuardPage]

expect:
  - kernel_write
```

---

## Fuzz Strategies

| Strategy | Values generated |
|----------|-----------------|
| `IntegerOverflow` | INT32_MAX, UINT32_MAX, INT64_MAX and ±1 variants |
| `Underflow` | 0, 1, -1, 2 |
| `SignedUnsigned` | sign boundary values |
| `TruncationBait` | values where lower32 ≠ full64 |
| `KernelAddress` | 0xFFFF800000000000, MmUserProbeAddress ±1 |
| `GuardPage` | MmUserProbeAddress exact and neighbors |
| `NullPage` | 0x0 through 0x1000 |
| `SizePlusOne` | base+1, base+7, base+8, 48-byte buffer variants |
| `SizeTimesTwo` | DPI-style doubling, 2047/2048 boundary |
| `InvalidHandle` | 0xDEADBEEF, closed handles, 0, -1 |

---

## Included Probes

| File | Syscall | Finding |
|------|---------|---------|
| `NtUserTransformPoint.yml` | 0x15AD | Kernel R/W via probe-then-use mismatch |
| `NtGdiExtTextOutW.yml` | 0x1324 | Pool overflow via dead check + direct memcpy |
| `NtGdiExtTextOutW_truncation.yml` | 0x1324 | Pointer truncation size corruption variant |
| `securekernel_sscall_0x2.yml` | 0x0002 | VTL1 controlled stack overflow (2047→48 byte) |
| `gpu_migration_ioctl.yml` | 0x226480 | Live Migration size corruption via int32 truncation |

---

## Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

---

## Verdict Output

```
[!!!] CONFIRMED KERNEL WRITE   — kernel VA access with STATUS_SUCCESS
[!!!] CONFIRMED CORRUPTION     — pool/heap corruption event
[!!!] CONFIRMED CRASH          — exception during syscall
[ ! ] SUSPICIOUS               — anomaly, manual review needed
[ ? ] UNEXPECTED STATUS        — non-standard NTSTATUS
[   ] ok                       — no anomaly
```

---

*SYSTEM privileges required. For legitimate security research only.*
