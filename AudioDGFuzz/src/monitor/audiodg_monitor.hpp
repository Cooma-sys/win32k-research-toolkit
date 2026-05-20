#pragma once
#ifndef AUDIODGFUZZ_AUDIODG_MONITOR_HPP
#define AUDIODGFUZZ_AUDIODG_MONITOR_HPP

#include <windows.h>
#include <tlhelp32.h>
#include <string>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Current status of audiodg.exe process
// -----------------------------------------------------------------------
struct AudiodgStatus {
    bool   alive = false;
    DWORD  pid    = 0;
    DWORD  exit_code = 0; // set if !alive
};

// -----------------------------------------------------------------------
// AudiodgMonitor — tracks audiodg.exe lifecycle via process snapshots.
// Used to detect crashes or forced restarts between test calls.
// -----------------------------------------------------------------------
class AudiodgMonitor {
public:
    AudiodgMonitor();

    // Find audiodg.exe PID via CreateToolhelp32Snapshot
    bool FindProcess();

    // Check current status right now
    AudiodgStatus Check();

    // Snapshot state before a test call
    void Begin();

    // After call: did audiodg crash since Begin()?
    bool DetectedCrash();

    // After call: was audiodg restarted (PID changed) by audiosrv?
    bool DetectedRestart();

private:
    DWORD last_pid_     = 0;
    HANDLE last_handle_ = nullptr;

    static DWORD FindPidByName(const wchar_t* process_name);
};

} // namespace audiodgfuzz

#endif // AUDIODGFUZZ_AUDIODG_MONITOR_HPP
