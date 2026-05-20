#include "monitor/audiodg_monitor.hpp"

#include <iostream>
#include <sstream>

namespace audiodgfuzz {

// -----------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------
AudiodgMonitor::AudiodgMonitor() = default;

// -----------------------------------------------------------------------
// FindPidByName — enumerate processes via toolhelp snapshot
// -----------------------------------------------------------------------
DWORD AudiodgMonitor::FindPidByName(const wchar_t* process_name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, process_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// -----------------------------------------------------------------------
// FindProcess — locate audiodg.exe
// -----------------------------------------------------------------------
bool AudiodgMonitor::FindProcess() {
    last_pid_ = FindPidByName(L"audiodg.exe");
    return last_pid_ != 0;
}

// -----------------------------------------------------------------------
// Check — full status right now
// -----------------------------------------------------------------------
AudiodgStatus AudiodgMonitor::Check() {
    AudiodgStatus status{};
    DWORD pid = FindPidByName(L"audiodg.exe");

    if (pid == 0) {
        // Not running — was it our tracked instance?
        status.alive = false;
        status.pid = last_pid_;
        // Try to get exit code from the old handle
        if (last_handle_) {
            DWORD code = STILL_ACTIVE;
            GetExitCodeProcess(last_handle_, &code);
            status.exit_code = (code == STILL_ACTIVE) ? 0 : code;
        }
        return status;
    }

    status.alive = true;
    status.pid = pid;

    // Open to get a handle for later exit-code queries
    if (last_handle_)
        CloseHandle(last_handle_);
    last_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!last_handle_)
        last_handle_ = OpenProcess(SYNCHRONIZE, FALSE, pid);

    return status;
}

// -----------------------------------------------------------------------
// Begin — capture state before test call
// -----------------------------------------------------------------------
void AudiodgMonitor::Begin() {
    last_pid_ = FindPidByName(L"audiodg.exe");
    if (last_pid_ > 0 && !last_handle_) {
        last_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                                   FALSE, last_pid_);
        if (!last_handle_)
            last_handle_ = OpenProcess(SYNCHRONIZE, FALSE, last_pid_);
    }
}

// -----------------------------------------------------------------------
// DetectedCrash — audiodg died since Begin()
// -----------------------------------------------------------------------
bool AudiodgMonitor::DetectedCrash() {
    if (last_pid_ == 0)
        return false; // wasn't running before either

    DWORD current_pid = FindPidByName(L"audiodg.exe");
    if (current_pid == 0 && current_pid != last_pid_) {
        // Was running before, not running now — crashed
        if (last_handle_) {
            DWORD code = STILL_ACTIVE;
            GetExitCodeProcess(last_handle_, &code);
            CloseHandle(last_handle_);
            last_handle_ = nullptr;
            std::cerr << "[monitor] audiodg.exe crash detected! PID "
                      << last_pid_ << " exited with code 0x"
                      << std::hex << code << std::dec << "\n";
        }
        return true;
    }
    return false;
}

// -----------------------------------------------------------------------
// DetectedRestart — PID changed (audiosrv restarted audiodg)
// -----------------------------------------------------------------------
bool AudiodgMonitor::DetectedRestart() {
    if (last_pid_ == 0)
        return false; // no prior baseline

    DWORD current_pid = FindPidByName(L"audiodg.exe");
    if (current_pid != 0 && current_pid != last_pid_) {
        std::cerr << "[monitor] audiodg.exe restart detected: PID "
                  << last_pid_ << " -> " << current_pid
                  << " (possible panic recovery)\n";
        last_pid_ = current_pid;
        if (last_handle_) CloseHandle(last_handle_);
        last_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                                   FALSE, current_pid);
        return true;
    }
    return false;
}

} // namespace audiodgfuzz
