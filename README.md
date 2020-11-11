# simple-dll-injector
i wrote **super** simple dll injector running on windows 10(only security research purposed)

main source code is below

```cpp
#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#define DEF_TARGET_DLL  L"C:\\YOUR\\PATH\\FILENAME.dll"
#define DEF_TARGET_PROC L"PROCESSNAME.exe"

// @author r99bbit@github

/* prototype */
bool process_name_to_pid(
    __out DWORD& pid,
    __in const std::wstring& process_name
    );

bool dll_injection(
    __in DWORD pid,
    __in const std::wstring& dll_name
    );


int main()
{
    /* hide terminal */
    HWND hWnd = GetForegroundWindow();
    ShowWindow(hWnd, SW_HIDE);
    DWORD pid = 0;

    std::wstring process_name = DEF_TARGET_PROC;
    std::wstring dll_name = DEF_TARGET_DLL;

    if (process_name_to_pid(pid, process_name)) {
        dll_injection(pid, dll_name);
    }
}

/* get process name via memory scan */
bool process_name_to_pid(
    __out DWORD& pid,
    __in const std::wstring& process_name
    ) {
    bool result = false;
    HANDLE snapshot = nullptr;
    PROCESSENTRY32 entry = {};

    entry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        Process32First(snapshot, &entry);
        do {
            if (!_tcsicmp(process_name.c_str(), entry.szExeFile)) {
                pid = entry.th32ProcessID;
                result = true;
                break;
            }
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
    }

    return result;
}

/* inject dll to target process */
bool dll_injection(
    __in DWORD pid,
    __in const std::wstring& dll_name
    ) {
    bool result = false;

    HANDLE process_handle = nullptr;
    HANDLE thread_handle = nullptr;
    LPVOID remote_buffer = nullptr;
    HMODULE module = {};

    LPTHREAD_START_ROUTINE thread_start_routine = nullptr;

    do {
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (process_handle == nullptr) {
            break;
        }

        remote_buffer = VirtualAllocEx(
                            process_handle, 
                            nullptr, 
                            dll_name.size(), 
                            MEM_COMMIT, 
                            PAGE_READWRITE
                            );
        if (!remote_buffer) {
            break;
        }

        if (!WriteProcessMemory(
                process_handle,
                remote_buffer,
                dll_name.c_str(),
                dll_name.size() * sizeof(wchar_t),
                nullptr
                )) {
            break;
        }

        module = GetModuleHandle(L"kernel32.dll");
        thread_start_routine = (LPTHREAD_START_ROUTINE)GetProcAddress(module, "LoadLibraryW");

        thread_handle = CreateRemoteThread(
                            process_handle, 
                            nullptr, 
                            0, 
                            thread_start_routine, 
                            remote_buffer, 
                            0, 
                            nullptr
                            );

        WaitForSingleObject(thread_handle, INFINITE);

        result = true;

    } while (false);

    CloseHandle(process_handle);
    CloseHandle(thread_handle);

    return result;
}
```