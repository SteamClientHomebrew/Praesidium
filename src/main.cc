#include <winsock2.h>
#include <windows.h>
#include <MinHook.h>
#include <iostream>
#include <string>
#include <ws2tcpip.h>
#include <filesystem>
#include <TlHelp32.h>
#include <algorithm>
#include <sstream>
#include <iphlpapi.h>
#include <vector>
#include <psapi.h>
#include <socket_trace.h>
#include <utilities.h>

typedef INT (WINAPI* receiveFunctionPtr_t)(SOCKET s, PCHAR buf, INT len, INT flags);
receiveFunctionPtr_t originalRecvPtr = nullptr;

namespace HttpResponse {
    static const std::string HTML_TEMPLATE = R"(
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <title>403 Forbidden</title>
            </head>
            <body>
                <h1>403 Forbidden</h1>
                <p>Forbidden: Millennium has blocked you from accessing this resource. Developer tools are only available when in -dev mode to help protect users from potential attacks.</p>
            </body>
        </html>
    )";

    /** 
     * Creates a 403 Forbidden HTTP response.
     * This response is sent when a connection is blocked due to security checks.
     * Rqw HTTP is so ugly lol.
     * 
     * @return A string containing the complete HTTP response.
     */
    std::string CreateForbiddenResponse() {
        return "HTTP/1.1 403 Forbidden\r\n"
               "Content-Type: text/html\r\n"
               "Content-Length: " + std::to_string(HTML_TEMPLATE.size()) + "\r\n"
               "Connection: close\r\n"
               "Server: CEFSecureHook\r\n\r\n" + HTML_TEMPLATE;
    }
}

namespace SecurityCheck {
    /** 
     * Check if the current process is a Steam web helper.
     * This is determined by checking the command line arguments for "steamwebhelper.exe" and ensuring the parent process is "steam.exe".
     */
    bool IsSteamProcess(SOCKET s) {
        const std::string processName = SocketProcessResolver::GetRemoteProcessFullPath(s);
        const static std::string steamPath = GetSteamPath();
        
        /** Extra check with 'steam.exe' just in case the command line args were hooked and replaced */
        return (processName == steamPath && processName.find("steam.exe") != std::string::npos);
    }
    
    /**  
     * Block the connection by sending a 403 Forbidden response and closing the socket.
     */
    void BlockConnection(SOCKET s) {
        std::string response = HttpResponse::CreateForbiddenResponse();
        send(s, response.c_str(), response.size(), 0);
        closesocket(s);
        WSASetLastError(WSAECONNABORTED);
    }
}

/**
 * Hooked recv function that intercepts socket connections.
 * If the connection is not from a Steam process, it blocks the connection and returns an error.
 * We use this as a security measure to prevent unauthorized access to the Steam through Millennium. 
 * 
 * @param s The socket to receive data from.
 * @param buf The buffer to store received data.
 * @param len The length of the buffer.
 * @param flags Flags for the recv function.
 * @return The number of bytes received, or SOCKET_ERROR on failure.
 */
INT WINAPI HookedRecv(SOCKET s, PCHAR buf, INT len, INT flags) {
    int result = originalRecvPtr(s, buf, len, flags);
    if (result <= 0) return result;
    
    /** We want Millennium to still be able to form an internal connection */
    if (SecurityCheck::IsSteamProcess(s)) return result;
    
    SecurityCheck::BlockConnection(s);
    return SOCKET_ERROR;
}

/** 
 * HookManager namespace to manage the hooking of the recv function.
 * This namespace encapsulates the MinHook initialization, hook creation, and cleanup.
 */
namespace HookManager {
    BOOL Initialize() {
        if (MH_Initialize() != MH_OK) return FALSE;
        
        /** Under the hood, CEF fortunately relies on ws2 to manage connections to the protocol */
        HMODULE socketLib = GetModuleHandleW(L"ws2_32.dll");
        if (!socketLib) return FALSE;
        
        /** recv is all we are concerned with here, as we can use it to block requests. */
        FARPROC recvFunc = GetProcAddress(socketLib, "recv");
        if (recvFunc) {
            MH_CreateHook((LPVOID)recvFunc, (LPVOID)HookedRecv, (LPVOID*)&originalRecvPtr);
            MH_EnableHook((LPVOID)recvFunc);
        }
        
        return TRUE;
    }
    
    /** Cleanup hooks before unloading, although it probably doesn't matter much. */
    VOID Cleanup() {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    /** 
     * Steam actually spawns 3 different web helpers at startup, but we are only concerned with 1 of them (the one owned by steam.exe as it handles remote debugging) 
     * We only want to hook the recv function if we are not in developer mode, because we want to keep it normal in developer mode.
    */
    if (!IsSteamWebHelper() || IsDeveloperMode()) return TRUE;
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            /** Speed up library by removing THREADING calls to DllMain */
            DisableThreadLibraryCalls(hModule);
            HookManager::Initialize();
            break;
        case DLL_PROCESS_DETACH:
            HookManager::Cleanup();
            break;
    }
    
    return TRUE;
}