#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <vector>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class SocketProcessResolver {
private:
    static void FreeProcessPath(char* path);
    static char* GetExecutableNameFromPID(DWORD processId);
    static char* AllocateString(const char* str);
    static HANDLE OpenProcessForQuery(DWORD processId);
    static BOOL GetProcessPath(HANDLE hProcess, char* processPath, DWORD pathSize);
    static BOOL IsDevicePath(const char* path);
    static char* ConvertSingleDevicePath(const char* devicePath, const char* deviceName, const char* driveLetter);
    static char* TryConvertDevicePath(const char* devicePath, const char* drive);
    static char* ConvertDevicePathToDosPath(char* devicePath);
    static char* ProcessDevicePathIfNeeded(char* fullPath);
    static int GetPeerAddress(SOCKET s, struct sockaddr_in* remoteAddr);
    static PMIB_TCPTABLE_OWNER_PID GetTcpTable(DWORD* tableSize);
    static void GetLocalSocketInfo(SOCKET s, DWORD* localPort, DWORD* localIP);
    static void ExtractRowInfo(const MIB_TCPROW_OWNER_PID* row, DWORD* tableLocalPort, DWORD* tableLocalIP, DWORD* tableRemotePort, DWORD* tableRemoteIP);
    static BOOL IsMatchingConnection(DWORD tableLocalPort, DWORD tableLocalIP, DWORD tableRemotePort, DWORD tableRemoteIP, DWORD ourLocalPort, DWORD ourLocalIP, DWORD remotePort, DWORD remoteIP) ;
    static char* FindMatchingProcess(PMIB_TCPTABLE_OWNER_PID pTcpTable, DWORD remotePort, DWORD remoteIP, DWORD ourLocalPort, DWORD ourLocalIP);

public:
    static char* GetRemoteProcessFullPath(SOCKET s);
};