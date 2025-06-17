#include <socket_trace.h>

// Helper function to allocate a string and copy the content
char* SocketProcessResolver::AllocateString(const char* str) {
    char* result = (char*)malloc(strlen(str) + 1);
    strcpy(result, str);
    return result;
}

/**
 * Open a process handle with the necessary permissions to query process information.
 * @param processId The ID of the process to open.
 * @return A handle to the process, or NULL if it fails.
 * This function attempts to open the process with both PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_QUERY_INFORMATION.
 * 
 * from what it seems, PROCESS_QUERY_LIMITED_INFORMATION is used for Windows 10 and later, while PROCESS_QUERY_INFORMATION is used for earlier versions.
 * likely needs further testing to determine if both are needed.
 */
HANDLE SocketProcessResolver::OpenProcessForQuery(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    }
    return hProcess;
}

/**
 * Get the full path of the executable for a given process handle.
 * 
 * @param hProcess The handle to the process.
 * @param processPath A buffer to receive the process path.
 * @param pathSize The size of the buffer.
 * 
 * @return TRUE if successful, FALSE otherwise.
 */
BOOL SocketProcessResolver::GetProcessPath(HANDLE hProcess, char* processPath, DWORD pathSize) {
    BOOL success = QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize);
    if (!success) {
        success = GetProcessImageFileNameA(hProcess, processPath, MAX_PATH);
    }
    return success;
}

/**
 * Check if the given path is a device path.
 * A device path is an internal windows namespace, very similar to unix which is far more familiar with. 
 * 
 * @param path The path to check.
 * @return TRUE if it is a device path, FALSE otherwise.
 */
BOOL SocketProcessResolver::IsDevicePath(const char* path) {
    return strncmp(path, "\\Device\\", 8) == 0;
}

/** 
 * Convert a single device path to a DOS path. DOS paths are the traditional file system paths used in Windows, such as "C:\\".
 * 
 * @param devicePath The device path to convert.
 * @param deviceName The name of the device.
 * @param driveLetter The drive letter to prepend.
 * @return A new string with the converted path, or NULL if conversion fails.
 */
char* SocketProcessResolver::ConvertSingleDevicePath(const char* devicePath, const char* deviceName, const char* driveLetter) {
    size_t deviceLen = strlen(deviceName);
    if (strncmp(devicePath, deviceName, deviceLen) != 0) {
        return NULL;
    }
    
    size_t remainingLen = strlen(devicePath) - deviceLen;
    char* newPath = (char*)malloc(3 + remainingLen + 1);
    strcpy(newPath, driveLetter);
    strcat(newPath, devicePath + deviceLen);
    return newPath;
}

/**  
 * Try to convert a device path to a DOS path using the specified drive letter.
 * 
 * @param devicePath The device path to convert.
 * @param drive The drive letter to use for conversion.
 * @return A new string with the converted path, or NULL if conversion fails.
 */
char* SocketProcessResolver::TryConvertDevicePath(const char* devicePath, const char* drive) {
    char deviceName[MAX_PATH];
    char driveLetter[4] = {drive[0], ':', '\0'};
    
    if (!QueryDosDeviceA(driveLetter, deviceName, MAX_PATH)) {
        return NULL;
    }
    
    return SocketProcessResolver::ConvertSingleDevicePath(devicePath, deviceName, driveLetter);
}

/** 
 * Convert a device path to a DOS path by checking all available drives.
 * 
 * @param devicePath The device path to convert.
 * @return A new string with the converted path, or the original devicePath if conversion fails.
 */
char* SocketProcessResolver::ConvertDevicePathToDosPath(char* devicePath) {
    char dosPath[MAX_PATH];
    if (!GetLogicalDriveStringsA(sizeof(dosPath), dosPath)) {
        return devicePath;
    }
    
    char* drive = dosPath;
    while (*drive) {
        char* converted = SocketProcessResolver::TryConvertDevicePath(devicePath, drive);
        if (converted) {
            free(devicePath);
            return converted;
        }
        drive += strlen(drive) + 1;
    }
    
    return devicePath;
}

/** 
 *  Process the device path if needed, converting it to a DOS path if it is a device path.
 * 
 * @param fullPath The full path to process.
 * @return A new string with the processed path, or the original fullPath if no conversion is needed.
 */
char* SocketProcessResolver::ProcessDevicePathIfNeeded(char* fullPath) {
    if (!SocketProcessResolver::IsDevicePath(fullPath)) {
        return fullPath;
    }
    return ConvertDevicePathToDosPath(fullPath);
}

/** 
 * Get the executable name from a process ID.
 * 
 * From a little bit of research, it seems that the process ID 0 is the system process, and 4 is the system idle process.
 * Could be wrong, but either way no regular process should have these IDs.
 */
char* SocketProcessResolver::GetExecutableNameFromPID(DWORD processId) {
    if (processId == 0 || processId == 4) {
        return AllocateString("System");
    }
    
    HANDLE hProcess = OpenProcessForQuery(processId);
    if (!hProcess) {
        return AllocateString("Unknown");
    }
    
    char processPath[MAX_PATH] = {0};
    DWORD pathSize = MAX_PATH;
    BOOL success = GetProcessPath(hProcess, processPath, pathSize);
    CloseHandle(hProcess);
    
    if (!success || strlen(processPath) == 0) {
        return AllocateString("Unknown");
    }
    
    char* fullPath = AllocateString(processPath);
    return ProcessDevicePathIfNeeded(fullPath);
}

/** 
 * Get the peer address of a socket. A peer address is the address of the remote endpoint to which the socket is connected.
 * MS doesn't have great documentation on this, but it seems to be a common function used to get the remote address of a socket.
 * 
 * @param s The socket to query.
 * @param remoteAddr A pointer to a sockaddr_in structure to receive the remote address.
 * @return 0 on success, or an error code on failure.
 */
int SocketProcessResolver::GetPeerAddress(SOCKET s, struct sockaddr_in* remoteAddr) {
    int addrLen = sizeof(*remoteAddr);
    return getpeername(s, (struct sockaddr*)remoteAddr, &addrLen);
}

/** 
 * Get the TCP table with process IDs. This function retrieves the TCP table that includes the owning process ID for each connection.
 * Doc: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid (same thing as MIB_TCPTABLE_OWNER_PID, just a pointer to it).
 * 
 * @param tableSize A pointer to a DWORD that will receive the size of the table.
 * @return A pointer to the MIB_TCPTABLE_OWNER_PID structure, or NULL on failure.
 */
PMIB_TCPTABLE_OWNER_PID SocketProcessResolver::GetTcpTable(DWORD* tableSize) {
    DWORD result = GetExtendedTcpTable(NULL, tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return NULL;
    }
    
    BYTE* buffer = (BYTE*)malloc(*tableSize);
    if (!buffer) {
        return NULL;
    }
    
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)buffer;
    result = GetExtendedTcpTable(pTcpTable, tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        free(buffer);
        return NULL;
    }
    
    return pTcpTable;
}

/** 
 * Get the local socket information, including the local port and IP address.
 * 
 * @param s The socket to query.
 * @param localPort A pointer to a DWORD to receive the local port.
 * @param localIP A pointer to a DWORD to receive the local IP address.
 */
void SocketProcessResolver::GetLocalSocketInfo(SOCKET s, DWORD* localPort, DWORD* localIP) {
    struct sockaddr_in ourLocalAddr = {0};
    int ourAddrLen = sizeof(ourLocalAddr);
    getsockname(s, (struct sockaddr*)&ourLocalAddr, &ourAddrLen);
    *localPort = ntohs(ourLocalAddr.sin_port);
    *localIP = ntohl(ourLocalAddr.sin_addr.s_addr);
}

/** 
 * Extract the local and remote port and IP address from a TCP row. A TCP row contains information about a TCP connection, including the local and remote addresses and ports.
 * https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
 * 
 * @param row The TCP row to extract information from.
 * @param tableLocalPort A pointer to a DWORD to receive the local port.
 * @param tableLocalIP A pointer to a DWORD to receive the local IP address.
 * @param tableRemotePort A pointer to a DWORD to receive the remote port.
 * @param tableRemoteIP A pointer to a DWORD to receive the remote IP address.
 */
void SocketProcessResolver::ExtractRowInfo(const MIB_TCPROW_OWNER_PID* row, DWORD* tableLocalPort, DWORD* tableLocalIP, DWORD* tableRemotePort, DWORD* tableRemoteIP) {
    *tableLocalPort = ntohs((USHORT)row->dwLocalPort);
    *tableLocalIP = ntohl(row->dwLocalAddr);
    *tableRemotePort = ntohs((USHORT)row->dwRemotePort);
    *tableRemoteIP = ntohl(row->dwRemoteAddr);
}

/** 
 * Check if the connection matches the given parameters. This function checks if the local and remote ports and IP addresses match the specified values.
 * 
 * @param tableLocalPort The local port from the TCP table.
 * @param tableLocalIP The local IP address from the TCP table.
 * @param tableRemotePort The remote port from the TCP table.
 * @param tableRemoteIP The remote IP address from the TCP table.
 * @param ourLocalPort The local port of our socket.
 * @param ourLocalIP The local IP address of our socket.
 * @param remotePort The remote port we are looking for.
 * @param remoteIP The remote IP address we are looking for.
 * @return TRUE if the connection matches, FALSE otherwise.
 */
BOOL SocketProcessResolver::IsMatchingConnection(DWORD tableLocalPort, DWORD tableLocalIP, DWORD tableRemotePort, DWORD tableRemoteIP, DWORD ourLocalPort, DWORD ourLocalIP, DWORD remotePort, DWORD remoteIP) {
    return (tableRemotePort == ourLocalPort && tableRemoteIP == ourLocalIP && tableLocalPort == remotePort &&  tableLocalIP == remoteIP);
}

/** 
 * Find the matching process in the TCP table based on the remote port and IP address, as well as our local port and IP address.
 * 
 * @param pTcpTable The TCP table to search.
 * @param remotePort The remote port we are looking for.
 * @param remoteIP The remote IP address we are looking for.
 * @param ourLocalPort The local port of our socket.
 * @param ourLocalIP The local IP address of our socket.
 * @return The full path of the executable for the matching process, or NULL if no match is found.
 */
char* SocketProcessResolver::FindMatchingProcess(PMIB_TCPTABLE_OWNER_PID pTcpTable, DWORD remotePort, DWORD remoteIP, DWORD ourLocalPort, DWORD ourLocalIP) {
    DWORD i;
    for (i = 0; i < pTcpTable->dwNumEntries; i++) {
        const MIB_TCPROW_OWNER_PID* row = &pTcpTable->table[i];
        
        DWORD tableLocalPort, tableLocalIP, tableRemotePort, tableRemoteIP;
        ExtractRowInfo(row, &tableLocalPort, &tableLocalIP, &tableRemotePort, &tableRemoteIP);
        
        if (!IsMatchingConnection(tableLocalPort, tableLocalIP, tableRemotePort, tableRemoteIP, ourLocalPort, ourLocalIP, remotePort, remoteIP)) {
            continue;
        }
    
        return GetExecutableNameFromPID(row->dwOwningPid);
    }
    
    return NULL;
}

/** 
 * Get the full path of the executable for the remote process associated with a socket.
 * 
 * @param s The socket to query.
 * @return The full path of the remote process, or "Unknown" if it cannot be determined.
 */
char* SocketProcessResolver::GetRemoteProcessFullPath(SOCKET s) {
    struct sockaddr_in remoteAddr = {0};
    if (GetPeerAddress(s, &remoteAddr) != 0) {
        return AllocateString("Unknown");
    }
    
    DWORD tableSize = 0;
    PMIB_TCPTABLE_OWNER_PID pTcpTable = GetTcpTable(&tableSize);
    if (!pTcpTable) {
        return AllocateString("Unknown");
    }
    
    DWORD remotePort = ntohs(remoteAddr.sin_port);
    DWORD remoteIP = ntohl(remoteAddr.sin_addr.s_addr);
    
    DWORD ourLocalPort, ourLocalIP;
    GetLocalSocketInfo(s, &ourLocalPort, &ourLocalIP);
    
    char* result = FindMatchingProcess(pTcpTable, remotePort, remoteIP, ourLocalPort, ourLocalIP);
    free(pTcpTable);
    
    if (result) return result;
    return AllocateString("Unknown");
}

/* Helper function to free the returned strings */
void SocketProcessResolver::FreeProcessPath(char* path) {
    if (path) free(path);  
}