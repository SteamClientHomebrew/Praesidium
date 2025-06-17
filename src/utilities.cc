#include <string>
#include <algorithm>
#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <algorithm>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

/** 
 * Creates a snapshot of all processes in the system.
 * 
 * @return A handle to the process snapshot, or INVALID_HANDLE_VALUE on failure.
 */
HANDLE CreateProcessSnapshot() {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

/** 
 * Finds a process by its PID in the snapshot.
 * 
 * @param hSnapshot The handle to the process snapshot.
 * @param targetPID The PID of the process to find.
 * @param pe A reference to a PROCESSENTRY32W structure to fill with process information.
 * @return True if the process is found, false otherwise.
 */
bool FindProcessByPID(HANDLE hSnapshot, DWORD targetPID, PROCESSENTRY32W& pe) {
    if (!Process32FirstW(hSnapshot, &pe)) return false;
    
    do {
        if (pe.th32ProcessID == targetPID) return true;
    } while (Process32NextW(hSnapshot, &pe));
    
    return false;
}

/** 
 * Retrieves the parent process ID of the current process.
 * 
 * @return The parent process ID, or 0 if it cannot be determined.
 */
DWORD GetCurrentProcessParentPID() {
    HANDLE hSnapshot = CreateProcessSnapshot();
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD currentPID = GetCurrentProcessId();
    DWORD parentPID = 0;
    
    if (FindProcessByPID(hSnapshot, currentPID, pe)) {
        parentPID = pe.th32ParentProcessID;
    }
    
    CloseHandle(hSnapshot);
    return parentPID;
}

/** 
 * Retrieves the name of a process by its PID.
 * 
 * @param pid The PID of the process.
 * @return The name of the process, or an empty string if it cannot be determined.
 */
std::wstring GetProcessNameByPID(DWORD pid) {
    if (pid == 0) return {};
    
    HANDLE hSnapshot = CreateProcessSnapshot();
    if (hSnapshot == INVALID_HANDLE_VALUE) return {};  
    
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    std::wstring processName = L"";
    
    if (FindProcessByPID(hSnapshot, pid, pe)) {
        processName = std::wstring(pe.szExeFile);
    }
    
    CloseHandle(hSnapshot);
    return processName;
}

/** 
 * Retrieves the name of the parent process of the current process.
 * 
 * @return The name of the parent process, or an empty string if it cannot be determined.
 */
std::wstring GetParentProcessName() {
    DWORD parentPID = GetCurrentProcessParentPID();
    return GetProcessNameByPID(parentPID);
}

/** 
 * Extracts the filename from a full path.
 * 
 * @param fullPath The full path to extract the filename from.
 * @return The filename extracted from the full path.
 */
std::wstring ExtractFilenameFromPath(const std::wstring& fullPath) {
    size_t pos = fullPath.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? fullPath : fullPath.substr(pos + 1);
}

/** 
 * Converts a string to lowercase.
 * 
 * @param str The string to convert.
 * @return The lowercase version of the string.
 */
std::wstring ToLowerCase(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

/** 
 * Retrieves the name of the current process.
 * 
 * @return The name of the current process, or an empty string if it cannot be determined.
 */
std::wstring GetCurrentProcessName() {
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return {};
    
    std::wstring fullPath(path);
    std::wstring filename = ExtractFilenameFromPath(fullPath);
    return ToLowerCase(filename);
}

/** 
 * Parses the command line arguments of the current process.
 * 
 * @return A vector of strings containing the command line arguments.
 */
std::vector<std::string> ParseCommandLineArgs() {
    std::vector<std::string> args;
    
    LPWSTR* argv;
    int argc;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if (argv == nullptr) return args;
    
    for (int i = 0; i < argc; ++i) {
        std::wstring warg(argv[i]);
        std::string arg(warg.begin(), warg.end());
        args.push_back(arg);
    }
    
    LocalFree(argv);
    return args;
}

/** 
 * Checks if a specific command line argument exists.
 * 
 * @param targetArg The argument to check for.
 * @return True if the argument exists, false otherwise.
 */
bool HasCommandLineArg(const std::string& targetArg) {
    std::vector<std::string> args = ParseCommandLineArgs();
    
    for (const auto& arg : args) 
        if (arg == targetArg) return true;
    
    return false;
}

/** 
 * Checks if the application is running in developer mode.
 * Developer mode is indicated by the presence of the "-dev" command line argument.
 * 
 * @return True if in developer mode, false otherwise.
 */
BOOL IsDeveloperMode() {
    return HasCommandLineArg("-dev");
}

/** 
 * Converts a wide string to a UTF-8 encoded string.
 * 
 * @param wstr The wide string to convert.
 * @return The UTF-8 encoded string.
 */
std::string WideStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) return {};
    
    std::string result(len - 1, 0); 
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

/** 
 * Finds a command line argument that starts with a specific prefix.
 * 
 * @param prefix The prefix to search for.
 * @return The argument string if found, or an empty string if not found.
 */
std::string FindArgWithPrefix(const std::string& prefix) {
    std::wstring cmdLineW = GetCommandLineW();
    std::string cmdLine = WideStringToUTF8(cmdLineW);
    
    size_t pos = cmdLine.find(prefix);
    if (pos == std::string::npos) return {};
    
    return cmdLine.substr(pos + prefix.length());
}

/** 
 * Extracts a quoted path from a string starting at a specific position.
 * 
 * @param str The string to search in.
 * @param startPos The position to start searching from.
 * @return The extracted path, or an empty string if not found.
 */
std::string ExtractQuotedPath(const std::string& str, size_t startPos) {
    if (startPos >= str.length() || str[startPos] != '"') return {};
    
    size_t endPos = str.find('"', startPos + 1);
    if (endPos == std::string::npos) return {};

    return str.substr(startPos + 1, endPos - startPos - 1);
}

/** 
 * Extracts an unquoted path from a string starting at a specific position.
 * 
 * @param str The string to search in.
 * @param startPos The position to start searching from.
 * @return The extracted path, or an empty string if not found.
 */
std::string ExtractUnquotedPath(const std::string& str, size_t startPos) {
    size_t endPos = startPos;
    
    while (endPos < str.length()) {
        if (str.substr(endPos, 4) == ".exe") { endPos += 4; break; }
        if (str[endPos] == ' ' && endPos + 1 < str.length() && str[endPos + 1] == '-') break;
        if (endPos == str.length() - 1) { endPos++; break; }
          
        endPos++;
    }
    
    return str.substr(startPos, endPos - startPos);
}

/** 
 * Extracts a path from a command line argument string.
 * 
 * @param argStr The argument string to extract the path from.
 * @return The extracted path, or an empty string if not found.
 */
std::string ExtractPathFromArg(const std::string& argStr) {
    if (argStr.empty()) return {};
    return argStr[0] == '"' ? ExtractQuotedPath(argStr, 0) : ExtractUnquotedPath(argStr, 0);
}

/** 
 * Retrieves the Steam installation path from the command line arguments.
 * 
 * The path is expected to be provided with the "-steampath=" prefix.
 * 
 * @return The Steam installation path, or an empty string if not found.
 */
std::string GetSteamPath() {
    std::string steamPathArg = FindArgWithPrefix("-steampath=");
    return ExtractPathFromArg(steamPathArg);
}

/** 
 * Checks if the current process is "steamwebhelper.exe" and its parent is "steam.exe".
 * 
 * @return True if the current process is steamwebhelper.exe and its parent is steam.exe, false otherwise.
 */
BOOL IsSteamWebHelper() {
    std::wstring currentProc = GetCurrentProcessName();
    std::wstring parentProc = GetParentProcessName();
    std::wstring parentProcLower = ToLowerCase(parentProc);
    
    return (currentProc == L"steamwebhelper.exe" && parentProcLower == L"steam.exe");
}