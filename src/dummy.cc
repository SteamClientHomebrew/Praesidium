#include <windows.h>

static HMODULE hPraesidium = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        hPraesidium = LoadLibraryA("./praesidium.dll");
        break;
    case DLL_PROCESS_DETACH:
        if (hPraesidium) {
            FreeLibrary(hPraesidium);
            hPraesidium = NULL;
        }
        break;
    }
    return TRUE;
}