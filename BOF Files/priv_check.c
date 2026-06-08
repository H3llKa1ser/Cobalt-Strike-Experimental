#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINADVAPI  BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINADVAPI  BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT WINADVAPI  BOOL    WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);

/* privileges that are interesting for escalation */
static int is_dangerous(const char* name) {
    static const char* hot[] = {
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
        "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
        "SeTcbPrivilege", "SeCreateTokenPrivilege",
        "SeManageVolumePrivilege", "SeRelabelPrivilege"
    };
    for (int i = 0; i < (int)(sizeof(hot)/sizeof(hot[0])); i++) {
        const char* a = name; const char* b = hot[i];
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) return 1;
    }
    return 0;
}

void go(char* args, int len) {
    HANDLE hToken = NULL;
    DWORD  needed = 0;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken failed: %lu", GetLastError());
        return;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    PTOKEN_PRIVILEGES priv = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!priv) { KERNEL32$CloseHandle(hToken); return; }

    if (ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, priv, needed, &needed)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Token privileges (%lu):", priv->PrivilegeCount);
        for (DWORD i = 0; i < priv->PrivilegeCount; i++) {
            char  name[128]; DWORD nlen = sizeof(name);
            if (ADVAPI32$LookupPrivilegeNameA(NULL, &priv->Privileges[i].Luid, name, &nlen)) {
                DWORD attr = priv->Privileges[i].Attributes;
                const char* state = (attr & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "disabled";
                const char* flag  = is_dangerous(name) ? "  <-- ABUSABLE" : "";
                BeaconPrintf(CALLBACK_OUTPUT, "    %-35s %-9s%s", name, state, flag);
            }
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, priv);
    KERNEL32$CloseHandle(hToken);
}
