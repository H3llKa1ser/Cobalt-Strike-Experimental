#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT WINADVAPI BOOL      WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT WINADVAPI BOOL      WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT WINADVAPI BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE   WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT WINBASEAPI LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(void);

#ifndef SC_ENUM_PROCESS_INFO
#define SC_ENUM_PROCESS_INFO 0
#endif

/* Detect an unquoted path that contains a space before the .exe -> hijackable */
static int is_unquoted_with_space(const char* path) {
    if (!path || path[0] == '\0') return 0;
    if (path[0] == '"') return 0;                 /* already quoted - safe */
    /* find first space that occurs before ".exe" */
    const char* p = path;
    while (*p) {
        if (*p == ' ') {
            /* a space exists in an unquoted path; if there's a path separator
               before it, it's a candidate for binary planting */
            const char* q = path;
            while (q < p) { if (*q == '\\') return 1; q++; }
        }
        p++;
    }
    return 0;
}

static int writable_dir_hint(const char* path) {
    /* cheap heuristic: world-writable-ish locations operators should check */
    const char* hits[] = { "\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\", "\\Windows\\Temp\\" };
    for (int i = 0; i < 4; i++) {
        const char* h = hits[i]; const char* p = path;
        for (; *p; p++) {
            const char* a = p; const char* b = h;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*b == 0) return 1;
        }
    }
    return 0;
}

void go(char* args, int len) {
    SC_HANDLE scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenSCManager failed: %lu", KERNEL32$GetLastError());
        return;
    }

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    /* first call sizes the buffer */
    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
        &bytesNeeded, &count, &resume, NULL);

    if (bytesNeeded == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No services / size query failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    LPBYTE buf = (LPBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
    if (!buf) { ADVAPI32$CloseServiceHandle(scm); return; }

    if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL, buf, bytesNeeded,
            &bytesNeeded, &count, &resume, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] EnumServicesStatusEx failed: %lu", KERNEL32$GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSA* svc = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerated %lu services\n", count);

    int findings = 0;
    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE h = ADVAPI32$OpenServiceA(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!h) continue;

        DWORD cfgNeeded = 0;
        ADVAPI32$QueryServiceConfigA(h, NULL, 0, &cfgNeeded);
        if (cfgNeeded == 0) { ADVAPI32$CloseServiceHandle(h); continue; }

        LPQUERY_SERVICE_CONFIGA cfg =
            (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cfgNeeded);
        if (!cfg) { ADVAPI32$CloseServiceHandle(h); continue; }

        if (ADVAPI32$QueryServiceConfigA(h, cfg, cfgNeeded, &cfgNeeded)) {
            const char* bin   = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "";
            const char* acct  = cfg->lpServiceStartName ? cfg->lpServiceStartName : "";
            int unq  = is_unquoted_with_space(bin);
            int wdir = writable_dir_hint(bin);

            /* only print the noisy details when something is interesting,
               but always note services running as LocalSystem with a flag */
            int sys = 0;
            { const char* a = acct; const char* b = "LocalSystem";
              while (*a && *b && *a == *b) { a++; b++; } sys = (*a==0 && *b==0); }

            if (unq || wdir || sys) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[%s] %s\n     bin : %s\n     acct: %s%s%s",
                    (unq||wdir) ? "!" : "i",
                    svc[i].lpServiceName, bin, acct,
                    unq  ? "\n     >>> UNQUOTED PATH (binary planting)" : "",
                    wdir ? "\n     >>> binary in writable dir (check ACLs)" : "");
                findings++;
            }
        }
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cfg);
        ADVAPI32$CloseServiceHandle(h);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Done. %d service(s) flagged for review.", findings);

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
    ADVAPI32$CloseServiceHandle(scm);
}
