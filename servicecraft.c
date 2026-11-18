/*
 * Windows Service Forensic Collector (Unicode)
 *
 * Coleta: inventario, configuracao, ServiceDll (svchost), SHA-256 e
 * assinatura digital (embutida e por catalogo) dos binarios, deteccao
 * de caminhos sem aspas e correlacao de processos.
 *
 * Saida: tabela (padrao), CSV ou JSON, sempre em UTF-8.
 *
 * Compilar (MSVC, prompt do desenvolvedor, de preferencia x64):
 *   cl /W3 /O2 service_collector_forensic.c
 *
 * Uso:
 *   service_collector_forensic.exe [--format table|csv|json]
 *                                  [--out arquivo] [--no-hash] [--no-sig]
 *                                  [--target host|ip [--user [DOM\\]usuario]
 *                                                    [--password senha]]
 *                                  [--forense] [--vuln-scan]
 *
 * Tres modos, que podem ser combinados:
 *
 *   (sem parametros)  Apenas SERVICE INVENTORY. Nao toca em disco:
 *                     so le o Service Control Manager, rapido mesmo
 *                     com muitos servicos.
 *
 *   --forense         SERVICE INVENTORY, PROCESS CORRELATION,
 *                     FINDINGS, BINARY ANALYSIS e SERVICE
 *                     CONFIGURATION.
 *
 *   --vuln-scan       REGISTRY HARDENING (SafeDllSearchMode,
 *                     CWDIllegalInDllSearch, AlwaysInstallElevated),
 *                     AUTORUN (permissoes de modificacao), SYSTEM PATH
 *                     (diretorios gravaveis/ausentes para DLL Hijack),
 *                     SCHEDULED TASKS (ACLs em XML e binarios) e
 *                     VULNERABILITY FINDINGS nos servicos.
 *
 *   --forense --vuln-scan combinados mostram todas as tabelas acima.
 */

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsvc.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#define INITIAL_BUFFER_SIZE 65536
#define MAX_IMAGE 1024
#define SIGNER_CAP 128
#define HASH_CHUNK 65536

#define NT_OK(s) ((LONG)(s) >= 0)

// ==================================================
// FLAGS DE ACHADOS (SERVICOS)
// ==================================================

#define F_UNQUOTED              0x0001
#define F_IMG_MISSING           0x0002
#define F_IMG_UNSIGNED          0x0004
#define F_IMG_BADSIG            0x0008
#define F_DLL_MISSING           0x0010
#define F_DLL_UNSIGNED          0x0020
#define F_DLL_BADSIG            0x0040
#define F_SUSP_LOC              0x0080

// Flags de vulnerabilidade (somente com --vuln-scan)
#define F_BINPATH_WRITABLE      0x0100
#define F_BINPATH_DIR_WRITABLE  0x0200
#define F_DLL_WRITABLE          0x0400
#define F_DLL_DIR_WRITABLE      0x0800
#define F_SVC_WEAK_ACL          0x1000
#define F_SVC_REG_WEAK_ACL      0x2000
#define F_DLL_HIJACK            0x4000

// Mascaras de agrupamento por modo
#define FORENSE_FLAGS_MASK ( \
    F_IMG_MISSING | F_IMG_UNSIGNED | F_IMG_BADSIG | \
    F_DLL_MISSING | F_DLL_UNSIGNED | F_DLL_BADSIG | \
    F_SUSP_LOC )

#define VULN_FLAGS_MASK ( \
    F_UNQUOTED | F_DLL_HIJACK | \
    F_BINPATH_WRITABLE | F_BINPATH_DIR_WRITABLE | \
    F_DLL_WRITABLE | F_DLL_DIR_WRITABLE | \
    F_SVC_WEAK_ACL | F_SVC_REG_WEAK_ACL )

static const struct { DWORD bit; const wchar_t* name; } FLAG_NAMES[] =
{
    { F_UNQUOTED,             L"UNQUOTED_SERVICE_PATH"      },
    { F_IMG_MISSING,          L"IMAGE_MISSING"              },
    { F_IMG_UNSIGNED,         L"IMAGE_UNSIGNED"             },
    { F_IMG_BADSIG,           L"IMAGE_INVALID_SIG"          },
    { F_DLL_MISSING,          L"DLL_MISSING"                },
    { F_DLL_UNSIGNED,         L"DLL_UNSIGNED"               },
    { F_DLL_BADSIG,           L"DLL_INVALID_SIG"            },
    { F_SUSP_LOC,             L"SUSPICIOUS_LOCATION"        },
    { F_BINPATH_WRITABLE,     L"WRITABLE_BINPATH"           },
    { F_BINPATH_DIR_WRITABLE, L"WRITABLE_BINPATH_DIR"       },
    { F_DLL_WRITABLE,         L"WRITABLE_DLL"               },
    { F_DLL_DIR_WRITABLE,     L"WRITABLE_DLL_DIR"           },
    { F_SVC_WEAK_ACL,         L"PERMISSIVE_SERVICE_ACL"     },
    { F_SVC_REG_WEAK_ACL,     L"PERMISSIVE_REGISTRY_ACL"    },
    { F_DLL_HIJACK,           L"DLL_HIJACK"                 }
};

#define FLAG_COUNT (sizeof(FLAG_NAMES) / sizeof(FLAG_NAMES[0]))

// ==================================================
// ESTRUTURAS
// ==================================================

typedef enum { FMT_TABLE, FMT_CSV, FMT_JSON } OUTPUT_FORMAT;

typedef struct
{
    DWORD pid;
    wchar_t image[MAX_IMAGE];
    DWORD serviceCount;
} PROCESS_ENTRY;

typedef struct
{
    wchar_t* path;
    BOOL exists;
    BOOL unreachable;
    wchar_t sha256[65];
    const wchar_t* sig;
    wchar_t signer[SIGNER_CAP];
} FILE_INFO;

typedef struct
{
    wchar_t* name;
    DWORD state;
    DWORD pid;
    DWORD serviceType;
    DWORD startType;
    BOOL  hasConfig;
    wchar_t* account;
    wchar_t* binaryPath;
    wchar_t* dependencies;
    wchar_t* loadGroup;
    wchar_t* description;
    wchar_t* imagePath;
    wchar_t* serviceDll;
    FILE_INFO* imageInfo;
    FILE_INFO* dllInfo;
    DWORD flags;
    wchar_t* vulnDetails;
    const wchar_t* queryStatus;
} SERVICE_RECORD;

static PROCESS_ENTRY* processes = NULL;
static DWORD processCount = 0;
static DWORD processCapacity = 0;

static SERVICE_RECORD* records = NULL;
static DWORD recordCount = 0;
static DWORD recordCapacity = 0;

static FILE_INFO** fileCache = NULL;
static DWORD fileCacheCount = 0;
static DWORD fileCacheCapacity = 0;

static FILE* g_out = NULL;
static BOOL g_doHash = TRUE;
static BOOL g_doSig = TRUE;
static BOOL g_vulnScan = FALSE;
static BOOL g_forense = FALSE;

// Modo remoto
static const wchar_t* g_target = NULL;
static BOOL g_remote = FALSE;
static wchar_t g_machineName[300];
static HKEY g_hklm = HKEY_LOCAL_MACHINE;
static HANDLE g_logonToken = NULL;
static BOOL g_filesUnreachable = FALSE;
static wchar_t g_hostLabel[300] = L"";

// Variaveis de ambiente do host remoto
static wchar_t g_sysRoot[MAX_PATH]       = L"C:\\Windows";
static wchar_t g_sysDrive[4]             = L"C:";
static wchar_t g_progFiles[MAX_PATH]     = L"C:\\Program Files";
static wchar_t g_progFilesX86[MAX_PATH]  = L"C:\\Program Files (x86)";
static wchar_t g_commonFiles[MAX_PATH]   = L"C:\\Program Files\\Common Files";
static wchar_t g_progData[MAX_PATH]      = L"C:\\ProgramData";

// ==================================================
// HELPERS
// ==================================================

static const wchar_t* S(const wchar_t* s)
{
    return s ? s : L"";
}

static const wchar_t* Dash(const wchar_t* s)
{
    return (s && *s) ? s : L"-";
}

static wchar_t* DupOrNull(const wchar_t* s)
{
    return s ? _wcsdup(s) : NULL;
}

static wchar_t* DupN(const wchar_t* s, size_t n)
{
    wchar_t* r = (wchar_t*)malloc((n + 1) * sizeof(wchar_t));

    if (r == NULL)
        return NULL;

    wmemcpy(r, s, n);
    r[n] = L'\0';
    return r;
}

static const wchar_t* FindI(const wchar_t* hay, const wchar_t* needle)
{
    size_t n = wcslen(needle);

    if (n == 0)
        return hay;

    for (; *hay; hay++)
    {
        if (_wcsnicmp(hay, needle, n) == 0)
            return hay;
    }

    return NULL;
}

static void BuildAccessPath(const wchar_t* path, wchar_t* out, size_t cap)
{
    if (g_remote && path[0] && path[1] == L':' && path[2] == L'\\')
        _snwprintf_s(out, cap, _TRUNCATE,
            L"\\\\%ls\\%c$\\%ls", g_target, path[0], path + 3);
    else
        wcsncpy_s(out, cap, path, _TRUNCATE);
}

typedef enum { FS_EXISTS, FS_MISSING, FS_UNREACHABLE } FILE_STATE;

static FILE_STATE QueryFile(const wchar_t* path)
{
    wchar_t acc[1200];

    if (g_remote && g_filesUnreachable)
        return FS_UNREACHABLE;

    BuildAccessPath(path, acc, 1200);

    DWORD a = GetFileAttributesW(acc);

    if (a != INVALID_FILE_ATTRIBUTES)
        return (a & FILE_ATTRIBUTE_DIRECTORY) ? FS_MISSING : FS_EXISTS;

    DWORD e = GetLastError();

    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ||
        e == ERROR_INVALID_NAME || e == ERROR_BAD_PATHNAME)
        return FS_MISSING;

    return FS_UNREACHABLE;
}

static FILE_STATE QueryDir(const wchar_t* path)
{
    wchar_t acc[1200];

    if (g_remote && g_filesUnreachable)
        return FS_UNREACHABLE;

    BuildAccessPath(path, acc, 1200);

    DWORD a = GetFileAttributesW(acc);

    if (a != INVALID_FILE_ATTRIBUTES)
        return (a & FILE_ATTRIBUTE_DIRECTORY) ? FS_EXISTS : FS_MISSING;

    DWORD e = GetLastError();

    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ||
        e == ERROR_INVALID_NAME || e == ERROR_BAD_PATHNAME)
        return FS_MISSING;

    return FS_UNREACHABLE;
}

static BOOL IsFile(const wchar_t* path)
{
    return QueryFile(path) == FS_EXISTS;
}

static wchar_t* ExpandEnvLocal(const wchar_t* s)
{
    DWORD n = ExpandEnvironmentStringsW(s, NULL, 0);

    if (n == 0)
        return _wcsdup(s);

    wchar_t* out = (wchar_t*)malloc(n * sizeof(wchar_t));

    if (out == NULL)
        return NULL;

    if (ExpandEnvironmentStringsW(s, out, n) == 0)
    {
        free(out);
        return _wcsdup(s);
    }

    return out;
}

// ==================================================
// AMBIENTE REMOTO
// ==================================================

static const wchar_t* RemoteVar(const wchar_t* name, size_t n)
{
#define MATCH(k) (wcslen(k) == n && _wcsnicmp(name, k, n) == 0)
    if (MATCH(L"SystemRoot") || MATCH(L"windir")) return g_sysRoot;
    if (MATCH(L"SystemDrive"))                    return g_sysDrive;
    if (MATCH(L"ProgramFiles"))                   return g_progFiles;
    if (MATCH(L"ProgramFiles(x86)"))              return g_progFilesX86;
    if (MATCH(L"CommonProgramFiles"))             return g_commonFiles;
    if (MATCH(L"ProgramData") || MATCH(L"ALLUSERSPROFILE"))
        return g_progData;
#undef MATCH
    return NULL;
}

static wchar_t* ExpandEnvRemote(const wchar_t* s)
{
    size_t pct = 0;

    for (const wchar_t* q = s; *q; q++)
    {
        if (*q == L'%')
            pct++;
    }

    size_t cap = wcslen(s) + 1 + pct * MAX_PATH;
    wchar_t* out = (wchar_t*)malloc(cap * sizeof(wchar_t));

    if (out == NULL)
        return NULL;

    size_t o = 0;

    for (const wchar_t* p = s; *p; )
    {
        if (*p == L'%')
        {
            const wchar_t* e = wcschr(p + 1, L'%');

            if (e != NULL)
            {
                const wchar_t* v = RemoteVar(p + 1, (size_t)(e - (p + 1)));

                if (v != NULL)
                {
                    size_t vl = wcslen(v);
                    wmemcpy(out + o, v, vl);
                    o += vl;
                    p = e + 1;
                    continue;
                }
            }
        }

        out[o++] = *p++;
    }

    out[o] = L'\0';
    return out;
}

static wchar_t* ExpandEnv(const wchar_t* s)
{
    return g_remote ? ExpandEnvRemote(s) : ExpandEnvLocal(s);
}

static BOOL ReadRegString(
    HKEY root, const wchar_t* key, const wchar_t* value,
    wchar_t* out, DWORD capChars)
{
    HKEY h = NULL;

    if (RegOpenKeyExW(root, key, 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0;
    DWORD bytes = (capChars - 1) * sizeof(wchar_t);

    LONG rc = RegQueryValueExW(h, value, NULL, &type, (LPBYTE)out, &bytes);

    RegCloseKey(h);

    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return FALSE;

    out[bytes / sizeof(wchar_t)] = L'\0';
    return TRUE;
}

static BOOL ReadRegDword(
    HKEY root, const wchar_t* key, const wchar_t* value, DWORD* outVal)
{
    if (root == NULL)
        return FALSE;

    HKEY h = NULL;

    if (RegOpenKeyExW(root, key, 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0;
    DWORD val = 0;
    DWORD bytes = sizeof(DWORD);

    LONG rc = RegQueryValueExW(h, value, NULL, &type, (LPBYTE)&val, &bytes);
    RegCloseKey(h);

    if (rc != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof(DWORD))
        return FALSE;

    *outVal = val;
    return TRUE;
}

static wchar_t* ReadRegStringAlloc(
    HKEY root, const wchar_t* key, const wchar_t* value)
{
    HKEY h = NULL;

    if (RegOpenKeyExW(root, key, 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return NULL;

    DWORD type = 0;
    DWORD bytes = 0;

    LONG rc = RegQueryValueExW(h, value, NULL, &type, NULL, &bytes);

    if (rc != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0)
    {
        RegCloseKey(h);
        return NULL;
    }

    wchar_t* buf = (wchar_t*)calloc((bytes / sizeof(wchar_t)) + 2, sizeof(wchar_t));
    if (buf == NULL)
    {
        RegCloseKey(h);
        return NULL;
    }

    rc = RegQueryValueExW(h, value, NULL, &type, (LPBYTE)buf, &bytes);
    RegCloseKey(h);

    if (rc != ERROR_SUCCESS)
    {
        free(buf);
        return NULL;
    }

    return buf;
}

static void LoadRemoteEnvironment(void)
{
    wchar_t tmp[MAX_PATH];
    BOOL gotPF = FALSE, gotPF86 = FALSE, gotCommon = FALSE;

    if (g_hklm != NULL)
    {
        if (ReadRegString(g_hklm,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"SystemRoot", tmp, MAX_PATH))
            wcsncpy_s(g_sysRoot, MAX_PATH, tmp, _TRUNCATE);

        gotPF = ReadRegString(g_hklm,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            L"ProgramFilesDir", g_progFiles, MAX_PATH);

        gotPF86 = ReadRegString(g_hklm,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            L"ProgramFilesDir (x86)", g_progFilesX86, MAX_PATH);

        gotCommon = ReadRegString(g_hklm,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            L"CommonFilesDir", g_commonFiles, MAX_PATH);
    }

    _snwprintf_s(g_sysDrive, 4, _TRUNCATE, L"%.2ls", g_sysRoot);

    if (!gotPF)
        _snwprintf_s(g_progFiles, MAX_PATH, _TRUNCATE,
            L"%ls\\Program Files", g_sysDrive);

    if (!gotPF86)
        _snwprintf_s(g_progFilesX86, MAX_PATH, _TRUNCATE,
            L"%ls\\Program Files (x86)", g_sysDrive);

    if (!gotCommon)
        _snwprintf_s(g_commonFiles, MAX_PATH, _TRUNCATE,
            L"%ls\\Program Files\\Common Files", g_sysDrive);

    _snwprintf_s(g_progData, MAX_PATH, _TRUNCATE,
        L"%ls\\ProgramData", g_sysDrive);
}

// ==================================================
// ESTADOS / TIPOS
// ==================================================

const wchar_t* GetState(DWORD state)
{
    switch (state)
    {
    case SERVICE_STOPPED:           return L"STOPPED";
    case SERVICE_START_PENDING:     return L"START_PENDING";
    case SERVICE_STOP_PENDING:      return L"STOP_PENDING";
    case SERVICE_RUNNING:           return L"RUNNING";
    case SERVICE_CONTINUE_PENDING:  return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:     return L"PAUSE_PENDING";
    case SERVICE_PAUSED:            return L"PAUSED";
    default:                        return L"UNKNOWN";
    }
}

const wchar_t* GetServiceType(DWORD type)
{
    if (type & SERVICE_WIN32_OWN_PROCESS)
        return L"WIN32_OWN";

    if (type & SERVICE_WIN32_SHARE_PROCESS)
        return L"WIN32_SHARE";

    if (type & SERVICE_KERNEL_DRIVER)
        return L"KERNEL_DRIVER";

    if (type & SERVICE_FILE_SYSTEM_DRIVER)
        return L"FILESYSTEM";

    return L"OTHER";
}

const wchar_t* GetStartType(DWORD type)
{
    switch (type)
    {
    case SERVICE_AUTO_START:    return L"AUTOMATIC";
    case SERVICE_BOOT_START:    return L"BOOT";
    case SERVICE_SYSTEM_START:  return L"SYSTEM";
    case SERVICE_DEMAND_START:  return L"MANUAL";
    case SERVICE_DISABLED:      return L"DISABLED";
    default:                    return L"UNKNOWN";
    }
}

// ==================================================
// PROCESSOS
// ==================================================

void GetProcessImage(DWORD pid, wchar_t* output, DWORD size)
{
    HANDLE hProcess;
    DWORD length = size;

    output[0] = L'\0';

    hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    if (hProcess == NULL)
    {
        wcscpy_s(output, size, L"ACCESS DENIED");
        return;
    }

    if (!QueryFullProcessImageNameW(hProcess, 0, output, &length))
        wcscpy_s(output, size, L"QUERY FAILED");

    CloseHandle(hProcess);
}

void AddProcess(DWORD pid, const wchar_t* imageHint)
{
    if (pid == 0)
        return;

    for (DWORD i = 0; i < processCount; i++)
    {
        if (processes[i].pid == pid)
        {
            processes[i].serviceCount++;
            return;
        }
    }

    if (processCount == processCapacity)
    {
        DWORD newCap = processCapacity ? processCapacity * 2 : 64;

        PROCESS_ENTRY* temp = (PROCESS_ENTRY*)
            realloc(processes, sizeof(PROCESS_ENTRY) * newCap);

        if (temp == NULL)
            return;

        processes = temp;
        processCapacity = newCap;
    }

    PROCESS_ENTRY* entry = &processes[processCount];

    ZeroMemory(entry, sizeof(PROCESS_ENTRY));

    entry->pid = pid;
    entry->serviceCount = 1;

    if (g_remote)
    {
        wcsncpy_s(entry->image, MAX_IMAGE,
            (imageHint && *imageHint) ? imageHint : L"UNAVAILABLE (REMOTE)",
            _TRUNCATE);
    }
    else
    {
        GetProcessImage(pid, entry->image, MAX_IMAGE);
    }

    processCount++;
}

// ==================================================
// CONFIGURACAO / DESCRICAO / DEPENDENCIAS
// ==================================================

QUERY_SERVICE_CONFIGW* GetServiceConfig(SC_HANDLE hService)
{
    DWORD needed = 0;

    QueryServiceConfigW(hService, NULL, 0, &needed);

    if (needed == 0)
        return NULL;

    QUERY_SERVICE_CONFIGW* config =
        (QUERY_SERVICE_CONFIGW*)malloc(needed);

    if (config == NULL)
        return NULL;

    if (!QueryServiceConfigW(hService, config, needed, &needed))
    {
        free(config);
        return NULL;
    }

    return config;
}

wchar_t* GetServiceDescription(SC_HANDLE hService)
{
    DWORD needed = 0;

    QueryServiceConfig2W(
        hService,
        SERVICE_CONFIG_DESCRIPTION,
        NULL,
        0,
        &needed
    );

    if (needed == 0)
        return NULL;

    SERVICE_DESCRIPTIONW* desc =
        (SERVICE_DESCRIPTIONW*)malloc(needed);

    if (desc == NULL)
        return NULL;

    if (!QueryServiceConfig2W(
        hService,
        SERVICE_CONFIG_DESCRIPTION,
        (LPBYTE)desc,
        needed,
        &needed))
    {
        free(desc);
        return NULL;
    }

    wchar_t* result = NULL;

    if (desc->lpDescription != NULL)
        result = _wcsdup(desc->lpDescription);

    free(desc);

    return result;
}

wchar_t* GetDependencies(const wchar_t* deps)
{
    if (deps == NULL || *deps == L'\0')
        return _wcsdup(L"");

    size_t total = 0;

    for (const wchar_t* p = deps; *p; p += wcslen(p) + 1)
        total += wcslen(p) + 1;

    wchar_t* result = (wchar_t*)calloc(total + 1, sizeof(wchar_t));

    if (result == NULL)
        return NULL;

    for (const wchar_t* p = deps; *p; p += wcslen(p) + 1)
    {
        if (result[0] != L'\0')
            wcscat_s(result, total + 1, L";");

        wcscat_s(result, total + 1, p);
    }

    return result;
}

// ==================================================
// RESOLUCAO DE CAMINHOS
// ==================================================

static wchar_t* NormalizeNtPath(const wchar_t* s)
{
    while (*s == L' ' || *s == L'\t')
        s++;

    if (_wcsnicmp(s, L"\\??\\", 4) == 0)
        return ExpandEnv(s + 4);

    if (_wcsnicmp(s, L"\\SystemRoot\\", 12) == 0 ||
        _wcsnicmp(s, L"System32\\", 9) == 0)
    {
        const wchar_t* rest =
            (_wcsnicmp(s, L"\\SystemRoot\\", 12) == 0) ? s + 12 : s;

        size_t n = wcslen(rest) + 32;
        wchar_t* tmp = (wchar_t*)malloc(n * sizeof(wchar_t));

        if (tmp == NULL)
            return NULL;

        swprintf_s(tmp, n, L"%%SystemRoot%%\\%ls", rest);

        wchar_t* result = ExpandEnv(tmp);
        free(tmp);
        return result;
    }

    return ExpandEnv(s);
}

static wchar_t* ResolveWin32Image(const wchar_t* cmd)
{
    while (*cmd == L' ' || *cmd == L'\t')
        cmd++;

    if (*cmd == L'"')
    {
        cmd++;
        const wchar_t* end = wcschr(cmd, L'"');
        size_t len = end ? (size_t)(end - cmd) : wcslen(cmd);
        return DupN(cmd, len);
    }

    size_t len = wcslen(cmd);

    for (size_t i = 1; i <= len; i++)
    {
        if (cmd[i] != L' ' && cmd[i] != L'\0')
            continue;

        wchar_t* cand = DupN(cmd, i);

        if (cand == NULL)
            continue;

        if (IsFile(cand))
            return cand;

        size_t n = i + 5;
        wchar_t* withExe = (wchar_t*)malloc(n * sizeof(wchar_t));

        if (withExe != NULL)
        {
            swprintf_s(withExe, n, L"%ls.exe", cand);

            if (IsFile(withExe))
            {
                free(cand);
                return withExe;
            }

            free(withExe);
        }

        free(cand);
    }

    size_t first = 0;

    while (cmd[first] && cmd[first] != L' ')
        first++;

    return DupN(cmd, first);
}

static BOOL IsUnquotedPathVuln(const wchar_t* cmd)
{
    while (*cmd == L' ' || *cmd == L'\t')
        cmd++;

    if (*cmd == L'"')
        return FALSE;

    const wchar_t* exe = FindI(cmd, L".exe");

    if (exe == NULL)
        return FALSE;

    for (const wchar_t* q = cmd; q < exe; q++)
    {
        if (*q == L' ')
            return TRUE;
    }

    return FALSE;
}

static BOOL IsSuspiciousLocation(const wchar_t* path)
{
    static const wchar_t* markers[] =
    {
        L"\\users\\", L"\\temp\\", L"\\appdata\\",
        L"\\$recycle.bin\\", L"\\perflogs\\"
    };

    if (path == NULL)
        return FALSE;

    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++)
    {
        if (FindI(path, markers[i]) != NULL)
            return TRUE;
    }

    return FALSE;
}

static wchar_t* ReadServiceDll(const wchar_t* serviceName)
{
    static const wchar_t* subkeys[] = { L"\\Parameters", L"" };

    if (g_hklm == NULL)
        return NULL;

    for (int k = 0; k < 2; k++)
    {
        wchar_t keyPath[640];

        if (swprintf_s(keyPath, 640,
            L"SYSTEM\\CurrentControlSet\\Services\\%ls%ls",
            serviceName, subkeys[k]) < 0)
            continue;

        HKEY hKey = NULL;

        if (RegOpenKeyExW(
            g_hklm,
            keyPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &hKey) != ERROR_SUCCESS)
            continue;

        DWORD type = 0;
        DWORD bytes = 0;

        LONG rc = RegQueryValueExW(
            hKey, L"ServiceDll", NULL, &type, NULL, &bytes);

        if (rc != ERROR_SUCCESS ||
            (type != REG_SZ && type != REG_EXPAND_SZ) ||
            bytes == 0)
        {
            RegCloseKey(hKey);
            continue;
        }

        wchar_t* raw = (wchar_t*)calloc(
            (bytes / sizeof(wchar_t)) + 2, sizeof(wchar_t));

        if (raw == NULL)
        {
            RegCloseKey(hKey);
            return NULL;
        }

        rc = RegQueryValueExW(
            hKey, L"ServiceDll", NULL, &type, (LPBYTE)raw, &bytes);

        RegCloseKey(hKey);

        if (rc != ERROR_SUCCESS)
        {
            free(raw);
            continue;
        }

        wchar_t* norm = NormalizeNtPath(raw);
        free(raw);

        if (norm == NULL)
            return NULL;

        if (wcschr(norm, L'\\') == NULL)
        {
            size_t n = wcslen(norm) + 40;
            wchar_t* tmp = (wchar_t*)malloc(n * sizeof(wchar_t));

            if (tmp != NULL)
            {
                swprintf_s(tmp, n, L"%%SystemRoot%%\\System32\\%ls", norm);
                free(norm);
                norm = ExpandEnv(tmp);
                free(tmp);
            }
        }

        return norm;
    }

    return NULL;
}

// ==================================================
// SHA-256 (CNG)
// ==================================================

static BOOL Sha256File(const wchar_t* path, wchar_t out[65])
{
    BOOL ok = FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR hashObject = NULL;
    BYTE* buffer = NULL;
    BYTE digest[32];
    DWORD objLen = 0, cb = 0;

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!NT_OK(BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto cleanup;

    if (!NT_OK(BCryptGetProperty(
        hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&objLen, sizeof(DWORD), &cb, 0)))
        goto cleanup;

    hashObject = (PUCHAR)malloc(objLen);
    buffer = (BYTE*)malloc(HASH_CHUNK);

    if (hashObject == NULL || buffer == NULL)
        goto cleanup;

    if (!NT_OK(BCryptCreateHash(
        hAlg, &hHash, hashObject, objLen, NULL, 0, 0)))
        goto cleanup;

    for (;;)
    {
        DWORD read = 0;

        if (!ReadFile(hFile, buffer, HASH_CHUNK, &read, NULL))
            goto cleanup;

        if (read == 0)
            break;

        if (!NT_OK(BCryptHashData(hHash, buffer, read, 0)))
            goto cleanup;
    }

    if (!NT_OK(BCryptFinishHash(hHash, digest, sizeof(digest), 0)))
        goto cleanup;

    for (int i = 0; i < 32; i++)
        swprintf_s(out + i * 2, 3, L"%02x", digest[i]);

    out[64] = L'\0';
    ok = TRUE;

cleanup:
    if (hHash)  BCryptDestroyHash(hHash);
    if (hAlg)   BCryptCloseAlgorithmProvider(hAlg, 0);
    free(hashObject);
    free(buffer);
    CloseHandle(hFile);

    return ok;
}

// ==================================================
// ASSINATURA DIGITAL (WinVerifyTrust)
// ==================================================

typedef BOOL (WINAPI *PFN_AcquireContext2)(
    HCATADMIN*, const GUID*, PCWSTR, const void*, DWORD);

typedef BOOL (WINAPI *PFN_CalcHash2)(
    HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);

static void GetSignerName(HANDLE hState, wchar_t* signer, size_t cap)
{
    if (hState == NULL)
        return;

    CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(hState);

    if (pd == NULL)
        return;

    CRYPT_PROVIDER_SGNR* sg =
        WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);

    if (sg == NULL)
        return;

    CRYPT_PROVIDER_CERT* pc = WTHelperGetProvCertFromChain(sg, 0);

    if (pc == NULL || pc->pCert == NULL)
        return;

    CertGetNameStringW(
        pc->pCert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        signer,
        (DWORD)cap
    );
}

static LONG RunWinVerifyTrust(
    WINTRUST_DATA* wd,
    wchar_t* signer,
    size_t cap)
{
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    wd->dwStateAction = WTD_STATEACTION_VERIFY;

    LONG r = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, wd);

    if (signer != NULL && signer[0] == L'\0')
        GetSignerName(wd->hWVTStateData, signer, cap);

    wd->dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, wd);

    return r;
}

static BOOL IsNoSignatureError(LONG r)
{
    return r == TRUST_E_NOSIGNATURE ||
           r == TRUST_E_SUBJECT_FORM_UNKNOWN ||
           r == TRUST_E_PROVIDER_UNKNOWN;
}

static LONG VerifyEmbedded(
    const wchar_t* path, wchar_t* signer, size_t cap)
{
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;

    ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;

    ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                     WTD_REVOCATION_CHECK_NONE;

    return RunWinVerifyTrust(&wd, signer, cap);
}

static LONG VerifyCatalog(
    const wchar_t* path,
    BOOL useSha256,
    wchar_t* signer,
    size_t cap,
    BOOL* found)
{
    LONG result = TRUST_E_NOSIGNATURE;
    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;
    BYTE* hash = NULL;
    wchar_t* tag = NULL;
    DWORD hashLen = 0;

    *found = FALSE;

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return result;

    HMODULE hWin = GetModuleHandleW(L"wintrust.dll");

    if (hWin == NULL)
        hWin = LoadLibraryW(L"wintrust.dll");

    PFN_AcquireContext2 pAcquire2 = NULL;
    PFN_CalcHash2 pCalc2 = NULL;

    if (useSha256 && hWin != NULL)
    {
        pAcquire2 = (PFN_AcquireContext2)(void*)
            GetProcAddress(hWin, "CryptCATAdminAcquireContext2");

        pCalc2 = (PFN_CalcHash2)(void*)
            GetProcAddress(hWin, "CryptCATAdminCalcHashFromFileHandle2");

        if (pAcquire2 == NULL || pCalc2 == NULL)
            goto cleanup;
    }

    if (useSha256)
    {
        if (!pAcquire2(&hCatAdmin, NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0))
            goto cleanup;

        pCalc2(hCatAdmin, hFile, &hashLen, NULL, 0);

        if (hashLen == 0)
            goto cleanup;

        hash = (BYTE*)malloc(hashLen);

        if (hash == NULL || !pCalc2(hCatAdmin, hFile, &hashLen, hash, 0))
            goto cleanup;
    }
    else
    {
        if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
            goto cleanup;

        CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0);

        if (hashLen == 0)
            goto cleanup;

        hash = (BYTE*)malloc(hashLen);

        if (hash == NULL ||
            !CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0))
            goto cleanup;
    }

    hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin, hash, hashLen, 0, NULL);

    if (hCatInfo == NULL)
        goto cleanup;

    *found = TRUE;

    CATALOG_INFO ci;
    ZeroMemory(&ci, sizeof(ci));
    ci.cbStruct = sizeof(ci);

    if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0))
    {
        result = TRUST_E_SYSTEM_ERROR;
        goto cleanup;
    }

    tag = (wchar_t*)calloc((size_t)hashLen * 2 + 1, sizeof(wchar_t));

    if (tag == NULL)
        goto cleanup;

    for (DWORD i = 0; i < hashLen; i++)
        swprintf_s(tag + i * 2, 3, L"%02X", hash[i]);

    WINTRUST_CATALOG_INFO wci;
    WINTRUST_DATA wd;

    ZeroMemory(&wci, sizeof(wci));
    wci.cbStruct = sizeof(wci);
    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
    wci.pcwszMemberTag = tag;
    wci.pcwszMemberFilePath = path;
    wci.pbCalculatedFileHash = hash;
    wci.cbCalculatedFileHash = hashLen;

    ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.pCatalog = &wci;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                     WTD_REVOCATION_CHECK_NONE;

    result = RunWinVerifyTrust(&wd, signer, cap);

cleanup:
    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

    if (hCatAdmin)
        CryptCATAdminReleaseContext(hCatAdmin, 0);

    free(hash);
    free(tag);
    CloseHandle(hFile);

    return result;
}

static const wchar_t* VerifySignature(
    const wchar_t* path, wchar_t* signer, size_t cap)
{
    signer[0] = L'\0';

    LONG r = VerifyEmbedded(path, signer, cap);

    if (r == 0)
        return L"SIGNED";

    if (!IsNoSignatureError(r))
        return L"INVALID";

    if (g_remote)
        return L"NO EMBEDDED SIG";

    for (int pass = 0; pass < 2; pass++)
    {
        BOOL found = FALSE;
        signer[0] = L'\0';

        LONG c = VerifyCatalog(path, pass == 0, signer, cap, &found);

        if (found)
            return (c == 0) ? L"SIGNED (CATALOG)" : L"INVALID";
    }

    signer[0] = L'\0';
    return L"UNSIGNED";
}

// ==================================================
// VERIFICACAO DE PERMISSOES (ACL) - somente --vuln-scan
// ==================================================

typedef struct { PSID sid; const wchar_t* name; } LOW_PRIV_SID;

static LOW_PRIV_SID g_lowPriv[4];
static int g_lowPrivCount = 0;

static void AddLowPrivSid(PSID sid, const wchar_t* name)
{
    if (sid == NULL || g_lowPrivCount >= 4)
        return;

    g_lowPriv[g_lowPrivCount].sid = sid;
    g_lowPriv[g_lowPrivCount].name = name;
    g_lowPrivCount++;
}

static void InitLowPrivSids(void)
{
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY nt    = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;

    // Everyone (S-1-1-0)
    if (AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID,
        0,0,0,0,0,0,0, &sid))
        AddLowPrivSid(sid, L"Everyone");

    // NT AUTHORITY\Authenticated Users (S-1-5-11)
    sid = NULL;
    if (AllocateAndInitializeSid(&nt, 1, SECURITY_AUTHENTICATED_USER_RID,
        0,0,0,0,0,0,0, &sid))
        AddLowPrivSid(sid, L"NT AUTHORITY\\Authenticated Users");

    // BUILTIN\Users (S-1-5-32-545)
    sid = NULL;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_USERS, 0,0,0,0,0,0, &sid))
        AddLowPrivSid(sid, L"BUILTIN\\Users");

    // NT AUTHORITY\INTERACTIVE (S-1-5-4)
    sid = NULL;
    if (AllocateAndInitializeSid(&nt, 1, SECURITY_INTERACTIVE_RID,
        0,0,0,0,0,0,0, &sid))
        AddLowPrivSid(sid, L"NT AUTHORITY\\INTERACTIVE");
}

static void FreeLowPrivSids(void)
{
    for (int i = 0; i < g_lowPrivCount; i++)
        FreeSid(g_lowPriv[i].sid);

    g_lowPrivCount = 0;
}

static int FindLowPrivIndex(PSID sid)
{
    for (int i = 0; i < g_lowPrivCount; i++)
    {
        if (EqualSid(sid, g_lowPriv[i].sid))
            return i;
    }

    return -1;
}

static BOOL ExtractRiskyAces(
    PACL dacl, ACCESS_MASK riskyMask, wchar_t* details, size_t cap)
{
    details[0] = L'\0';

    if (dacl == NULL)
        return FALSE;

    BOOL any = FALSE;

    for (WORD i = 0; i < dacl->AceCount; i++)
    {
        LPVOID aceVoid = NULL;

        if (!GetAce(dacl, i, &aceVoid))
            continue;

        ACE_HEADER* hdr = (ACE_HEADER*)aceVoid;

        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;

        ACCESS_ALLOWED_ACE* ace = (ACCESS_ALLOWED_ACE*)aceVoid;
        PSID sid = (PSID)&ace->SidStart;

        int idx = FindLowPrivIndex(sid);

        if (idx < 0)
            continue;

        ACCESS_MASK mask = ace->Mask;
        BOOL generic = (mask & (GENERIC_ALL | GENERIC_WRITE)) != 0;

        if (!generic && !(mask & riskyMask))
            continue;

        wchar_t seg[160];

        swprintf_s(seg, 160, L"%ls(0x%lx)", g_lowPriv[idx].name,
            (unsigned long)mask);

        if (details[0] != L'\0')
            wcscat_s(details, cap, L"; ");

        wcscat_s(details, cap, seg);
        any = TRUE;
    }

    return any;
}

static wchar_t* GetParentDir(const wchar_t* path)
{
    if (path == NULL)
        return NULL;

    wchar_t* dup = _wcsdup(path);

    if (dup == NULL)
        return NULL;

    wchar_t* slash = wcsrchr(dup, L'\\');

    if (slash == NULL)
    {
        free(dup);
        return NULL;
    }

    if (slash == dup)
        slash[1] = L'\0';
    else
        *slash = L'\0';

    return dup;
}

static BOOL CheckFileAcl(
    const wchar_t* path, ACCESS_MASK riskyMask,
    wchar_t* details, size_t cap)
{
    details[0] = L'\0';

    if (path == NULL || *path == L'\0')
        return FALSE;

    wchar_t acc[1200];
    BuildAccessPath(path, acc, 1200);

    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    DWORD rc = GetNamedSecurityInfoW(
        acc, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);

    if (rc != ERROR_SUCCESS)
    {
        if (sd != NULL)
            LocalFree(sd);

        return FALSE;
    }

    BOOL risky;

    if (dacl == NULL)
    {
        wcscpy_s(details, cap, L"NO_DACL(unrestricted)");
        risky = TRUE;
    }
    else
    {
        risky = ExtractRiskyAces(dacl, riskyMask, details, cap);
    }

    if (sd != NULL)
        LocalFree(sd);

    return risky;
}

static BOOL CheckServiceAcl(SC_HANDLE hService, wchar_t* details, size_t cap)
{
    details[0] = L'\0';

    DWORD needed = 0;
    BYTE probe[4];

    QueryServiceObjectSecurity(
        hService, DACL_SECURITY_INFORMATION, probe, 0, &needed);

    if (needed == 0)
        return FALSE;

    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)malloc(needed);

    if (sd == NULL)
        return FALSE;

    BOOL got = QueryServiceObjectSecurity(
        hService, DACL_SECURITY_INFORMATION, sd, needed, &needed);

    if (!got)
    {
        free(sd);
        return FALSE;
    }

    PACL dacl = NULL;
    BOOL present = FALSE;
    BOOL isDefault = FALSE;

    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &isDefault))
    {
        free(sd);
        return FALSE;
    }

    ACCESS_MASK mask = SERVICE_CHANGE_CONFIG | DELETE | WRITE_DAC | WRITE_OWNER;
    BOOL risky;

    if (!present || dacl == NULL)
    {
        wcscpy_s(details, cap, L"NO_DACL(unrestricted)");
        risky = TRUE;
    }
    else
    {
        risky = ExtractRiskyAces(dacl, mask, details, cap);
    }

    free(sd);
    return risky;
}

static BOOL CheckRegistryKeyAcl(
    HKEY hKeyRoot, const wchar_t* subkey, wchar_t* details, size_t cap)
{
    details[0] = L'\0';

    if (hKeyRoot == NULL)
        return FALSE;

    HKEY hKey = NULL;

    if (RegOpenKeyExW(hKeyRoot, subkey, 0,
        READ_CONTROL | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return FALSE;

    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    DWORD rc = GetSecurityInfo(
        hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS)
    {
        if (sd != NULL)
            LocalFree(sd);

        return FALSE;
    }

    ACCESS_MASK mask =
        KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER;
    BOOL risky;

    if (dacl == NULL)
    {
        wcscpy_s(details, cap, L"NO_DACL(unrestricted)");
        risky = TRUE;
    }
    else
    {
        risky = ExtractRiskyAces(dacl, mask, details, cap);
    }

    if (sd != NULL)
        LocalFree(sd);

    return risky;
}

// ==================================================
// REGISTRY HARDENING & PRIVILEGE ESCALATION CHECKS
// (SafeDllSearchMode, CWDIllegalInDllSearch, AlwaysInstallElevated)
// ==================================================

typedef struct
{
    wchar_t* category;      // "DLL_SEARCH_PROTECTION" ou "MSI_PRIV_ESC"
    wchar_t* hive;          // "HKLM" ou "HKLM + HKCU"
    wchar_t* keyPath;
    wchar_t* valueName;
    wchar_t* rawValue;
    wchar_t* status;        // "VULNERABLE", "PARTIAL", "SECURE"
    wchar_t* details;
    BOOL isVulnerable;
} REG_HARDENING_ENTRY;

static REG_HARDENING_ENTRY* regHardeningEntries = NULL;
static DWORD regHardeningCount = 0;
static DWORD regHardeningCapacity = 0;

static void AddRegHardeningEntry(
    const wchar_t* category,
    const wchar_t* hive,
    const wchar_t* keyPath,
    const wchar_t* valueName,
    const wchar_t* rawValue,
    const wchar_t* status,
    const wchar_t* details,
    BOOL isVulnerable)
{
    if (regHardeningCount == regHardeningCapacity)
    {
        DWORD newCap = regHardeningCapacity ? regHardeningCapacity * 2 : 8;
        REG_HARDENING_ENTRY* temp = (REG_HARDENING_ENTRY*)
            realloc(regHardeningEntries, sizeof(REG_HARDENING_ENTRY) * newCap);
        if (temp == NULL)
            return;
        regHardeningEntries = temp;
        regHardeningCapacity = newCap;
    }

    REG_HARDENING_ENTRY* e = &regHardeningEntries[regHardeningCount++];
    e->category = _wcsdup(category);
    e->hive = _wcsdup(hive);
    e->keyPath = _wcsdup(keyPath);
    e->valueName = _wcsdup(valueName);
    e->rawValue = _wcsdup(rawValue);
    e->status = _wcsdup(status);
    e->details = _wcsdup(details);
    e->isVulnerable = isVulnerable;
}

static void FreeRegHardening(void)
{
    for (DWORD i = 0; i < regHardeningCount; i++)
    {
        free(regHardeningEntries[i].category);
        free(regHardeningEntries[i].hive);
        free(regHardeningEntries[i].keyPath);
        free(regHardeningEntries[i].valueName);
        free(regHardeningEntries[i].rawValue);
        free(regHardeningEntries[i].status);
        free(regHardeningEntries[i].details);
    }
    free(regHardeningEntries);
    regHardeningEntries = NULL;
    regHardeningCount = 0;
    regHardeningCapacity = 0;
}

static DWORD CountRegHardeningFindings(void)
{
    DWORD n = 0;
    for (DWORD i = 0; i < regHardeningCount; i++)
    {
        if (regHardeningEntries[i].isVulnerable)
            n++;
    }
    return n;
}

static void ScanRegistryHardening(void)
{
    const wchar_t* smKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    const wchar_t* instKey =
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";

    // 1. SafeDllSearchMode
    if (g_hklm != NULL)
    {
        DWORD val = 0;
        wchar_t valStr[64];
        if (ReadRegDword(g_hklm, smKey, L"SafeDllSearchMode", &val))
        {
            swprintf_s(valStr, 64, L"0x%lx (%lu)", (unsigned long)val, (unsigned long)val);
            if (val == 0)
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"SafeDllSearchMode",
                    valStr, L"VULNERABLE",
                    L"SafeDllSearchMode=0 places CWD before System32 in DLL search order",
                    TRUE);
            }
            else
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"SafeDllSearchMode",
                    valStr, L"SECURE",
                    L"SafeDllSearchMode enabled (System32 searched before CWD)",
                    FALSE);
            }
        }
        else
        {
            AddRegHardeningEntry(
                L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"SafeDllSearchMode",
                L"NOT_SET (default=1)", L"SECURE",
                L"Default Windows behavior enabled (System32 searched before CWD)",
                FALSE);
        }

        // 2. CWDIllegalInDllSearch
        if (ReadRegDword(g_hklm, smKey, L"CWDIllegalInDllSearch", &val))
        {
            swprintf_s(valStr, 64, L"0x%lx", (unsigned long)val);
            if (val == 0xFFFFFFFF)
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                    valStr, L"VULNERABLE",
                    L"CWD blocking explicitly disabled (0xFFFFFFFF)",
                    TRUE);
            }
            else if (val == 0)
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                    valStr, L"UNHARDENED",
                    L"CWD is allowed in DLL search path (set 1 for WebDAV or 2 for all CWD)",
                    TRUE);
            }
            else if (val == 1)
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                    valStr, L"PARTIAL",
                    L"Blocks CWD only on WebDAV/remote shares (local CWD still searched)",
                    FALSE);
            }
            else if (val == 2)
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                    valStr, L"HARDENED",
                    L"CWD completely removed from default DLL search order",
                    FALSE);
            }
            else
            {
                AddRegHardeningEntry(
                    L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                    valStr, L"CUSTOM",
                    L"Custom CWDIllegalInDllSearch bitmask configured",
                    FALSE);
            }
        }
        else
        {
            AddRegHardeningEntry(
                L"DLL_SEARCH_PROTECTION", L"HKLM", smKey, L"CWDIllegalInDllSearch",
                L"NOT_SET", L"UNHARDENED",
                L"CWDIllegalInDllSearch not configured (CWD remains in DLL search path)",
                TRUE);
        }
    }

    // 3. AlwaysInstallElevated (HKLM e HKCU)
    {
        DWORD hklmVal = 0;
        DWORD hkcuVal = 0;
        BOOL hasHklm = ReadRegDword(g_hklm, instKey, L"AlwaysInstallElevated", &hklmVal);
        BOOL hasHkcu = (!g_remote)
            ? ReadRegDword(HKEY_CURRENT_USER, instKey, L"AlwaysInstallElevated", &hkcuVal)
            : FALSE;

        BOOL hklmEnabled = (hasHklm && hklmVal == 1);
        BOOL hkcuEnabled = (hasHkcu && hkcuVal == 1);

        wchar_t valSummary[128];
        if (g_remote)
        {
            swprintf_s(valSummary, 128, L"HKLM=%ls (HKCU=N/A remote)",
                hasHklm ? (hklmVal == 1 ? L"1" : L"0") : L"NOT_SET");
        }
        else
        {
            swprintf_s(valSummary, 128, L"HKLM=%ls | HKCU=%ls",
                hasHklm ? (hklmVal == 1 ? L"1" : L"0") : L"NOT_SET",
                hasHkcu ? (hkcuVal == 1 ? L"1" : L"0") : L"NOT_SET");
        }

        if (hklmEnabled && hkcuEnabled)
        {
            AddRegHardeningEntry(
                L"MSI_PRIV_ESC", L"HKLM + HKCU", instKey, L"AlwaysInstallElevated",
                valSummary, L"VULNERABLE (CRITICAL)",
                L"Both HKLM and HKCU AlwaysInstallElevated=1: any user can install MSI as SYSTEM",
                TRUE);
        }
        else if (hklmEnabled && g_remote)
        {
            AddRegHardeningEntry(
                L"MSI_PRIV_ESC", L"HKLM", instKey, L"AlwaysInstallElevated",
                valSummary, L"VULNERABLE (HIGH)",
                L"HKLM AlwaysInstallElevated=1 (exploitable if user sets HKCU AlwaysInstallElevated=1)",
                TRUE);
        }
        else if (hklmEnabled || hkcuEnabled)
        {
            AddRegHardeningEntry(
                L"MSI_PRIV_ESC", hklmEnabled ? L"HKLM" : L"HKCU", instKey, L"AlwaysInstallElevated",
                valSummary, L"PARTIAL",
                hklmEnabled
                    ? L"HKLM=1 but HKCU!=1 (any user can still set HKCU=1 to escalate)"
                    : L"HKCU=1 only (requires HKLM=1 as well to elevate privileges)",
                hklmEnabled ? TRUE : FALSE);
        }
        else
        {
            AddRegHardeningEntry(
                L"MSI_PRIV_ESC", L"HKLM + HKCU", instKey, L"AlwaysInstallElevated",
                valSummary, L"SECURE",
                L"AlwaysInstallElevated is disabled",
                FALSE);
        }
    }
}

// ==================================================
// CACHE DE ARQUIVOS (hash + assinatura por caminho)
// ==================================================

static FILE_INFO* GetFileInfo(const wchar_t* path)
{
    if (path == NULL || *path == L'\0')
        return NULL;

    for (DWORD i = 0; i < fileCacheCount; i++)
    {
        if (_wcsicmp(fileCache[i]->path, path) == 0)
            return fileCache[i];
    }

    FILE_INFO* fi = (FILE_INFO*)calloc(1, sizeof(FILE_INFO));

    if (fi == NULL)
        return NULL;

    fi->path = _wcsdup(path);

    FILE_STATE fs = QueryFile(path);

    fi->exists = (fs == FS_EXISTS);
    fi->unreachable = (fs == FS_UNREACHABLE);

    if (fs == FS_MISSING)
    {
        fi->sig = L"NOT FOUND";
    }
    else if (fs == FS_UNREACHABLE)
    {
        fi->sig = L"UNREACHABLE";
    }
    else
    {
        wchar_t acc[1200];
        BuildAccessPath(path, acc, 1200);

        if (g_doHash && !Sha256File(acc, fi->sha256))
            wcscpy_s(fi->sha256, 65, L"READ FAILED");

        if (g_doSig)
            fi->sig = VerifySignature(acc, fi->signer, SIGNER_CAP);
        else
            fi->sig = L"SKIPPED";
    }

    if (fileCacheCount == fileCacheCapacity)
    {
        DWORD newCap = fileCacheCapacity ? fileCacheCapacity * 2 : 128;

        FILE_INFO** temp = (FILE_INFO**)
            realloc(fileCache, sizeof(FILE_INFO*) * newCap);

        if (temp == NULL)
        {
            free(fi->path);
            free(fi);
            return NULL;
        }

        fileCache = temp;
        fileCacheCapacity = newCap;
    }

    fileCache[fileCacheCount++] = fi;

    return fi;
}

static void FreeFileCache(void)
{
    for (DWORD i = 0; i < fileCacheCount; i++)
    {
        free(fileCache[i]->path);
        free(fileCache[i]);
    }

    free(fileCache);
    fileCache = NULL;
    fileCacheCount = 0;
    fileCacheCapacity = 0;
}

// ==================================================
// REGISTROS
// ==================================================

static SERVICE_RECORD* NewRecord(void)
{
    if (recordCount == recordCapacity)
    {
        DWORD newCap = recordCapacity ? recordCapacity * 2 : 256;

        SERVICE_RECORD* temp = (SERVICE_RECORD*)
            realloc(records, sizeof(SERVICE_RECORD) * newCap);

        if (temp == NULL)
            return NULL;

        records = temp;
        recordCapacity = newCap;
    }

    SERVICE_RECORD* rec = &records[recordCount];
    ZeroMemory(rec, sizeof(SERVICE_RECORD));
    recordCount++;

    return rec;
}

static void FreeRecords(void)
{
    for (DWORD i = 0; i < recordCount; i++)
    {
        free(records[i].name);
        free(records[i].account);
        free(records[i].binaryPath);
        free(records[i].dependencies);
        free(records[i].loadGroup);
        free(records[i].description);
        free(records[i].imagePath);
        free(records[i].serviceDll);
        free(records[i].vulnDetails);
    }

    free(records);
    records = NULL;
    recordCount = 0;
    recordCapacity = 0;
}

static void FlagsToString(
    DWORD flags, wchar_t* buf, size_t cap, const wchar_t* sep)
{
    buf[0] = L'\0';

    for (size_t i = 0; i < FLAG_COUNT; i++)
    {
        if (!(flags & FLAG_NAMES[i].bit))
            continue;

        if (buf[0] != L'\0')
            wcscat_s(buf, cap, sep);

        wcscat_s(buf, cap, FLAG_NAMES[i].name);
    }
}

// ==================================================
// COLETA DE UM SERVICO
// ==================================================

static void EvaluateFlags(SERVICE_RECORD* rec)
{
    if (g_forense)
    {
        if (rec->imageInfo != NULL)
        {
            if (!rec->imageInfo->exists && !rec->imageInfo->unreachable)
                rec->flags |= F_IMG_MISSING;
            else if (wcscmp(rec->imageInfo->sig, L"UNSIGNED") == 0)
                rec->flags |= F_IMG_UNSIGNED;
            else if (wcscmp(rec->imageInfo->sig, L"INVALID") == 0)
                rec->flags |= F_IMG_BADSIG;
        }

        if (rec->dllInfo != NULL)
        {
            if (!rec->dllInfo->exists && !rec->dllInfo->unreachable)
                rec->flags |= F_DLL_MISSING;
            else if (wcscmp(rec->dllInfo->sig, L"UNSIGNED") == 0)
                rec->flags |= F_DLL_UNSIGNED;
            else if (wcscmp(rec->dllInfo->sig, L"INVALID") == 0)
                rec->flags |= F_DLL_BADSIG;
        }

        if (IsSuspiciousLocation(rec->imagePath) ||
            IsSuspiciousLocation(rec->serviceDll))
            rec->flags |= F_SUSP_LOC;
    }
}

static void CollectService(
    SC_HANDLE hManager,
    const ENUM_SERVICE_STATUS_PROCESSW* item)
{
    SERVICE_RECORD* rec = NewRecord();

    if (rec == NULL)
        return;

    const SERVICE_STATUS_PROCESS* status = &item->ServiceStatusProcess;

    rec->name        = DupOrNull(item->lpServiceName);
    rec->state       = status->dwCurrentState;
    rec->pid         = status->dwProcessId;
    rec->serviceType = status->dwServiceType;
    rec->queryStatus = L"OK";

    SC_HANDLE hService = OpenServiceW(
        hManager,
        item->lpServiceName,
        SERVICE_QUERY_CONFIG
    );

    if (hService == NULL)
    {
        rec->queryStatus =
            GetLastError() == ERROR_ACCESS_DENIED ?
            L"ACCESS DENIED" : L"OPEN FAILED";
    }
    else
    {
        QUERY_SERVICE_CONFIGW* config = GetServiceConfig(hService);

        if (config == NULL)
        {
            rec->queryStatus = L"QUERY FAILED";
        }
        else
        {
            rec->hasConfig    = TRUE;
            rec->startType    = config->dwStartType;
            rec->account      = DupOrNull(config->lpServiceStartName);
            rec->binaryPath   = DupOrNull(config->lpBinaryPathName);
            rec->loadGroup    = DupOrNull(config->lpLoadOrderGroup);
            rec->dependencies = GetDependencies(config->lpDependencies);

            free(config);
        }

        if (g_forense)
            rec->description = GetServiceDescription(hService);

        CloseServiceHandle(hService);
    }

    if (g_forense || g_vulnScan)
    {
        if (rec->hasConfig && rec->binaryPath && *rec->binaryPath)
        {
            wchar_t* norm = NormalizeNtPath(rec->binaryPath);

            if (norm != NULL)
            {
                if (rec->serviceType & SERVICE_DRIVER)
                {
                    rec->imagePath = norm;
                }
                else
                {
                    if (g_vulnScan && IsUnquotedPathVuln(norm))
                        rec->flags |= F_UNQUOTED;

                    rec->imagePath = ResolveWin32Image(norm);
                    free(norm);
                }

                rec->imageInfo = GetFileInfo(rec->imagePath);
            }
        }

        if (rec->serviceType & SERVICE_WIN32)
        {
            rec->serviceDll = ReadServiceDll(item->lpServiceName);
            rec->dllInfo = GetFileInfo(rec->serviceDll);
        }
    }

    if (g_vulnScan)
    {
        wchar_t details[400];
        wchar_t combined[1536] = L"";

        if (rec->flags & F_UNQUOTED)
        {
            wchar_t seg[512];
            swprintf_s(seg, 512, L"UNQUOTED_PATH[%ls]", S(rec->binaryPath));
            wcscat_s(combined, 1536, seg);
        }

        ACCESS_MASK fileMask = FILE_WRITE_DATA | FILE_APPEND_DATA |
            FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE |
            WRITE_DAC | WRITE_OWNER;

        ACCESS_MASK dirMask =
            FILE_ADD_FILE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;

        // Binario (executavel ou driver)
        if (rec->imagePath != NULL && *rec->imagePath)
        {
            if (CheckFileAcl(rec->imagePath, fileMask, details, 400))
            {
                rec->flags |= F_BINPATH_WRITABLE;

                wchar_t seg[460];
                swprintf_s(seg, 460, L"BINPATH[%ls]", details);

                if (combined[0]) wcscat_s(combined, 1536, L"; ");
                wcscat_s(combined, 1536, seg);
            }

            wchar_t* dir = GetParentDir(rec->imagePath);

            if (dir != NULL)
            {
                if (CheckFileAcl(dir, dirMask, details, 400))
                {
                    rec->flags |= F_BINPATH_DIR_WRITABLE;

                    wchar_t seg[460];
                    swprintf_s(seg, 460, L"BINPATH_DIR[%ls]", details);

                    if (combined[0]) wcscat_s(combined, 1536, L"; ");
                    wcscat_s(combined, 1536, seg);
                }

                free(dir);
            }
        }

        // ServiceDll
        if (rec->serviceDll != NULL && *rec->serviceDll)
        {
            if (CheckFileAcl(rec->serviceDll, fileMask, details, 400))
            {
                rec->flags |= F_DLL_WRITABLE;

                wchar_t seg[460];
                swprintf_s(seg, 460, L"DLL[%ls]", details);

                if (combined[0]) wcscat_s(combined, 1536, L"; ");
                wcscat_s(combined, 1536, seg);
            }

            wchar_t* dllDir = GetParentDir(rec->serviceDll);

            if (dllDir != NULL)
            {
                if (CheckFileAcl(dllDir, dirMask, details, 400))
                {
                    rec->flags |= F_DLL_DIR_WRITABLE;

                    wchar_t seg[460];
                    swprintf_s(seg, 460, L"DLL_DIR[%ls]", details);

                    if (combined[0]) wcscat_s(combined, 1536, L"; ");
                    wcscat_s(combined, 1536, seg);
                }

                free(dllDir);
            }

            if (rec->dllInfo != NULL &&
                !rec->dllInfo->exists && !rec->dllInfo->unreachable &&
                (rec->flags & F_DLL_DIR_WRITABLE))
            {
                rec->flags |= F_DLL_HIJACK;

                wchar_t seg[260];
                swprintf_s(seg, 260,
                    L"DLL_HIJACK[missing + writable dir: %ls]",
                    rec->serviceDll);

                if (combined[0]) wcscat_s(combined, 1536, L"; ");
                wcscat_s(combined, 1536, seg);
            }
        }

        // ACL do objeto de servico no SCM
        {
            SC_HANDLE hAcl = OpenServiceW(
                hManager, item->lpServiceName, READ_CONTROL);

            if (hAcl != NULL)
            {
                if (CheckServiceAcl(hAcl, details, 400))
                {
                    rec->flags |= F_SVC_WEAK_ACL;

                    wchar_t seg[460];
                    swprintf_s(seg, 460, L"SERVICE_ACL[%ls]", details);

                    if (combined[0]) wcscat_s(combined, 1536, L"; ");
                    wcscat_s(combined, 1536, seg);
                }

                CloseServiceHandle(hAcl);
            }
        }

        // Permissive Registry ACLs na chave do servico
        {
            wchar_t keyPath[640];

            swprintf_s(keyPath, 640,
                L"SYSTEM\\CurrentControlSet\\Services\\%ls",
                item->lpServiceName);

            if (CheckRegistryKeyAcl(g_hklm, keyPath, details, 400))
            {
                rec->flags |= F_SVC_REG_WEAK_ACL;

                wchar_t seg[460];
                swprintf_s(seg, 460, L"REGISTRY_ACL[%ls]", details);

                if (combined[0]) wcscat_s(combined, 1536, L"; ");
                wcscat_s(combined, 1536, seg);
            }
        }

        if (combined[0])
            rec->vulnDetails = _wcsdup(combined);
    }

    EvaluateFlags(rec);

    if (g_forense)
        AddProcess(status->dwProcessId, rec->imagePath);
}

// ==================================================
// AUTORUN (chaves Run / RunOnce) - somente --vuln-scan
// ==================================================

#define FA_KEY_WEAK            0x0001
#define FA_TARGET_MISSING      0x0002
#define FA_TARGET_WRITABLE     0x0004
#define FA_TARGET_DIR_WRITABLE 0x0008

static const struct { DWORD bit; const wchar_t* name; } AUTORUN_FLAG_NAMES[] =
{
    { FA_KEY_WEAK,            L"PERMISSIVE_REGISTRY_ACL"     },
    { FA_TARGET_MISSING,      L"AUTORUN_TARGET_MISSING"      },
    { FA_TARGET_WRITABLE,     L"WRITABLE_AUTORUN_TARGET"     },
    { FA_TARGET_DIR_WRITABLE, L"WRITABLE_AUTORUN_TARGET_DIR" }
};

#define AUTORUN_FLAG_COUNT \
    (sizeof(AUTORUN_FLAG_NAMES) / sizeof(AUTORUN_FLAG_NAMES[0]))

typedef struct
{
    wchar_t* hive;
    wchar_t* keyPath;
    wchar_t* valueName;
    wchar_t* command;
    wchar_t* resolvedPath;
    DWORD flags;
    wchar_t* details;
} AUTORUN_ENTRY;

static AUTORUN_ENTRY* autorunEntries = NULL;
static DWORD autorunCount = 0;
static DWORD autorunCapacity = 0;

static AUTORUN_ENTRY* NewAutorunEntry(void)
{
    if (autorunCount == autorunCapacity)
    {
        DWORD newCap = autorunCapacity ? autorunCapacity * 2 : 32;

        AUTORUN_ENTRY* temp = (AUTORUN_ENTRY*)
            realloc(autorunEntries, sizeof(AUTORUN_ENTRY) * newCap);

        if (temp == NULL)
            return NULL;

        autorunEntries = temp;
        autorunCapacity = newCap;
    }

    AUTORUN_ENTRY* e = &autorunEntries[autorunCount];
    ZeroMemory(e, sizeof(AUTORUN_ENTRY));
    autorunCount++;

    return e;
}

static void FreeAutorun(void)
{
    for (DWORD i = 0; i < autorunCount; i++)
    {
        free(autorunEntries[i].hive);
        free(autorunEntries[i].keyPath);
        free(autorunEntries[i].valueName);
        free(autorunEntries[i].command);
        free(autorunEntries[i].resolvedPath);
        free(autorunEntries[i].details);
    }

    free(autorunEntries);
    autorunEntries = NULL;
    autorunCount = 0;
    autorunCapacity = 0;
}

static DWORD CountAutorunFindings(void)
{
    DWORD n = 0;

    for (DWORD i = 0; i < autorunCount; i++)
    {
        if (autorunEntries[i].flags != 0)
            n++;
    }

    return n;
}

static void ScanAutorunKey(
    HKEY hKeyRoot, const wchar_t* hiveLabel,
    const wchar_t* keyPath, REGSAM extraFlags)
{
    if (hKeyRoot == NULL)
        return;

    HKEY hKey = NULL;

    if (RegOpenKeyExW(hKeyRoot, keyPath, 0,
        KEY_READ | extraFlags, &hKey) != ERROR_SUCCESS)
        return;

    wchar_t aclDetails[400];
    BOOL keyWeak = CheckRegistryKeyAcl(hKeyRoot, keyPath, aclDetails, 400);

    for (DWORD idx = 0; ; idx++)
    {
        wchar_t name[256];
        DWORD nameCap = 256;
        DWORD type = 0;
        wchar_t data[4096];
        DWORD dataCap = sizeof(data);

        LONG rc = RegEnumValueW(
            hKey, idx, name, &nameCap, NULL, &type,
            (LPBYTE)data, &dataCap);

        if (rc == ERROR_NO_MORE_ITEMS)
            break;

        if (rc != ERROR_SUCCESS)
            continue;

        if (type != REG_SZ && type != REG_EXPAND_SZ)
            continue;

        size_t maxChars = dataCap / sizeof(wchar_t);

        if (maxChars == 0)
            continue;

        if (maxChars >= 4096)
            maxChars = 4095;

        data[maxChars] = L'\0';

        AUTORUN_ENTRY* e = NewAutorunEntry();

        if (e == NULL)
            continue;

        e->hive = _wcsdup(hiveLabel);
        e->keyPath = _wcsdup(keyPath);
        e->valueName = _wcsdup(name);
        e->command = _wcsdup(data);

        wchar_t* expanded = ExpandEnv(data);
        e->resolvedPath = ResolveWin32Image(expanded ? expanded : data);
        free(expanded);

        wchar_t combined[1024] = L"";

        if (keyWeak)
        {
            e->flags |= FA_KEY_WEAK;
            wchar_t seg[460];
            swprintf_s(seg, 460, L"KEY_ACL[%ls]", aclDetails);
            wcscat_s(combined, 1024, seg);
        }

        FILE_STATE fs = QueryFile(e->resolvedPath);

        if (fs == FS_MISSING)
        {
            e->flags |= FA_TARGET_MISSING;
            if (combined[0]) wcscat_s(combined, 1024, L"; ");
            wcscat_s(combined, 1024, L"TARGET_MISSING");
        }
        else if (fs == FS_EXISTS)
        {
            wchar_t fdet[400];

            ACCESS_MASK fileMask = FILE_WRITE_DATA | FILE_APPEND_DATA |
                FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE |
                WRITE_DAC | WRITE_OWNER;

            if (CheckFileAcl(e->resolvedPath, fileMask, fdet, 400))
            {
                e->flags |= FA_TARGET_WRITABLE;
                wchar_t seg[460];
                swprintf_s(seg, 460, L"FILE_ACL[%ls]", fdet);
                if (combined[0]) wcscat_s(combined, 1024, L"; ");
                wcscat_s(combined, 1024, seg);
            }

            wchar_t* dir = GetParentDir(e->resolvedPath);

            if (dir != NULL)
            {
                ACCESS_MASK dirMask = FILE_ADD_FILE | FILE_DELETE_CHILD |
                    WRITE_DAC | WRITE_OWNER;

                if (CheckFileAcl(dir, dirMask, fdet, 400))
                {
                    e->flags |= FA_TARGET_DIR_WRITABLE;
                    wchar_t seg[460];
                    swprintf_s(seg, 460, L"DIR_ACL[%ls]", fdet);
                    if (combined[0]) wcscat_s(combined, 1024, L"; ");
                    wcscat_s(combined, 1024, seg);
                }

                free(dir);
            }
        }

        if (combined[0])
            e->details = _wcsdup(combined);
    }

    RegCloseKey(hKey);
}

static void ScanAutorun(void)
{
    static const wchar_t* keys[] =
    {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
    {
        ScanAutorunKey(g_hklm, L"HKLM", keys[i], KEY_WOW64_64KEY);
        ScanAutorunKey(g_hklm, L"HKLM", keys[i], KEY_WOW64_32KEY);
    }

    if (!g_remote)
    {
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
            ScanAutorunKey(HKEY_CURRENT_USER, L"HKCU", keys[i], 0);
    }
}

// ==================================================
// SYSTEM PATH DLL HIJACK - somente --vuln-scan
// ==================================================

#define FP_DIR_WRITABLE 0x0001
#define FP_DIR_MISSING  0x0002

typedef struct
{
    DWORD index;
    wchar_t* rawEntry;
    wchar_t* resolvedDir;
    DWORD flags;
    wchar_t* details;
} PATH_ENTRY;

static PATH_ENTRY* pathEntries = NULL;
static DWORD pathCount = 0;
static DWORD pathCapacity = 0;

static PATH_ENTRY* NewPathEntry(void)
{
    if (pathCount == pathCapacity)
    {
        DWORD newCap = pathCapacity ? pathCapacity * 2 : 32;
        PATH_ENTRY* temp = (PATH_ENTRY*)
            realloc(pathEntries, sizeof(PATH_ENTRY) * newCap);
        if (temp == NULL)
            return NULL;
        pathEntries = temp;
        pathCapacity = newCap;
    }

    PATH_ENTRY* e = &pathEntries[pathCount];
    ZeroMemory(e, sizeof(PATH_ENTRY));
    pathCount++;
    return e;
}

static void FreeSystemPath(void)
{
    for (DWORD i = 0; i < pathCount; i++)
    {
        free(pathEntries[i].rawEntry);
        free(pathEntries[i].resolvedDir);
        free(pathEntries[i].details);
    }
    free(pathEntries);
    pathEntries = NULL;
    pathCount = 0;
    pathCapacity = 0;
}

static DWORD CountPathFindings(void)
{
    DWORD n = 0;
    for (DWORD i = 0; i < pathCount; i++)
    {
        if (pathEntries[i].flags != 0)
            n++;
    }
    return n;
}

static void ScanSystemPath(void)
{
    if (g_hklm == NULL)
        return;

    const wchar_t* envKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

    wchar_t keyAclDetails[400];
    BOOL envKeyWeak = CheckRegistryKeyAcl(g_hklm, envKey, keyAclDetails, 400);

    wchar_t* rawPath = ReadRegStringAlloc(g_hklm, envKey, L"Path");
    if (rawPath == NULL)
        return;

    ACCESS_MASK dirMask =
        FILE_ADD_FILE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;

    DWORD orderIdx = 0;
    wchar_t* ctx = NULL;
    wchar_t* token = wcstok_s(rawPath, L";", &ctx);

    while (token != NULL)
    {
        while (*token == L' ' || *token == L'\t')
            token++;

        size_t len = wcslen(token);
        while (len > 0 && (token[len - 1] == L' ' || token[len - 1] == L'\t'))
            token[--len] = L'\0';

        if (len >= 2 && token[0] == L'"' && token[len - 1] == L'"')
        {
            token[len - 1] = L'\0';
            token++;
            len -= 2;
        }

        if (len > 0)
        {
            orderIdx++;
            wchar_t* expanded = ExpandEnv(token);
            const wchar_t* targetDir = expanded ? expanded : token;

            size_t elen = wcslen(targetDir);
            if (expanded && elen > 3 && expanded[elen - 1] == L'\\')
                expanded[elen - 1] = L'\0';

            DWORD flags = 0;
            wchar_t combined[640] = L"";
            wchar_t aclDet[400];

            FILE_STATE ds = QueryDir(targetDir);

            if (ds == FS_MISSING)
            {
                flags |= FP_DIR_MISSING;
                wcscpy_s(combined, 640, L"DIRECTORY_MISSING (can be created if parent is writable)");
            }
            else if (ds == FS_EXISTS)
            {
                if (CheckFileAcl(targetDir, dirMask, aclDet, 400))
                {
                    flags |= FP_DIR_WRITABLE;
                    swprintf_s(combined, 640, L"WRITABLE_PATH_DIR[%ls]", aclDet);
                }
            }

            if (flags != 0 || (envKeyWeak && orderIdx == 1))
            {
                PATH_ENTRY* pe = NewPathEntry();
                if (pe != NULL)
                {
                    pe->index = orderIdx;
                    pe->rawEntry = _wcsdup(token);
                    pe->resolvedDir = _wcsdup(targetDir);
                    pe->flags = flags;
                    if (envKeyWeak && orderIdx == 1)
                    {
                        if (combined[0]) wcscat_s(combined, 640, L"; ");
                        wcscat_s(combined, 640, L"ENV_KEY_ACL[");
                        wcscat_s(combined, 640, keyAclDetails);
                        wcscat_s(combined, 640, L"]");
                    }
                    pe->details = combined[0] ? _wcsdup(combined) : NULL;
                }
            }

            free(expanded);
        }

        token = wcstok_s(NULL, L";", &ctx);
    }

    free(rawPath);
}

// ==================================================
// SCHEDULED TASKS - somente --vuln-scan
// ==================================================

#define FT_XML_WRITABLE        0x0001
#define FT_TARGET_MISSING      0x0002
#define FT_TARGET_WRITABLE     0x0004
#define FT_TARGET_DIR_WRITABLE 0x0008

static const struct { DWORD bit; const wchar_t* name; } TASK_FLAG_NAMES[] =
{
    { FT_XML_WRITABLE,        L"WRITABLE_TASK_XML"        },
    { FT_TARGET_MISSING,      L"TASK_TARGET_MISSING"      },
    { FT_TARGET_WRITABLE,     L"WRITABLE_TASK_TARGET"     },
    { FT_TARGET_DIR_WRITABLE, L"WRITABLE_TASK_TARGET_DIR" }
};

#define TASK_FLAG_COUNT (sizeof(TASK_FLAG_NAMES) / sizeof(TASK_FLAG_NAMES[0]))

typedef struct
{
    wchar_t* taskName;
    wchar_t* principal;
    wchar_t* command;
    wchar_t* resolvedPath;
    DWORD flags;
    wchar_t* details;
} TASK_ENTRY;

static TASK_ENTRY* taskEntries = NULL;
static DWORD taskCount = 0;
static DWORD taskCapacity = 0;

static TASK_ENTRY* NewTaskEntry(void)
{
    if (taskCount == taskCapacity)
    {
        DWORD newCap = taskCapacity ? taskCapacity * 2 : 32;
        TASK_ENTRY* temp = (TASK_ENTRY*)
            realloc(taskEntries, sizeof(TASK_ENTRY) * newCap);
        if (temp == NULL)
            return NULL;
        taskEntries = temp;
        taskCapacity = newCap;
    }

    TASK_ENTRY* t = &taskEntries[taskCount];
    ZeroMemory(t, sizeof(TASK_ENTRY));
    taskCount++;
    return t;
}

static void FreeTasks(void)
{
    for (DWORD i = 0; i < taskCount; i++)
    {
        free(taskEntries[i].taskName);
        free(taskEntries[i].principal);
        free(taskEntries[i].command);
        free(taskEntries[i].resolvedPath);
        free(taskEntries[i].details);
    }
    free(taskEntries);
    taskEntries = NULL;
    taskCount = 0;
    taskCapacity = 0;
}

static DWORD CountTaskFindings(void)
{
    DWORD n = 0;
    for (DWORD i = 0; i < taskCount; i++)
    {
        if (taskEntries[i].flags != 0)
            n++;
    }
    return n;
}

static wchar_t* ExtractXmlTag(const wchar_t* xml, const wchar_t* openTag, const wchar_t* closeTag)
{
    const wchar_t* start = FindI(xml, openTag);
    if (start == NULL)
        return NULL;

    start += wcslen(openTag);
    const wchar_t* end = FindI(start, closeTag);
    if (end == NULL || end <= start)
        return NULL;

    while (start < end && (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n'))
        start++;

    while (end > start && (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n'))
        end--;

    return DupN(start, (size_t)(end - start));
}

static wchar_t* ReadTaskXmlFile(const wchar_t* localStylePath)
{
    wchar_t acc[1200];
    BuildAccessPath(localStylePath, acc, 1200);

    HANDLE hFile = CreateFileW(
        acc, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0 || liSize.QuadPart > 1048576)
    {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytes = (DWORD)liSize.QuadPart;
    BYTE* raw = (BYTE*)malloc(bytes + 4);
    if (raw == NULL)
    {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD read = 0;
    BOOL ok = ReadFile(hFile, raw, bytes, &read, NULL);
    CloseHandle(hFile);

    if (!ok || read < 4)
    {
        free(raw);
        return NULL;
    }

    raw[read] = 0;
    raw[read + 1] = 0;

    wchar_t* wcontent = NULL;

    if (raw[0] == 0xFF && raw[1] == 0xFE)
    {
        size_t wchars = (read - 2) / sizeof(wchar_t);
        wcontent = (wchar_t*)calloc(wchars + 1, sizeof(wchar_t));
        if (wcontent != NULL)
            wmemcpy(wcontent, (const wchar_t*)(raw + 2), wchars);
    }
    else
    {
        const char* utf8 = (const char*)raw;
        DWORD offset = 0;
        if (read >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
            offset = 3;

        int needed = MultiByteToWideChar(CP_UTF8, 0, utf8 + offset, (int)(read - offset), NULL, 0);
        if (needed > 0)
        {
            wcontent = (wchar_t*)calloc((size_t)needed + 1, sizeof(wchar_t));
            if (wcontent != NULL)
                MultiByteToWideChar(CP_UTF8, 0, utf8 + offset, (int)(read - offset), wcontent, needed);
        }
    }

    free(raw);
    return wcontent;
}

static void InspectTaskXml(const wchar_t* relTaskName, const wchar_t* fullTaskPath)
{
    wchar_t* xml = ReadTaskXmlFile(fullTaskPath);
    if (xml == NULL)
        return;

    wchar_t* cmd = ExtractXmlTag(xml, L"<Command>", L"</Command>");
    wchar_t* userId = ExtractXmlTag(xml, L"<UserId>", L"</UserId>");
    wchar_t* runLevel = ExtractXmlTag(xml, L"<RunLevel>", L"</RunLevel>");

    wchar_t principalBuf[256];
    swprintf_s(principalBuf, 256, L"%ls%ls%ls",
        userId ? userId : L"DEFAULT",
        runLevel ? L" (" : L"",
        runLevel ? runLevel : L"");
    if (runLevel)
        wcscat_s(principalBuf, 256, L")");

    DWORD flags = 0;
    wchar_t combined[1200] = L"";
    wchar_t aclDet[400];

    ACCESS_MASK fileMask = FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE |
        WRITE_DAC | WRITE_OWNER;

    ACCESS_MASK dirMask = FILE_ADD_FILE | FILE_DELETE_CHILD |
        WRITE_DAC | WRITE_OWNER;

    if (CheckFileAcl(fullTaskPath, fileMask, aclDet, 400))
    {
        flags |= FT_XML_WRITABLE;
        wchar_t seg[460];
        swprintf_s(seg, 460, L"TASK_XML_ACL[%ls]", aclDet);
        wcscat_s(combined, 1200, seg);
    }

    wchar_t* resolved = NULL;
    if (cmd != NULL && *cmd)
    {
        wchar_t* expanded = ExpandEnv(cmd);
        const wchar_t* targetCmd = expanded ? expanded : cmd;

        if (wcschr(targetCmd, L'\\') == NULL && targetCmd[0] != L'"')
        {
            wchar_t sysCandidate[MAX_PATH];
            swprintf_s(sysCandidate, MAX_PATH, L"%ls\\System32\\%ls", g_sysRoot, targetCmd);
            resolved = ResolveWin32Image(sysCandidate);
        }
        else
        {
            resolved = ResolveWin32Image(targetCmd);
        }

        free(expanded);

        if (resolved != NULL && *resolved)
        {
            FILE_STATE fs = QueryFile(resolved);

            if (fs == FS_MISSING)
            {
                flags |= FT_TARGET_MISSING;
                if (combined[0]) wcscat_s(combined, 1200, L"; ");
                wcscat_s(combined, 1200, L"TARGET_MISSING");
            }
            else if (fs == FS_EXISTS)
            {
                if (CheckFileAcl(resolved, fileMask, aclDet, 400))
                {
                    flags |= FT_TARGET_WRITABLE;
                    wchar_t seg[460];
                    swprintf_s(seg, 460, L"TARGET_ACL[%ls]", aclDet);
                    if (combined[0]) wcscat_s(combined, 1200, L"; ");
                    wcscat_s(combined, 1200, seg);
                }

                wchar_t* parentDir = GetParentDir(resolved);
                if (parentDir != NULL)
                {
                    if (CheckFileAcl(parentDir, dirMask, aclDet, 400))
                    {
                        flags |= FT_TARGET_DIR_WRITABLE;
                        wchar_t seg[460];
                        swprintf_s(seg, 460, L"TARGET_DIR_ACL[%ls]", aclDet);
                        if (combined[0]) wcscat_s(combined, 1200, L"; ");
                        wcscat_s(combined, 1200, seg);
                    }
                    free(parentDir);
                }
            }
        }
    }

    TASK_ENTRY* te = NewTaskEntry();
    if (te != NULL)
    {
        te->taskName = _wcsdup(relTaskName);
        te->principal = _wcsdup(principalBuf);
        te->command = cmd;
        te->resolvedPath = resolved;
        te->flags = flags;
        te->details = combined[0] ? _wcsdup(combined) : NULL;
    }
    else
    {
        free(cmd);
        free(resolved);
    }

    free(userId);
    free(runLevel);
    free(xml);
}

static void ScanTasksDirRecursive(const wchar_t* baseTasksDir, const wchar_t* subDir)
{
    wchar_t localDir[1024];
    wchar_t searchPattern[1200];

    if (subDir[0] != L'\0')
        swprintf_s(localDir, 1024, L"%ls\\%ls", baseTasksDir, subDir);
    else
        wcscpy_s(localDir, 1024, baseTasksDir);

    BuildAccessPath(localDir, searchPattern, 1200);
    wcscat_s(searchPattern, 1200, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t nextRel[1024];
        if (subDir[0] != L'\0')
            swprintf_s(nextRel, 1024, L"%ls\\%ls", subDir, fd.cFileName);
        else
            wcscpy_s(nextRel, 1024, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ScanTasksDirRecursive(baseTasksDir, nextRel);
        }
        else
        {
            wchar_t fullLocal[1024];
            swprintf_s(fullLocal, 1024, L"%ls\\%ls", baseTasksDir, nextRel);
            InspectTaskXml(nextRel, fullLocal);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

static void ScanScheduledTasks(void)
{
    if (g_remote && g_filesUnreachable)
        return;

    wchar_t tasksRoot[MAX_PATH];
    swprintf_s(tasksRoot, MAX_PATH, L"%ls\\System32\\Tasks", g_sysRoot);
    ScanTasksDirRecursive(tasksRoot, L"");
}

// ==================================================
// SAIDA: UTILITARIOS
// ==================================================

static void PrintLine(wchar_t ch, int width)
{
    for (int i = 0; i < width; i++)
        fputwc(ch, g_out);

    fputwc(L'\n', g_out);
}

static void CsvField(const wchar_t* s, BOOL last)
{
    fputwc(L'"', g_out);

    for (s = S(s); *s; s++)
    {
        if (*s == L'"')
            fputwc(L'"', g_out);

        fputwc(*s, g_out);
    }

    fputwc(L'"', g_out);
    fputwc(last ? L'\n' : L',', g_out);
}

static void JsonString(const wchar_t* s)
{
    if (s == NULL)
    {
        fputws(L"null", g_out);
        return;
    }

    fputwc(L'"', g_out);

    for (; *s; s++)
    {
        switch (*s)
        {
        case L'"':  fputws(L"\\\"", g_out); break;
        case L'\\': fputws(L"\\\\", g_out); break;
        case L'\n': fputws(L"\\n", g_out);  break;
        case L'\r': fputws(L"\\r", g_out);  break;
        case L'\t': fputws(L"\\t", g_out);  break;
        default:
            if (*s < 0x20)
                fwprintf(g_out, L"\\u%04x", (unsigned)*s);
            else
                fputwc(*s, g_out);
        }
    }

    fputwc(L'"', g_out);
}

static void JsonKeyStr(const wchar_t* key, const wchar_t* val, BOOL first)
{
    fwprintf(g_out, L"%ls\n      \"%ls\": ", first ? L"" : L",", key);
    JsonString(val);
}

static void JsonKeyNum(const wchar_t* key, DWORD val, BOOL first)
{
    fwprintf(g_out, L"%ls\n      \"%ls\": %lu",
        first ? L"" : L",", key, val);
}

static void JsonFileInfo(const FILE_INFO* fi)
{
    if (fi == NULL)
    {
        fputws(L"null", g_out);
        return;
    }

    fputws(L"{ \"path\": ", g_out);
    JsonString(fi->path);
    fwprintf(g_out, L", \"exists\": %ls, \"sha256\": ",
        fi->exists ? L"true" : L"false");
    JsonString(fi->sha256[0] ? fi->sha256 : NULL);
    fputws(L", \"signature\": ", g_out);
    JsonString(fi->sig);
    fputws(L", \"signer\": ", g_out);
    JsonString(fi->signer[0] ? fi->signer : NULL);
    fputws(L" }", g_out);
}

// ==================================================
// SAIDA: TABELAS
// ==================================================

#define INV_LINE_WIDTH     112
#define CFG_LINE_WIDTH     144
#define BIN_LINE_WIDTH     188
#define PROC_LINE_WIDTH    94
#define FIND_LINE_WIDTH    170
#define HARDEN_LINE_WIDTH  185
#define AUTORUN_LINE_WIDTH 185
#define PATH_LINE_WIDTH    175
#define TASK_LINE_WIDTH    185

static void PrintTitle(wchar_t ch, int width, const wchar_t* title)
{
    int pad = (width - (int)wcslen(title)) / 2;

    fputwc(L'\n', g_out);
    PrintLine(ch, width);
    fwprintf(g_out, L"%*ls%ls\n", pad > 0 ? pad : 0, L"", title);
    PrintLine(ch, width);
}

static void PrintInventoryTable(void)
{
    PrintTitle(L'=', INV_LINE_WIDTH, L"SERVICE INVENTORY");

    fwprintf(g_out,
        L"%-20ls %-16ls %-8ls %-14ls %-10ls %-22ls %-14ls\n",
        L"SERVICE NAME", L"STATE", L"PID", L"TYPE",
        L"START TYPE", L"ACCOUNT", L"QUERY");

    PrintLine(L'-', INV_LINE_WIDTH);

    for (DWORD i = 0; i < recordCount; i++)
    {
        const SERVICE_RECORD* r = &records[i];

        fwprintf(g_out,
            L"%-20.20ls %-16ls %-8lu %-14ls %-10ls %-22.22ls %-14ls\n",
            S(r->name),
            GetState(r->state),
            r->pid,
            GetServiceType(r->serviceType),
            r->hasConfig ? GetStartType(r->startType) : L"UNKNOWN",
            r->hasConfig ? S(r->account) : L"UNAVAILABLE",
            r->queryStatus);
    }

    PrintLine(L'-', INV_LINE_WIDTH);
    fwprintf(g_out, L"Total services: %lu\n", recordCount);
}

static void PrintConfigurationTable(void)
{
    PrintTitle(L'=', CFG_LINE_WIDTH, L"SERVICE CONFIGURATION");

    fwprintf(g_out, L"%-20ls %-45ls %-25ls %-18ls %-30ls\n",
        L"SERVICE NAME", L"BINARY PATH", L"DEPENDENCIES",
        L"LOAD GROUP", L"DESCRIPTION");

    PrintLine(L'-', CFG_LINE_WIDTH);

    for (DWORD i = 0; i < recordCount; i++)
    {
        const SERVICE_RECORD* r = &records[i];

        fwprintf(g_out,
            L"%-20.20ls %-45.45ls %-25.25ls %-18.18ls %-30.30ls\n",
            S(r->name),
            r->hasConfig ? S(r->binaryPath) : L"UNAVAILABLE",
            r->hasConfig ? S(r->dependencies) : L"UNAVAILABLE",
            r->hasConfig ? S(r->loadGroup) : L"",
            r->description ? r->description : L"UNAVAILABLE");
    }
}

static void PrintBinaryRow(
    const wchar_t* name, const wchar_t* kind, const FILE_INFO* fi)
{
    if (fi == NULL)
        return;

    fwprintf(g_out,
        L"%-20.20ls %-6ls %-18ls %-24.24ls %-64ls %-50.50ls\n",
        S(name),
        kind,
        fi->sig,
        Dash(fi->signer),
        Dash(fi->sha256),
        S(fi->path));
}

static void PrintBinaryTable(void)
{
    PrintTitle(L'=', BIN_LINE_WIDTH, L"BINARY ANALYSIS");

    fwprintf(g_out, L"%-20ls %-6ls %-18ls %-24ls %-64ls %-50ls\n",
        L"SERVICE NAME", L"TARGET", L"SIGNATURE", L"SIGNER",
        L"SHA-256", L"PATH");

    PrintLine(L'-', BIN_LINE_WIDTH);

    for (DWORD i = 0; i < recordCount; i++)
    {
        PrintBinaryRow(records[i].name, L"IMAGE", records[i].imageInfo);
        PrintBinaryRow(records[i].name, L"DLL", records[i].dllInfo);
    }

    PrintLine(L'-', BIN_LINE_WIDTH);
    fwprintf(g_out, L"Unique files analyzed: %lu\n", fileCacheCount);
}

static void PrintFindingsTable(DWORD filterMask, const wchar_t* title)
{
    PrintTitle(L'=', FIND_LINE_WIDTH, title);

    fwprintf(g_out, L"%-25ls %-48ls %ls\n",
        L"SERVICE NAME", L"FLAGS", L"DETAILS");
    PrintLine(L'-', FIND_LINE_WIDTH);

    DWORD count = 0;

    for (DWORD i = 0; i < recordCount; i++)
    {
        DWORD maskedFlags = records[i].flags & filterMask;

        if (maskedFlags == 0)
            continue;

        wchar_t flags[256];
        FlagsToString(maskedFlags, flags, 256, L";");

        fwprintf(g_out, L"%-25.25ls %-48.48ls %ls\n",
            S(records[i].name), flags, Dash(records[i].vulnDetails));
        count++;
    }

    if (count == 0)
        fputws(L"No findings.\n", g_out);

    PrintLine(L'-', FIND_LINE_WIDTH);
    fwprintf(g_out, L"Services with findings: %lu\n", count);
}

static void PrintRegHardeningTable(void)
{
    PrintTitle(L'=', HARDEN_LINE_WIDTH,
        L"REGISTRY HARDENING (SafeDllSearchMode / CWDIllegalInDllSearch / AlwaysInstallElevated)");

    fwprintf(g_out, L"%-22ls %-12ls %-24ls %-26ls %-24ls %ls\n",
        L"CATEGORY", L"HIVE", L"SETTING", L"VALUE", L"STATUS", L"ASSESSMENT");

    PrintLine(L'-', HARDEN_LINE_WIDTH);

    for (DWORD i = 0; i < regHardeningCount; i++)
    {
        const REG_HARDENING_ENTRY* e = &regHardeningEntries[i];
        fwprintf(g_out, L"%-22.22ls %-12.12ls %-24.24ls %-26.26ls %-24.24ls %ls\n",
            S(e->category), S(e->hive), S(e->valueName),
            S(e->rawValue), S(e->status), S(e->details));
    }

    PrintLine(L'-', HARDEN_LINE_WIDTH);
    fwprintf(g_out, L"Registry hardening issues: %lu (of %lu checked)\n",
        CountRegHardeningFindings(), regHardeningCount);
}

static void PrintAutorunTable(void)
{
    PrintTitle(L'=', AUTORUN_LINE_WIDTH, L"AUTORUN (MODIFIABLE PERMISSIONS / TARGETS)");

    fwprintf(g_out, L"%-6ls %-42ls %-32ls %-45ls %ls\n",
        L"HIVE", L"KEY \\ VALUE", L"FLAGS", L"TARGET", L"PERMISSIONS / DETAILS");

    PrintLine(L'-', AUTORUN_LINE_WIDTH);

    DWORD shown = 0;

    for (DWORD i = 0; i < autorunCount; i++)
    {
        const AUTORUN_ENTRY* e = &autorunEntries[i];

        if (e->flags == 0)
            continue;

        wchar_t keyLabel[300];
        swprintf_s(keyLabel, 300, L"%ls\\%ls", S(e->keyPath), S(e->valueName));

        wchar_t flagsStr[256];
        flagsStr[0] = L'\0';

        for (size_t f = 0; f < AUTORUN_FLAG_COUNT; f++)
        {
            if (!(e->flags & AUTORUN_FLAG_NAMES[f].bit))
                continue;

            if (flagsStr[0])
                wcscat_s(flagsStr, 256, L";");

            wcscat_s(flagsStr, 256, AUTORUN_FLAG_NAMES[f].name);
        }

        fwprintf(g_out, L"%-6ls %-42.42ls %-32.32ls %-45.45ls %ls\n",
            S(e->hive), keyLabel, flagsStr, S(e->resolvedPath), Dash(e->details));

        shown++;
    }

    if (shown == 0)
        fputws(L"No findings.\n", g_out);

    PrintLine(L'-', AUTORUN_LINE_WIDTH);
    fwprintf(g_out, L"Autorun entries with findings: %lu (of %lu scanned)\n",
        shown, autorunCount);
}

static void PrintSystemPathTable(void)
{
    PrintTitle(L'=', PATH_LINE_WIDTH, L"SYSTEM PATH DLL HIJACK (WRITABLE / MISSING DIRECTORIES)");

    fwprintf(g_out, L"%-6ls %-28ls %-55ls %ls\n",
        L"ORDER", L"FLAGS", L"PATH DIRECTORY", L"PERMISSIONS / DETAILS");

    PrintLine(L'-', PATH_LINE_WIDTH);

    DWORD shown = 0;

    for (DWORD i = 0; i < pathCount; i++)
    {
        const PATH_ENTRY* pe = &pathEntries[i];

        wchar_t flagsStr[128] = L"";
        if (pe->flags & FP_DIR_WRITABLE)
            wcscat_s(flagsStr, 128, L"PATH_DIR_WRITABLE");
        if (pe->flags & FP_DIR_MISSING)
        {
            if (flagsStr[0]) wcscat_s(flagsStr, 128, L";");
            wcscat_s(flagsStr, 128, L"PATH_DIR_MISSING");
        }
        if (flagsStr[0] == L'\0')
            wcscpy_s(flagsStr, 128, L"PERMISSIVE_ENV_KEY");

        fwprintf(g_out, L"%-6lu %-28.28ls %-55.55ls %ls\n",
            pe->index, flagsStr, S(pe->resolvedDir), Dash(pe->details));
        shown++;
    }

    if (shown == 0)
        fputws(L"No vulnerable directories found in system PATH.\n", g_out);

    PrintLine(L'-', PATH_LINE_WIDTH);
    fwprintf(g_out, L"Vulnerable PATH entries: %lu\n", shown);
}

static void PrintScheduledTasksTable(void)
{
    PrintTitle(L'=', TASK_LINE_WIDTH, L"SCHEDULED TASKS (MODIFIABLE XML / TARGET / DIRECTORY ACLs)");

    fwprintf(g_out, L"%-38ls %-22ls %-32ls %-40ls %ls\n",
        L"TASK NAME", L"RUN AS", L"FLAGS", L"TARGET BINARY", L"PERMISSIONS / DETAILS");

    PrintLine(L'-', TASK_LINE_WIDTH);

    DWORD shown = 0;

    for (DWORD i = 0; i < taskCount; i++)
    {
        const TASK_ENTRY* te = &taskEntries[i];
        if (te->flags == 0)
            continue;

        wchar_t flagsStr[256] = L"";
        for (size_t f = 0; f < TASK_FLAG_COUNT; f++)
        {
            if (!(te->flags & TASK_FLAG_NAMES[f].bit))
                continue;

            if (flagsStr[0])
                wcscat_s(flagsStr, 256, L";");
            wcscat_s(flagsStr, 256, TASK_FLAG_NAMES[f].name);
        }

        fwprintf(g_out, L"%-38.38ls %-22.22ls %-32.32ls %-40.40ls %ls\n",
            S(te->taskName), S(te->principal), flagsStr,
            Dash(te->resolvedPath), Dash(te->details));
        shown++;
    }

    if (shown == 0)
        fputws(L"No findings.\n", g_out);

    PrintLine(L'-', TASK_LINE_WIDTH);
    fwprintf(g_out, L"Scheduled tasks with findings: %lu (of %lu scanned)\n",
        shown, taskCount);
}

static void PrintProcessTable(void)
{
    PrintTitle(L'=', PROC_LINE_WIDTH, L"PROCESS CORRELATION");

    fwprintf(g_out, L"%-10ls %-65ls %-15ls\n",
        L"PID", L"PROCESS IMAGE", L"SERVICE COUNT");

    PrintLine(L'-', PROC_LINE_WIDTH);

    for (DWORD i = 0; i < processCount; i++)
    {
        fwprintf(g_out, L"%-10lu %-65.65ls %-15lu\n",
            processes[i].pid,
            processes[i].image,
            processes[i].serviceCount);
    }

    PrintLine(L'-', PROC_LINE_WIDTH);
    fwprintf(g_out, L"Unique processes: %lu\n", processCount);

    if (g_remote)
        fputws(L"Note: remote mode - process images are inferred from the "
               L"service configuration, not read from live processes.\n",
               g_out);
}

static DWORD CountDenied(void)
{
    DWORD denied = 0;

    for (DWORD i = 0; i < recordCount; i++)
    {
        if (wcscmp(records[i].queryStatus, L"ACCESS DENIED") == 0)
            denied++;
    }

    return denied;
}

static DWORD CountFindings(DWORD mask)
{
    DWORD n = 0;

    for (DWORD i = 0; i < recordCount; i++)
    {
        if ((records[i].flags & mask) != 0)
            n++;
    }

    return n;
}

static void OutputTable(
    const wchar_t* host, const SYSTEMTIME* st, BOOL complete)
{
    // 1. Sem parametros: retorna APENAS SERVICE INVENTORY
    if (!g_forense && !g_vulnScan)
    {
        PrintInventoryTable();

        if (CountDenied() > 0)
        {
            fputwc(L'\n', g_out);
            fputws(L"Note: run as Administrator for complete data.\n", g_out);
        }

        return;
    }

    fputwc(L'\n', g_out);
    PrintLine(L'=', 60);
    fputws(L"             WINDOWS SERVICE FORENSIC COLLECTOR\n", g_out);
    PrintLine(L'=', 60);

    fwprintf(g_out, L"Host:            %ls\n", host);
    fwprintf(g_out, L"Mode:            %ls%ls%ls\n",
        g_remote ? L"REMOTE (" : L"LOCAL",
        g_remote ? g_target : L"",
        g_remote ? L")" : L"");
    fwprintf(g_out, L"Collection date: %04d-%02d-%02d\n",
        st->wYear, st->wMonth, st->wDay);
    fwprintf(g_out, L"Collection time: %02d:%02d:%02d\n",
        st->wHour, st->wMinute, st->wSecond);

    if (g_forense)
        fwprintf(g_out, L"Hashing: %ls | Signature check: %ls\n",
            g_doHash ? L"ON" : L"OFF", g_doSig ? L"ON" : L"OFF");

    fwprintf(g_out, L"Mode flags:      %ls%ls\n",
        g_forense ? L"--forense " : L"",
        g_vulnScan ? L"--vuln-scan " : L"");

    PrintLine(L'=', 60);

    // 2. --forense: SERVICE INVENTORY, PROCESS CORRELATION, FINDINGS,
    //    BINARY ANALYSIS e SERVICE CONFIGURATION
    if (g_forense)
    {
        PrintInventoryTable();
        PrintProcessTable();
        PrintFindingsTable(FORENSE_FLAGS_MASK, L"FINDINGS");
        PrintBinaryTable();
        PrintConfigurationTable();
    }

    // 3. --vuln-scan: REGISTRY HARDENING, AUTORUN, SYSTEM PATH DLL HIJACK,
    //    SCHEDULED TASKS e VULNERABILITY FINDINGS nos servicos
    if (g_vulnScan)
    {
        PrintRegHardeningTable();
        PrintAutorunTable();
        PrintSystemPathTable();
        PrintScheduledTasksTable();
        PrintFindingsTable(
            VULN_FLAGS_MASK,
            L"VULNERABILITY FINDINGS (DLL HIJACK / UNQUOTED PATH / WRITABLE BINPATH / PERMISSIVE ACLs)"
        );
    }

    DWORD denied = CountDenied();

    fputwc(L'\n', g_out);
    PrintLine(L'=', 60);
    fputws(L"                 COLLECTION SUMMARY\n", g_out);
    PrintLine(L'=', 60);

    fwprintf(g_out, L"Services enumerated:       %lu\n", recordCount);

    if (g_forense)
    {
        fwprintf(g_out, L"Unique processes:          %lu\n", processCount);
        fwprintf(g_out, L"Files analyzed:            %lu\n", fileCacheCount);
        fwprintf(g_out, L"Forensic findings:         %lu\n",
            CountFindings(FORENSE_FLAGS_MASK));
    }

    if (g_vulnScan)
    {
        fwprintf(g_out, L"Registry hardening issues: %lu\n",
            CountRegHardeningFindings());
        fwprintf(g_out, L"Service vuln findings:     %lu\n",
            CountFindings(VULN_FLAGS_MASK));
        fwprintf(g_out, L"Autorun findings:          %lu\n",
            CountAutorunFindings());
        fwprintf(g_out, L"System PATH findings:      %lu\n",
            CountPathFindings());
        fwprintf(g_out, L"Scheduled tasks findings:  %lu (of %lu scanned)\n",
            CountTaskFindings(), taskCount);
    }

    fwprintf(g_out, L"Access denied:             %lu\n", denied);
    fwprintf(g_out, L"Enumeration status:        %ls\n",
        complete ? L"COMPLETE" : L"INCOMPLETE");

    if (denied > 0)
        fputws(L"Note: run as Administrator for complete data.\n", g_out);

    if (g_remote && g_forense)
        fputws(L"Note: remote mode - catalog signatures are not checked "
               L"(NO EMBEDDED SIG is not flagged).\n", g_out);

    if (g_vulnScan)
        fputws(L"Note: ACL checks evaluate ALLOW aces for low-privilege "
               L"principals (Everyone, Authenticated Users, BUILTIN\\Users, "
               L"INTERACTIVE).\n", g_out);

    PrintLine(L'=', 60);
}

// ==================================================
// SAIDA: CSV
// ==================================================

static void CsvFileColumns(const FILE_INFO* fi, const wchar_t* path, BOOL last)
{
    CsvField(path, FALSE);
    CsvField(fi ? (fi->exists ? L"true" : L"false") : L"", FALSE);
    CsvField(fi ? fi->sha256 : L"", FALSE);
    CsvField(fi ? fi->sig : L"", FALSE);
    CsvField(fi ? fi->signer : L"", last);
}

static void OutputVulnExtraCsvSections(void)
{
    if (regHardeningCount > 0)
    {
        fputwc(L'\n', g_out);
        static const wchar_t* hcols[] =
        {
            L"section", L"category", L"hive", L"key",
            L"value_name", L"value", L"status", L"details"
        };
        size_t hn = sizeof(hcols) / sizeof(hcols[0]);
        for (size_t i = 0; i < hn; i++)
            CsvField(hcols[i], i == hn - 1);

        for (DWORD i = 0; i < regHardeningCount; i++)
        {
            const REG_HARDENING_ENTRY* e = &regHardeningEntries[i];
            CsvField(L"REGISTRY_HARDENING", FALSE);
            CsvField(e->category, FALSE);
            CsvField(e->hive, FALSE);
            CsvField(e->keyPath, FALSE);
            CsvField(e->valueName, FALSE);
            CsvField(e->rawValue, FALSE);
            CsvField(e->status, FALSE);
            CsvField(e->details, TRUE);
        }
    }

    if (autorunCount > 0)
    {
        fputwc(L'\n', g_out);
        static const wchar_t* acols[] =
        {
            L"section", L"hive", L"key", L"value_name", L"command",
            L"resolved_path", L"flags", L"details"
        };
        size_t an = sizeof(acols) / sizeof(acols[0]);
        for (size_t i = 0; i < an; i++)
            CsvField(acols[i], i == an - 1);

        for (DWORD i = 0; i < autorunCount; i++)
        {
            const AUTORUN_ENTRY* e = &autorunEntries[i];
            if (e->flags == 0)
                continue;

            wchar_t flagsStr[256] = L"";
            for (size_t f = 0; f < AUTORUN_FLAG_COUNT; f++)
            {
                if (!(e->flags & AUTORUN_FLAG_NAMES[f].bit))
                    continue;
                if (flagsStr[0]) wcscat_s(flagsStr, 256, L";");
                wcscat_s(flagsStr, 256, AUTORUN_FLAG_NAMES[f].name);
            }

            CsvField(L"AUTORUN", FALSE);
            CsvField(e->hive, FALSE);
            CsvField(e->keyPath, FALSE);
            CsvField(e->valueName, FALSE);
            CsvField(e->command, FALSE);
            CsvField(e->resolvedPath, FALSE);
            CsvField(flagsStr, FALSE);
            CsvField(e->details, TRUE);
        }
    }

    if (pathCount > 0)
    {
        fputwc(L'\n', g_out);
        static const wchar_t* pcols[] =
        {
            L"section", L"order", L"raw_entry", L"resolved_dir", L"flags", L"details"
        };
        size_t pn = sizeof(pcols) / sizeof(pcols[0]);
        for (size_t i = 0; i < pn; i++)
            CsvField(pcols[i], i == pn - 1);

        for (DWORD i = 0; i < pathCount; i++)
        {
            const PATH_ENTRY* pe = &pathEntries[i];
            wchar_t ord[16];
            swprintf_s(ord, 16, L"%lu", pe->index);

            wchar_t flagsStr[128] = L"";
            if (pe->flags & FP_DIR_WRITABLE)
                wcscat_s(flagsStr, 128, L"PATH_DIR_WRITABLE");
            if (pe->flags & FP_DIR_MISSING)
            {
                if (flagsStr[0]) wcscat_s(flagsStr, 128, L";");
                wcscat_s(flagsStr, 128, L"PATH_DIR_MISSING");
            }
            if (flagsStr[0] == L'\0')
                wcscpy_s(flagsStr, 128, L"PERMISSIVE_ENV_KEY");

            CsvField(L"SYSTEM_PATH", FALSE);
            CsvField(ord, FALSE);
            CsvField(pe->rawEntry, FALSE);
            CsvField(pe->resolvedDir, FALSE);
            CsvField(flagsStr, FALSE);
            CsvField(pe->details, TRUE);
        }
    }

    if (taskCount > 0)
    {
        fputwc(L'\n', g_out);
        static const wchar_t* tcols[] =
        {
            L"section", L"task_name", L"principal", L"command",
            L"resolved_path", L"flags", L"details"
        };
        size_t tn = sizeof(tcols) / sizeof(tcols[0]);
        for (size_t i = 0; i < tn; i++)
            CsvField(tcols[i], i == tn - 1);

        for (DWORD i = 0; i < taskCount; i++)
        {
            const TASK_ENTRY* te = &taskEntries[i];
            if (te->flags == 0)
                continue;

            wchar_t flagsStr[256] = L"";
            for (size_t f = 0; f < TASK_FLAG_COUNT; f++)
            {
                if (!(te->flags & TASK_FLAG_NAMES[f].bit))
                    continue;
                if (flagsStr[0]) wcscat_s(flagsStr, 256, L";");
                wcscat_s(flagsStr, 256, TASK_FLAG_NAMES[f].name);
            }

            CsvField(L"SCHEDULED_TASK", FALSE);
            CsvField(te->taskName, FALSE);
            CsvField(te->principal, FALSE);
            CsvField(te->command, FALSE);
            CsvField(te->resolvedPath, FALSE);
            CsvField(flagsStr, FALSE);
            CsvField(te->details, TRUE);
        }
    }
}

static void OutputCsv(void)
{
    if (!g_forense && !g_vulnScan)
    {
        static const wchar_t* invCols[] =
        {
            L"host", L"name", L"state", L"pid", L"type",
            L"start_type", L"account", L"query_status"
        };

        size_t n = sizeof(invCols) / sizeof(invCols[0]);

        for (size_t i = 0; i < n; i++)
            CsvField(invCols[i], i == n - 1);

        for (DWORD i = 0; i < recordCount; i++)
        {
            const SERVICE_RECORD* r = &records[i];
            wchar_t num[16];

            CsvField(g_hostLabel, FALSE);
            CsvField(r->name, FALSE);
            CsvField(GetState(r->state), FALSE);

            swprintf_s(num, 16, L"%lu", r->pid);
            CsvField(num, FALSE);

            CsvField(GetServiceType(r->serviceType), FALSE);
            CsvField(r->hasConfig ? GetStartType(r->startType) : L"UNKNOWN", FALSE);
            CsvField(r->account, FALSE);
            CsvField(r->queryStatus, TRUE);
        }

        return;
    }

    if (g_vulnScan && !g_forense)
    {
        static const wchar_t* vulnCols[] =
        {
            L"host", L"service_name", L"binary_path", L"image_path",
            L"service_dll", L"flags", L"vuln_details"
        };

        size_t vn = sizeof(vulnCols) / sizeof(vulnCols[0]);

        for (size_t i = 0; i < vn; i++)
            CsvField(vulnCols[i], i == vn - 1);

        for (DWORD i = 0; i < recordCount; i++)
        {
            const SERVICE_RECORD* r = &records[i];
            DWORD masked = r->flags & VULN_FLAGS_MASK;

            if (masked == 0)
                continue;

            wchar_t flags[256];
            FlagsToString(masked, flags, 256, L";");

            CsvField(g_hostLabel, FALSE);
            CsvField(r->name, FALSE);
            CsvField(r->binaryPath, FALSE);
            CsvField(r->imagePath, FALSE);
            CsvField(r->serviceDll, FALSE);
            CsvField(flags, FALSE);
            CsvField(r->vulnDetails, TRUE);
        }

        OutputVulnExtraCsvSections();
        return;
    }

    static const wchar_t* cols[] =
    {
        L"host", L"name", L"state", L"pid", L"type", L"start_type", L"account",
        L"query_status", L"binary_path", L"dependencies", L"load_group",
        L"description",
        L"image_path", L"image_exists", L"image_sha256",
        L"image_signature", L"image_signer",
        L"service_dll", L"dll_exists", L"dll_sha256",
        L"dll_signature", L"dll_signer",
        L"flags", L"vuln_details"
    };

    size_t n = sizeof(cols) / sizeof(cols[0]);

    for (size_t i = 0; i < n; i++)
        CsvField(cols[i], i == n - 1);

    for (DWORD i = 0; i < recordCount; i++)
    {
        const SERVICE_RECORD* r = &records[i];
        wchar_t num[16];
        wchar_t flags[256];

        CsvField(g_hostLabel, FALSE);
        CsvField(r->name, FALSE);
        CsvField(GetState(r->state), FALSE);

        swprintf_s(num, 16, L"%lu", r->pid);
        CsvField(num, FALSE);

        CsvField(GetServiceType(r->serviceType), FALSE);
        CsvField(r->hasConfig ? GetStartType(r->startType) : L"UNKNOWN", FALSE);
        CsvField(r->account, FALSE);
        CsvField(r->queryStatus, FALSE);
        CsvField(r->binaryPath, FALSE);
        CsvField(r->dependencies, FALSE);
        CsvField(r->loadGroup, FALSE);
        CsvField(r->description, FALSE);

        CsvFileColumns(r->imageInfo, r->imagePath, FALSE);
        CsvFileColumns(r->dllInfo, r->serviceDll, FALSE);

        FlagsToString(r->flags, flags, 256, L";");
        CsvField(flags, FALSE);
        CsvField(r->vulnDetails, TRUE);
    }

    if (g_vulnScan)
        OutputVulnExtraCsvSections();
}

// ==================================================
// SAIDA: JSON
// ==================================================

static void OutputVulnExtraJsonSections(void)
{
    fputws(L",\n  \"registry_hardening\": [", g_out);
    for (DWORD i = 0; i < regHardeningCount; i++)
    {
        const REG_HARDENING_ENTRY* e = &regHardeningEntries[i];
        fwprintf(g_out, L"%ls\n    {", i ? L"," : L"");

        JsonKeyStr(L"category", e->category, TRUE);
        JsonKeyStr(L"hive", e->hive, FALSE);
        JsonKeyStr(L"key", e->keyPath, FALSE);
        JsonKeyStr(L"value_name", e->valueName, FALSE);
        JsonKeyStr(L"value", e->rawValue, FALSE);
        JsonKeyStr(L"status", e->status, FALSE);
        fwprintf(g_out, L",\n      \"vulnerable\": %ls", e->isVulnerable ? L"true" : L"false");
        JsonKeyStr(L"details", e->details, FALSE);

        fputws(L"\n    }", g_out);
    }

    fputws(L"\n  ],\n  \"autorun_findings\": [", g_out);
    BOOL firstAr = TRUE;
    for (DWORD i = 0; i < autorunCount; i++)
    {
        const AUTORUN_ENTRY* e = &autorunEntries[i];
        if (e->flags == 0)
            continue;

        fwprintf(g_out, L"%ls\n    {", firstAr ? L"" : L",");
        firstAr = FALSE;

        JsonKeyStr(L"hive", e->hive, TRUE);
        JsonKeyStr(L"key", e->keyPath, FALSE);
        JsonKeyStr(L"value_name", e->valueName, FALSE);
        JsonKeyStr(L"command", e->command, FALSE);
        JsonKeyStr(L"resolved_path", e->resolvedPath, FALSE);
        JsonKeyStr(L"details", e->details, FALSE);

        fputws(L",\n      \"flags\": [", g_out);
        BOOL firstFlag = TRUE;
        for (size_t f = 0; f < AUTORUN_FLAG_COUNT; f++)
        {
            if (!(e->flags & AUTORUN_FLAG_NAMES[f].bit))
                continue;
            if (!firstFlag) fputws(L", ", g_out);
            JsonString(AUTORUN_FLAG_NAMES[f].name);
            firstFlag = FALSE;
        }
        fputws(L"]\n    }", g_out);
    }

    fputws(L"\n  ],\n  \"system_path_findings\": [", g_out);
    for (DWORD i = 0; i < pathCount; i++)
    {
        const PATH_ENTRY* pe = &pathEntries[i];
        fwprintf(g_out, L"%ls\n    {", i ? L"," : L"");

        JsonKeyNum(L"order", pe->index, TRUE);
        JsonKeyStr(L"raw_entry", pe->rawEntry, FALSE);
        JsonKeyStr(L"resolved_dir", pe->resolvedDir, FALSE);
        JsonKeyStr(L"details", pe->details, FALSE);

        fputws(L",\n      \"flags\": [", g_out);
        BOOL firstFlag = TRUE;
        if (pe->flags & FP_DIR_WRITABLE)
        {
            JsonString(L"PATH_DIR_WRITABLE");
            firstFlag = FALSE;
        }
        if (pe->flags & FP_DIR_MISSING)
        {
            if (!firstFlag) fputws(L", ", g_out);
            JsonString(L"PATH_DIR_MISSING");
            firstFlag = FALSE;
        }
        if (firstFlag)
            JsonString(L"PERMISSIVE_ENV_KEY");
        fputws(L"]\n    }", g_out);
    }

    fputws(L"\n  ],\n  \"scheduled_task_findings\": [", g_out);
    BOOL firstTk = TRUE;
    for (DWORD i = 0; i < taskCount; i++)
    {
        const TASK_ENTRY* te = &taskEntries[i];
        if (te->flags == 0)
            continue;

        fwprintf(g_out, L"%ls\n    {", firstTk ? L"" : L",");
        firstTk = FALSE;

        JsonKeyStr(L"task_name", te->taskName, TRUE);
        JsonKeyStr(L"principal", te->principal, FALSE);
        JsonKeyStr(L"command", te->command, FALSE);
        JsonKeyStr(L"resolved_path", te->resolvedPath, FALSE);
        JsonKeyStr(L"details", te->details, FALSE);

        fputws(L",\n      \"flags\": [", g_out);
        BOOL firstFlag = TRUE;
        for (size_t f = 0; f < TASK_FLAG_COUNT; f++)
        {
            if (!(te->flags & TASK_FLAG_NAMES[f].bit))
                continue;
            if (!firstFlag) fputws(L", ", g_out);
            JsonString(TASK_FLAG_NAMES[f].name);
            firstFlag = FALSE;
        }
        fputws(L"]\n    }", g_out);
    }
    fputws(L"\n  ]", g_out);
}

static void OutputJson(
    const wchar_t* host, const SYSTEMTIME* utc, BOOL complete)
{
    fputws(L"{\n", g_out);

    fwprintf(g_out,
        L"  \"collected_utc\": \"%04d-%02d-%02dT%02d:%02d:%02dZ\",\n",
        utc->wYear, utc->wMonth, utc->wDay,
        utc->wHour, utc->wMinute, utc->wSecond);

    fputws(L"  \"host\": ", g_out);
    JsonString(host);
    fputws(L",\n", g_out);

    fwprintf(g_out, L"  \"remote\": %ls,\n", g_remote ? L"true" : L"false");
    fputws(L"  \"target\": ", g_out);
    JsonString(g_target);
    fputws(L",\n", g_out);

    if (!g_forense && !g_vulnScan)
    {
        fputws(L"  \"service_inventory\": [", g_out);

        for (DWORD i = 0; i < recordCount; i++)
        {
            const SERVICE_RECORD* r = &records[i];
            fwprintf(g_out, L"%ls\n    {", i ? L"," : L"");

            JsonKeyStr(L"name", r->name, TRUE);
            JsonKeyStr(L"state", GetState(r->state), FALSE);
            JsonKeyNum(L"pid", r->pid, FALSE);
            JsonKeyStr(L"type", GetServiceType(r->serviceType), FALSE);
            JsonKeyStr(L"start_type",
                r->hasConfig ? GetStartType(r->startType) : L"UNKNOWN", FALSE);
            JsonKeyStr(L"account", r->account, FALSE);
            JsonKeyStr(L"query_status", r->queryStatus, FALSE);

            fputws(L"\n    }", g_out);
        }

        fwprintf(g_out,
            L"\n  ],\n"
            L"  \"total_services\": %lu,\n"
            L"  \"enumeration_complete\": %ls\n"
            L"}\n",
            recordCount, complete ? L"true" : L"false");
        return;
    }

    if (g_vulnScan && !g_forense)
    {
        fputws(L"  \"service_vulnerabilities\": [", g_out);

        BOOL firstSvc = TRUE;
        for (DWORD i = 0; i < recordCount; i++)
        {
            const SERVICE_RECORD* r = &records[i];
            DWORD masked = r->flags & VULN_FLAGS_MASK;
            if (masked == 0)
                continue;

            fwprintf(g_out, L"%ls\n    {", firstSvc ? L"" : L",");
            firstSvc = FALSE;

            JsonKeyStr(L"name", r->name, TRUE);
            JsonKeyStr(L"binary_path", r->binaryPath, FALSE);
            JsonKeyStr(L"image_path", r->imagePath, FALSE);
            JsonKeyStr(L"service_dll", r->serviceDll, FALSE);
            JsonKeyStr(L"vuln_details", r->vulnDetails, FALSE);

            fputws(L",\n      \"flags\": [", g_out);

            BOOL firstFlag = TRUE;
            for (size_t f = 0; f < FLAG_COUNT; f++)
            {
                if (!(masked & FLAG_NAMES[f].bit))
                    continue;

                if (!firstFlag)
                    fputws(L", ", g_out);

                JsonString(FLAG_NAMES[f].name);
                firstFlag = FALSE;
            }

            fputws(L"]\n    }", g_out);
        }

        fputws(L"\n  ]", g_out);
        OutputVulnExtraJsonSections();

        fwprintf(g_out,
            L",\n"
            L"  \"summary\": {\n"
            L"    \"registry_hardening_issues\": %lu,\n"
            L"    \"services_with_vulnerabilities\": %lu,\n"
            L"    \"autorun_findings\": %lu,\n"
            L"    \"system_path_findings\": %lu,\n"
            L"    \"scheduled_task_findings\": %lu,\n"
            L"    \"access_denied\": %lu,\n"
            L"    \"enumeration_complete\": %ls\n"
            L"  }\n"
            L"}\n",
            CountRegHardeningFindings(),
            CountFindings(VULN_FLAGS_MASK),
            CountAutorunFindings(),
            CountPathFindings(),
            CountTaskFindings(),
            CountDenied(),
            complete ? L"true" : L"false");
        return;
    }

    fwprintf(g_out, L"  \"hashing\": %ls,\n  \"signature_check\": %ls,\n",
        g_doHash ? L"true" : L"false", g_doSig ? L"true" : L"false");

    fputws(L"  \"services\": [", g_out);

    for (DWORD i = 0; i < recordCount; i++)
    {
        const SERVICE_RECORD* r = &records[i];

        fwprintf(g_out, L"%ls\n    {", i ? L"," : L"");

        JsonKeyStr(L"name", r->name, TRUE);
        JsonKeyStr(L"state", GetState(r->state), FALSE);
        JsonKeyNum(L"pid", r->pid, FALSE);
        JsonKeyStr(L"type", GetServiceType(r->serviceType), FALSE);
        JsonKeyStr(L"start_type",
            r->hasConfig ? GetStartType(r->startType) : L"UNKNOWN", FALSE);
        JsonKeyStr(L"account", r->account, FALSE);
        JsonKeyStr(L"query_status", r->queryStatus, FALSE);
        JsonKeyStr(L"binary_path", r->binaryPath, FALSE);
        JsonKeyStr(L"dependencies", r->dependencies, FALSE);
        JsonKeyStr(L"load_group", r->loadGroup, FALSE);
        JsonKeyStr(L"description", r->description, FALSE);
        JsonKeyStr(L"vuln_details", r->vulnDetails, FALSE);

        fputws(L",\n      \"image\": ", g_out);
        JsonFileInfo(r->imageInfo);

        fputws(L",\n      \"service_dll\": ", g_out);
        JsonFileInfo(r->dllInfo);

        fputws(L",\n      \"flags\": [", g_out);

        BOOL firstFlag = TRUE;

        for (size_t f = 0; f < FLAG_COUNT; f++)
        {
            if (!(r->flags & FLAG_NAMES[f].bit))
                continue;

            if (!firstFlag)
                fputws(L", ", g_out);

            JsonString(FLAG_NAMES[f].name);
            firstFlag = FALSE;
        }

        fputws(L"]\n    }", g_out);
    }

    fputws(L"\n  ],\n  \"processes\": [", g_out);

    for (DWORD i = 0; i < processCount; i++)
    {
        fwprintf(g_out, L"%ls\n    { \"pid\": %lu, \"image\": ",
            i ? L"," : L"", processes[i].pid);
        JsonString(processes[i].image);
        fwprintf(g_out, L", \"service_count\": %lu }",
            processes[i].serviceCount);
    }

    fputws(L"\n  ]", g_out);

    if (g_vulnScan)
        OutputVulnExtraJsonSections();

    fwprintf(g_out,
        L",\n"
        L"  \"vuln_scan\": %ls,\n"
        L"  \"summary\": {\n"
        L"    \"services\": %lu,\n"
        L"    \"processes\": %lu,\n"
        L"    \"files_analyzed\": %lu,\n"
        L"    \"forensic_findings\": %lu,\n"
        L"    \"registry_hardening_issues\": %lu,\n"
        L"    \"vuln_findings\": %lu,\n"
        L"    \"autorun_findings\": %lu,\n"
        L"    \"system_path_findings\": %lu,\n"
        L"    \"scheduled_task_findings\": %lu,\n"
        L"    \"access_denied\": %lu,\n"
        L"    \"enumeration_complete\": %ls\n"
        L"  }\n"
        L"}\n",
        g_vulnScan ? L"true" : L"false",
        recordCount, processCount, fileCacheCount,
        CountFindings(FORENSE_FLAGS_MASK),
        CountRegHardeningFindings(),
        CountFindings(VULN_FLAGS_MASK),
        CountAutorunFindings(),
        CountPathFindings(),
        CountTaskFindings(),
        CountDenied(),
        complete ? L"true" : L"false");
}

// ==================================================
// ARGUMENTOS
// ==================================================

static BOOL PromptPassword(const wchar_t* user, wchar_t* buf, DWORD cap)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    DWORD read = 0;

    if (hIn == INVALID_HANDLE_VALUE || !GetConsoleMode(hIn, &mode))
        return FALSE;

    fwprintf(stderr, L"Password for %ls: ", user);

    SetConsoleMode(hIn, mode & ~ENABLE_ECHO_INPUT);
    BOOL ok = ReadConsoleW(hIn, buf, cap - 1, &read, NULL);
    SetConsoleMode(hIn, mode);

    fputws(L"\n", stderr);

    if (!ok)
        return FALSE;

    buf[read] = L'\0';

    while (read > 0 && (buf[read - 1] == L'\r' || buf[read - 1] == L'\n'))
        buf[--read] = L'\0';

    return TRUE;
}

static BOOL AuthenticateRemote(const wchar_t* user, const wchar_t* password)
{
    wchar_t pwBuf[256];
    wchar_t domainBuf[256];
    BOOL prompted = FALSE;

    const wchar_t* pw = password;
    const wchar_t* name = user;
    const wchar_t* domain = NULL;

    if (pw == NULL)
    {
        if (!PromptPassword(user, pwBuf, 256))
        {
            fwprintf(stderr,
                L"Could not read the password from the console. "
                L"Use --password.\n");
            return FALSE;
        }

        pw = pwBuf;
        prompted = TRUE;
    }

    const wchar_t* bs = wcschr(user, L'\\');

    if (bs != NULL)
    {
        size_t dl = (size_t)(bs - user);

        if (dl >= 256)
        {
            fwprintf(stderr, L"Domain name too long.\n");
            return FALSE;
        }

        wcsncpy_s(domainBuf, 256, user, dl);
        domain = domainBuf;
        name = bs + 1;
    }
    else if (wcschr(user, L'@') == NULL)
    {
        domain = g_target;
    }

    BOOL ok = LogonUserW(
        name,
        domain,
        pw,
        LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_WINNT50,
        &g_logonToken
    );

    DWORD err = GetLastError();

    if (prompted)
        SecureZeroMemory(pwBuf, sizeof(pwBuf));

    if (!ok)
    {
        fwprintf(stderr, L"LogonUserW error: %lu\n", err);
        return FALSE;
    }

    if (!ImpersonateLoggedOnUser(g_logonToken))
    {
        fwprintf(stderr, L"ImpersonateLoggedOnUser error: %lu\n",
            GetLastError());
        return FALSE;
    }

    return TRUE;
}

static void PrintScmError(DWORD err)
{
    fwprintf(stderr, L"OpenSCManagerW error: %lu\n", err);

    switch (err)
    {
    case ERROR_ACCESS_DENIED:
        fputws(L"Access denied. Use an administrator account on the "
               L"target. Local (non built-in) accounts may be blocked by "
               L"remote UAC filtering (LocalAccountTokenFilterPolicy).\n",
               stderr);
        break;

    case ERROR_LOGON_FAILURE:
        fputws(L"Logon failure: wrong user name or password.\n", stderr);
        break;

    case RPC_S_SERVER_UNAVAILABLE:
        fputws(L"RPC server unavailable: host offline, wrong address, or a "
               L"firewall blocking TCP 135/445 and dynamic RPC ports.\n",
               stderr);
        break;

    case ERROR_SESSION_CREDENTIAL_CONFLICT:
        fputws(L"Credential conflict: there is already a connection to "
               L"this host with other credentials (try: net use * "
               L"/delete).\n", stderr);
        break;

    case ERROR_BAD_NETPATH:
    case ERROR_NETWORK_UNREACHABLE:
        fputws(L"Network path not found or unreachable.\n", stderr);
        break;

    default:
        break;
    }
}

static void PrintUsage(void)
{
    fputws(
        L"Usage: service_collector_forensic.exe [options]\n"
        L"  -f, --format <table|csv|json>  Output format (default: table)\n"
        L"  -o, --out <file>               Write output to file (UTF-8)\n"
        L"  -t, --target <host|ip>         Collect from a remote host\n"
        L"  -u, --user <[DOMAIN\\]user>     Credentials for the remote host\n"
        L"  -p, --password <password>      Password (prompted if omitted)\n"
        L"      --no-hash                  Skip SHA-256 hashing\n"
        L"      --no-sig                   Skip signature verification\n"
        L"      --forense                  SERVICE INVENTORY, PROCESS CORRELATION,\n"
        L"                                 FINDINGS, BINARY ANALYSIS, SERVICE\n"
        L"                                 CONFIGURATION\n"
        L"      --vuln-scan                REGISTRY HARDENING (SafeDllSearchMode,\n"
        L"                                 CWDIllegalInDllSearch, AlwaysInstallElevated),\n"
        L"                                 AUTORUN, SYSTEM PATH DLL hijack,\n"
        L"                                 SCHEDULED TASKS permissions, and\n"
        L"                                 service vulnerability findings\n"
        L"  -h, --help                     Show this help\n"
        L"\n"
        L"No mode given: returns ONLY SERVICE INVENTORY.\n",
        stderr);
}

// ==================================================
// MAIN
// ==================================================

int wmain(int argc, wchar_t** argv)
{
    OUTPUT_FORMAT format = FMT_TABLE;
    const wchar_t* outPath = NULL;
    const wchar_t* userArg = NULL;
    wchar_t* passArg = NULL;

    SC_HANDLE hManager = NULL;
    ENUM_SERVICE_STATUS_PROCESSW* services = NULL;

    DWORD bufferSize = INITIAL_BUFFER_SIZE;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    SYSTEMTIME stLocal, stUtc;
    BOOL enumerationComplete = FALSE;

    _setmode(_fileno(stderr), _O_U8TEXT);

    for (int i = 1; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"-h") == 0 ||
            _wcsicmp(argv[i], L"--help") == 0)
        {
            PrintUsage();
            return 0;
        }
        else if ((_wcsicmp(argv[i], L"-t") == 0 ||
                  _wcsicmp(argv[i], L"--target") == 0) && i + 1 < argc)
        {
            g_target = argv[++i];
        }
        else if ((_wcsicmp(argv[i], L"-u") == 0 ||
                  _wcsicmp(argv[i], L"--user") == 0) && i + 1 < argc)
        {
            userArg = argv[++i];
        }
        else if ((_wcsicmp(argv[i], L"-p") == 0 ||
                  _wcsicmp(argv[i], L"--password") == 0) && i + 1 < argc)
        {
            passArg = argv[++i];
        }
        else if (_wcsicmp(argv[i], L"--no-hash") == 0)
        {
            g_doHash = FALSE;
        }
        else if (_wcsicmp(argv[i], L"--no-sig") == 0)
        {
            g_doSig = FALSE;
        }
        else if (_wcsicmp(argv[i], L"--vuln-scan") == 0)
        {
            g_vulnScan = TRUE;
        }
        else if (_wcsicmp(argv[i], L"--forense") == 0)
        {
            g_forense = TRUE;
        }
        else if ((_wcsicmp(argv[i], L"-f") == 0 ||
                  _wcsicmp(argv[i], L"--format") == 0) && i + 1 < argc)
        {
            const wchar_t* v = argv[++i];

            if (_wcsicmp(v, L"table") == 0)      format = FMT_TABLE;
            else if (_wcsicmp(v, L"csv") == 0)   format = FMT_CSV;
            else if (_wcsicmp(v, L"json") == 0)  format = FMT_JSON;
            else
            {
                fwprintf(stderr, L"Unknown format: %ls\n", v);
                PrintUsage();
                return 2;
            }
        }
        else if ((_wcsicmp(argv[i], L"-o") == 0 ||
                  _wcsicmp(argv[i], L"--out") == 0) && i + 1 < argc)
        {
            outPath = argv[++i];
        }
        else
        {
            fwprintf(stderr, L"Invalid argument: %ls\n", argv[i]);
            PrintUsage();
            return 2;
        }
    }

    if (!g_forense)
    {
        g_doHash = FALSE;
        g_doSig = FALSE;
    }

    if (outPath != NULL)
    {
        if (_wfopen_s(&g_out, outPath, L"w, ccs=UTF-8") != 0 ||
            g_out == NULL)
        {
            fwprintf(stderr, L"Cannot open output file: %ls\n", outPath);
            return 1;
        }
    }
    else
    {
        _setmode(_fileno(stdout), _O_U8TEXT);
        g_out = stdout;
    }

#ifndef _WIN64
    {
        BOOL wow = FALSE;

        if (IsWow64Process(GetCurrentProcess(), &wow) && wow)
        {
            PVOID old = NULL;
            Wow64DisableWow64FsRedirection(&old);
        }
    }
#endif

    GetLocalTime(&stLocal);
    GetSystemTime(&stUtc);

    if ((userArg != NULL || passArg != NULL) && g_target == NULL)
    {
        fwprintf(stderr, L"--user/--password require --target.\n");
        return 2;
    }

    if (passArg != NULL && userArg == NULL)
    {
        fwprintf(stderr, L"--password requires --user.\n");
        return 2;
    }

    if (g_target != NULL)
    {
        g_remote = TRUE;
        _snwprintf_s(g_machineName, 300, _TRUNCATE, L"\\\\%ls", g_target);

        if (userArg != NULL)
        {
            BOOL authOk = AuthenticateRemote(userArg, passArg);

            if (passArg != NULL)
                SecureZeroMemory(passArg, wcslen(passArg) * sizeof(wchar_t));

            if (!authOk)
                return 1;
        }

        LONG rr = RegConnectRegistryW(g_machineName, HKEY_LOCAL_MACHINE, &g_hklm);

        if (rr != ERROR_SUCCESS)
        {
            g_hklm = NULL;
            fwprintf(stderr,
                L"[!] Remote registry unavailable (error %ld): ServiceDll, "
                L"registry hardening and system PATH will not be collected.\n", rr);
        }

        LoadRemoteEnvironment();

        wchar_t probe[1200];
        BuildAccessPath(g_sysRoot, probe, 1200);

        if (GetFileAttributesW(probe) == INVALID_FILE_ATTRIBUTES)
        {
            g_filesUnreachable = TRUE;
            fwprintf(stderr,
                L"[!] Cannot access the administrative share (%ls).\n",
                probe);
        }
    }

    wchar_t host[300] = L"UNKNOWN";

    if (!g_remote)
    {
        DWORD hostLen = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameW(host, &hostLen);
    }
    else if (g_hklm == NULL || !ReadRegString(g_hklm,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName", host, 300))
    {
        wcsncpy_s(host, 300, g_target, _TRUNCATE);
    }

    wcsncpy_s(g_hostLabel, 300, host, _TRUNCATE);

    hManager = OpenSCManagerW(
        g_remote ? g_machineName : NULL,
        NULL,
        SC_MANAGER_ENUMERATE_SERVICE
    );

    if (hManager == NULL)
    {
        PrintScmError(GetLastError());
        return 1;
    }

    services = (ENUM_SERVICE_STATUS_PROCESSW*)malloc(bufferSize);

    if (services == NULL)
    {
        fwprintf(stderr, L"Memory allocation failed.\n");
        CloseServiceHandle(hManager);
        return 1;
    }

    if (g_vulnScan)
    {
        InitLowPrivSids();

        fputws(L"[*] Vulnerability scan enabled: checking registry hardening, "
               L"autorun, system PATH DLL hijack, scheduled tasks, unquoted "
               L"service paths, writable binpath/binperm and permissive ACLs.\n",
               stderr);

        if (g_remote)
            fputws(L"[*] Remote mode: HKCU entries are not scanned.\n",
                   stderr);
    }

    fwprintf(stderr, L"[*] Enumerating and analyzing services...\n");

    for (;;)
    {
        bytesNeeded = 0;
        servicesReturned = 0;

        BOOL result = EnumServicesStatusExW(
            hManager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_TYPE_ALL,
            SERVICE_STATE_ALL,
            (LPBYTE)services,
            bufferSize,
            &bytesNeeded,
            &servicesReturned,
            &resumeHandle,
            NULL
        );

        DWORD error = result ? ERROR_SUCCESS : GetLastError();

        for (DWORD i = 0; i < servicesReturned; i++)
            CollectService(hManager, &services[i]);

        if (result)
        {
            enumerationComplete = TRUE;
            break;
        }

        if (error != ERROR_MORE_DATA)
        {
            fwprintf(stderr, L"Enumeration error: %lu\n", error);
            break;
        }

        DWORD newSize = bytesNeeded;

        if (newSize <= bufferSize)
            newSize = bufferSize * 2;

        ENUM_SERVICE_STATUS_PROCESSW* temp =
            (ENUM_SERVICE_STATUS_PROCESSW*)realloc(services, newSize);

        if (temp == NULL)
        {
            fwprintf(stderr, L"Buffer allocation failed.\n");
            break;
        }

        services = temp;
        bufferSize = newSize;
    }

    if (g_vulnScan)
    {
        fwprintf(stderr, L"[*] Checking registry hardening (DLL search & MSI elevation)...\n");
        ScanRegistryHardening();

        fwprintf(stderr, L"[*] Scanning autorun registry keys...\n");
        ScanAutorun();

        fwprintf(stderr, L"[*] Scanning system PATH directories for DLL hijack...\n");
        ScanSystemPath();

        fwprintf(stderr, L"[*] Scanning scheduled tasks permissions...\n");
        ScanScheduledTasks();
    }

    fwprintf(stderr, L"[*] Done. Writing output...\n");

    switch (format)
    {
    case FMT_CSV:
        OutputCsv();
        break;

    case FMT_JSON:
        OutputJson(host, &stUtc, enumerationComplete);
        break;

    default:
        OutputTable(host, &stLocal, enumerationComplete);
        break;
    }

    if (!enumerationComplete)
        fwprintf(stderr, L"[!] Enumeration incomplete: output may be partial.\n");

    if (CountDenied() > 0)
        fwprintf(stderr, L"[!] Some services were access denied. Run as Administrator.\n");

    if (outPath != NULL && g_out != NULL)
        fclose(g_out);

    free(services);
    free(processes);
    FreeRecords();
    FreeFileCache();
    FreeRegHardening();
    FreeAutorun();
    FreeSystemPath();
    FreeTasks();

    if (g_vulnScan)
        FreeLowPrivSids();

    CloseServiceHandle(hManager);

    if (g_remote && g_hklm != NULL)
        RegCloseKey(g_hklm);

    if (g_logonToken != NULL)
    {
        RevertToSelf();
        CloseHandle(g_logonToken);
    }

    return enumerationComplete ? 0 : 1;
}
