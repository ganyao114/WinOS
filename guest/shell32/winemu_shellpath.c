/*
 * Minimal shell32 folder-path exports for WinEmu.
 *
 * These are intentionally narrow: only the subset needed by CPU-Z / wininet
 * cache initialization is implemented for now.
 */

#include <windows.h>
#include <knownfolders.h>
#include <objbase.h>
#include <shlobj.h>

#ifndef CSIDL_FOLDER_MASK
#define CSIDL_FOLDER_MASK 0x00ff
#endif

static const WCHAR PROFILE_PATH[] = L"C:\\users\\Default";
static const WCHAR DESKTOP_PATH[] = L"C:\\users\\Default\\Desktop";
static const WCHAR DOCUMENTS_PATH[] = L"C:\\users\\Default\\Documents";
static const WCHAR APPDATA_PATH[] = L"C:\\users\\Default\\AppData\\Roaming";
static const WCHAR LOCAL_APPDATA_PATH[] = L"C:\\users\\Default\\AppData\\Local";
static const WCHAR INTERNET_CACHE_PATH[] =
    L"C:\\users\\Default\\AppData\\Local\\Microsoft\\Windows\\INetCache";
static const WCHAR COOKIES_PATH[] =
    L"C:\\users\\Default\\AppData\\Local\\Microsoft\\Windows\\INetCookies";
static const WCHAR HISTORY_PATH[] =
    L"C:\\users\\Default\\AppData\\Local\\Microsoft\\Windows\\History";

static void winemu_debug_ascii(const char *msg)
{
    HANDLE out;
    DWORD written;
    DWORD len = 0;

    while (msg[len]) len++;
    out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE)
        return;
    WriteFile(out, msg, len, &written, NULL);
}

static void winemu_debug_hex32(DWORD value)
{
    char buf[11] = "0x00000000";
    static const char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 8; i++)
    {
        buf[2 + i] = hex[(value >> ((7 - i) * 4)) & 0xf];
    }
    winemu_debug_ascii(buf);
}

static void winemu_debug_wide(const WCHAR *path)
{
    char buf[MAX_PATH];
    DWORD i = 0;

    while (path && path[i] && i + 1 < MAX_PATH)
    {
        buf[i] = (path[i] < 0x80) ? (char)path[i] : '?';
        i++;
    }
    buf[i] = 0;
    winemu_debug_ascii(buf);
}

static int winemu_wstrlen(const WCHAR *s)
{
    int len = 0;
    while (s && s[len]) len++;
    return len;
}

static BOOL winemu_copy_wstr(WCHAR *dst, DWORD dst_len, const WCHAR *src)
{
    DWORD i = 0;

    if (!dst || !src || !dst_len) return FALSE;
    while (src[i])
    {
        if (i + 1 >= dst_len) return FALSE;
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
    return TRUE;
}

static BOOL winemu_create_dir_if_missing(const WCHAR *path)
{
    DWORD err;

    if (CreateDirectoryW(path, NULL))
        return TRUE;

    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS)
        return TRUE;

    winemu_debug_ascii("winemu_shell32: CreateDirectoryW failed gle=");
    winemu_debug_hex32(err);
    winemu_debug_ascii(" path=");
    winemu_debug_wide(path);
    winemu_debug_ascii("\r\n");
    return FALSE;
}

static BOOL winemu_create_dir_tree(const WCHAR *path)
{
    WCHAR buf[MAX_PATH];
    int i;
    int len;

    if (!path) return FALSE;
    len = winemu_wstrlen(path);
    if (!len || len >= MAX_PATH) return FALSE;
    if (!winemu_copy_wstr(buf, MAX_PATH, path)) return FALSE;

    for (i = 3; i < len; i++)
    {
        if (buf[i] != L'\\' && buf[i] != L'/')
            continue;

        buf[i] = 0;
        if (!winemu_create_dir_if_missing(buf))
            return FALSE;
        buf[i] = L'\\';
    }

    return winemu_create_dir_if_missing(buf);
}

static HRESULT winemu_utf16_to_ansi(const WCHAR *src, char *dst, DWORD dst_len)
{
    int ret;

    if (!src || !dst || !dst_len) return E_INVALIDARG;
    ret = WideCharToMultiByte(CP_ACP, 0, src, -1, dst, (int)dst_len, NULL, NULL);
    if (!ret)
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

static BOOL winemu_is_equal_guid(REFGUID a, REFGUID b)
{
    const BYTE *aa = (const BYTE *)a;
    const BYTE *bb = (const BYTE *)b;
    int i;

    for (i = 0; i < (int)sizeof(GUID); i++)
    {
        if (aa[i] != bb[i])
            return FALSE;
    }
    return TRUE;
}

static const WCHAR *winemu_path_for_csidl(int folder)
{
    switch (folder & CSIDL_FOLDER_MASK)
    {
    case CSIDL_PROFILE:
        return PROFILE_PATH;
    case CSIDL_DESKTOPDIRECTORY:
        return DESKTOP_PATH;
    case CSIDL_PERSONAL:
        return DOCUMENTS_PATH;
    case CSIDL_APPDATA:
        return APPDATA_PATH;
    case CSIDL_LOCAL_APPDATA:
        return LOCAL_APPDATA_PATH;
    case CSIDL_INTERNET_CACHE:
        return INTERNET_CACHE_PATH;
    case CSIDL_COOKIES:
        return COOKIES_PATH;
    case CSIDL_HISTORY:
        return HISTORY_PATH;
    default:
        return NULL;
    }
}

static HRESULT winemu_get_folder_path_w(int folder, LPWSTR path)
{
    const WCHAR *resolved = winemu_path_for_csidl(folder);

    if (!path) return E_INVALIDARG;
    if (!resolved)
    {
        winemu_debug_ascii("winemu_shell32: unknown csidl\r\n");
        SetLastError(ERROR_PATH_NOT_FOUND);
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }
    if ((folder & CSIDL_FLAG_CREATE) && !winemu_create_dir_tree(resolved))
    {
        winemu_debug_ascii("winemu_shell32: create_dir_tree failed\r\n");
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (!winemu_copy_wstr(path, MAX_PATH, resolved))
        return E_FAIL;
    winemu_debug_ascii("winemu_shell32: folder path ok\r\n");
    return S_OK;
}

static HRESULT winemu_known_folder_to_csidl(REFKNOWNFOLDERID rfid, int *folder)
{
    if (!rfid || !folder) return E_INVALIDARG;

    if (winemu_is_equal_guid(rfid, &FOLDERID_Profile))
        *folder = CSIDL_PROFILE;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_Desktop))
        *folder = CSIDL_DESKTOPDIRECTORY;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_Documents))
        *folder = CSIDL_PERSONAL;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_RoamingAppData))
        *folder = CSIDL_APPDATA;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_LocalAppData))
        *folder = CSIDL_LOCAL_APPDATA;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_InternetCache))
        *folder = CSIDL_INTERNET_CACHE;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_Cookies))
        *folder = CSIDL_COOKIES;
    else if (winemu_is_equal_guid(rfid, &FOLDERID_History))
        *folder = CSIDL_HISTORY;
    else
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);

    return S_OK;
}

HRESULT WINAPI SHGetFolderPathW(
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath)
{
    UNREFERENCED_PARAMETER(hwndOwner);
    UNREFERENCED_PARAMETER(hToken);
    UNREFERENCED_PARAMETER(dwFlags);
    return winemu_get_folder_path_w(nFolder, pszPath);
}

HRESULT WINAPI SHGetFolderPathA(
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPSTR pszPath)
{
    WCHAR wide[MAX_PATH];
    HRESULT hr;

    UNREFERENCED_PARAMETER(hwndOwner);
    UNREFERENCED_PARAMETER(hToken);
    UNREFERENCED_PARAMETER(dwFlags);

    hr = winemu_get_folder_path_w(nFolder, wide);
    if (FAILED(hr))
        return hr;
    return winemu_utf16_to_ansi(wide, pszPath, MAX_PATH);
}

BOOL WINAPI SHGetSpecialFolderPathW(
    HWND hwndOwner,
    LPWSTR szPath,
    int nFolder,
    BOOL bCreate)
{
    UNREFERENCED_PARAMETER(hwndOwner);
    return SUCCEEDED(winemu_get_folder_path_w(
        bCreate ? (nFolder | CSIDL_FLAG_CREATE) : nFolder, szPath));
}

BOOL WINAPI SHGetSpecialFolderPathA(
    HWND hwndOwner,
    LPSTR szPath,
    int nFolder,
    BOOL bCreate)
{
    CHAR ansi[MAX_PATH];
    HRESULT hr;

    UNREFERENCED_PARAMETER(hwndOwner);
    hr = SHGetFolderPathA(
        NULL,
        bCreate ? (nFolder | CSIDL_FLAG_CREATE) : nFolder,
        NULL,
        0,
        ansi);
    if (FAILED(hr))
        return FALSE;
    lstrcpynA(szPath, ansi, MAX_PATH);
    return TRUE;
}

HRESULT WINAPI SHGetKnownFolderPath(
    REFKNOWNFOLDERID rfid,
    DWORD flags,
    HANDLE token,
    WCHAR **ret_path)
{
    WCHAR path[MAX_PATH];
    WCHAR *copy;
    int folder;
    int i;
    HRESULT hr;

    UNREFERENCED_PARAMETER(token);

    if (!ret_path) return E_INVALIDARG;
    *ret_path = NULL;

    hr = winemu_known_folder_to_csidl(rfid, &folder);
    if (FAILED(hr))
        return hr;
    if (flags & KF_FLAG_CREATE)
        folder |= CSIDL_FLAG_CREATE;

    hr = winemu_get_folder_path_w(folder, path);
    if (FAILED(hr))
        return hr;

    copy = CoTaskMemAlloc((winemu_wstrlen(path) + 1) * sizeof(WCHAR));
    if (!copy)
        return E_OUTOFMEMORY;

    for (i = 0;; i++)
    {
        copy[i] = path[i];
        if (!path[i])
            break;
    }
    *ret_path = copy;
    return S_OK;
}
