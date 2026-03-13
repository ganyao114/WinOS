#include <stddef.h>
#include <stdint.h>

#define INITGUID
#define COBJMACROS
#include <objbase.h>
#include <oleauto.h>
#include <rpcdce.h>
#include <wbemcli.h>

typedef void *HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define STATUS_SUCCESS 0x00000000U
#define COINIT_MULTITHREADED 0x0

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void *apc_routine, void *apc_ctx,
    IO_STATUS_BLOCK *iosb, const void *buf, ULONG len, uint64_t *byte_offset, ULONG *key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);

static void write_buf(const char *buf, ULONG len)
{
    IO_STATUS_BLOCK iosb = {0};
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, buf, len, 0, 0);
}

static void write_str(const char *s)
{
    ULONG len = 0;
    while (s[len]) len++;
    write_buf(s, len);
}

static void write_hex32(uint32_t value)
{
    static const char digits[] = "0123456789ABCDEF";
    char buf[10];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; ++i)
        buf[2 + i] = digits[(value >> ((7 - i) * 4)) & 0xF];
    write_buf(buf, (ULONG)sizeof(buf));
}

static __attribute__((noreturn)) void exit_process(uint32_t code)
{
    NtTerminateProcess((HANDLE)0, code);
    for (;;)
        __asm__ volatile("wfi" ::: "memory");
}

void mainCRTStartup(void)
{
    HRESULT hr;
    IWbemLocator *locator = NULL;
    IWbemRefresher *refresher = NULL;
    IWbemConfigureRefresher *configure = NULL;
    IWbemHiPerfEnum *perf_enum = NULL;
    IWbemServices *services = NULL;
    IWbemObjectAccess *objects[4] = {0};
    BSTR namespace_path = NULL;
    long enum_id = 0;
    long temp_handle = 0;
    long name_handle = 0;
    CIMTYPE prop_type = 0;
    ULONG returned = 0;
    DWORD temperature = 0;
    WCHAR probe_buf[16] = {0};
    int probe_len = 0;

    write_str("== com_wbem_test ==\r\n");

    write_str("GetACP -> ");
    write_hex32((uint32_t)GetACP());
    write_str("\r\n");

    SetLastError(0xDEADBEEF);
    probe_len = MultiByteToWideChar(CP_ACP, 0, "root", -1, NULL, 0);
    write_str("MultiByteToWideChar(CP_ACP,size) -> ");
    write_hex32((uint32_t)probe_len);
    write_str(" gle=");
    write_hex32((uint32_t)GetLastError());
    write_str("\r\n");

    SetLastError(0xDEADBEEF);
    probe_len = MultiByteToWideChar(CP_ACP, 0, "root", -1, probe_buf, 16);
    write_str("MultiByteToWideChar(CP_ACP,buf) -> ");
    write_hex32((uint32_t)probe_len);
    write_str(" gle=");
    write_hex32((uint32_t)GetLastError());
    write_str(" first=");
    write_hex32((uint32_t)probe_buf[0]);
    write_str("\r\n");

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    write_str("CoInitializeEx -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(1);

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void **)&locator);
    write_str("CoCreateInstance(CLSID_WbemLocator) -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    write_str(locator ? "locator != NULL\r\n" : "locator == NULL\r\n");
    if (FAILED(hr))
        exit_process(2);

    namespace_path = SysAllocString(L"\\\\.\\root\\cimv2");
    if (!namespace_path)
        exit_process(12);

    hr = IWbemLocator_ConnectServer(locator, namespace_path, NULL, NULL, NULL, 0, NULL, NULL, &services);
    write_str("IWbemLocator::ConnectServer -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    write_str(services ? "services != NULL\r\n" : "services == NULL\r\n");
    if (FAILED(hr))
        exit_process(13);

    hr = CoSetProxyBlanket((IUnknown *)services,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           NULL,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL,
                           EOAC_NONE);
    write_str("CoSetProxyBlanket(services) -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(14);

    if (locator)
        IWbemLocator_Release(locator);

    hr = CoCreateInstance(&CLSID_WbemRefresher, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemRefresher, (void **)&refresher);
    write_str("CoCreateInstance(CLSID_WbemRefresher) -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    write_str(refresher ? "refresher != NULL\r\n" : "refresher == NULL\r\n");
    if (FAILED(hr))
        exit_process(3);

    hr = IWbemRefresher_QueryInterface(refresher, &IID_IWbemConfigureRefresher,
                                       (void **)&configure);
    write_str("IWbemRefresher::QueryInterface(IWbemConfigureRefresher) -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    write_str(configure ? "configure != NULL\r\n" : "configure == NULL\r\n");
    if (FAILED(hr))
        exit_process(4);

    hr = IWbemConfigureRefresher_AddEnum(
        configure, services, L"Win32_PerfRawData_Counters_ThermalZoneInformation", 0, NULL, &perf_enum, &enum_id);
    write_str("IWbemConfigureRefresher::AddEnum -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    write_str(perf_enum ? "enum != NULL\r\n" : "enum == NULL\r\n");
    if (FAILED(hr))
        exit_process(5);

    hr = IWbemRefresher_Refresh(refresher, 0);
    write_str("IWbemRefresher::Refresh -> ");
    write_hex32((uint32_t)hr);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(6);

    returned = 0xFFFFFFFFu;
    hr = IWbemHiPerfEnum_GetObjects(perf_enum, 0, 4, objects, &returned);
    write_str("IWbemHiPerfEnum::GetObjects -> ");
    write_hex32((uint32_t)hr);
    write_str(" returned=");
    write_hex32((uint32_t)returned);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(7);
    if (returned == 0 || !objects[0])
        exit_process(8);

    hr = IWbemObjectAccess_GetPropertyHandle(objects[0], L"Name", &prop_type, &name_handle);
    write_str("IWbemObjectAccess::GetPropertyHandle(Name) -> ");
    write_hex32((uint32_t)hr);
    write_str(" handle=");
    write_hex32((uint32_t)name_handle);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(9);

    hr = IWbemObjectAccess_GetPropertyHandle(objects[0], L"Temperature", &prop_type, &temp_handle);
    write_str("IWbemObjectAccess::GetPropertyHandle(Temperature) -> ");
    write_hex32((uint32_t)hr);
    write_str(" handle=");
    write_hex32((uint32_t)temp_handle);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(10);

    hr = IWbemObjectAccess_ReadDWORD(objects[0], temp_handle, &temperature);
    write_str("IWbemObjectAccess::ReadDWORD(Temperature) -> ");
    write_hex32((uint32_t)hr);
    write_str(" value=");
    write_hex32((uint32_t)temperature);
    write_str("\r\n");
    if (FAILED(hr))
        exit_process(11);

    if (objects[0])
        IWbemObjectAccess_Release(objects[0]);
    if (services)
        IWbemServices_Release(services);
    if (perf_enum)
        IWbemHiPerfEnum_Release(perf_enum);
    if (configure)
        IWbemConfigureRefresher_Release(configure);
    if (refresher)
        IWbemRefresher_Release(refresher);
    if (namespace_path)
        SysFreeString(namespace_path);
    CoUninitialize();

    exit_process(SUCCEEDED(hr) ? 0 : 2);
}
