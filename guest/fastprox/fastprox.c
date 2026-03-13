#define COBJMACROS
#define INITGUID

#include <stddef.h>

#include <objbase.h>
#include <oleauto.h>
#include <wbemcli.h>
#include <winbase.h>

#define PERF_HANDLE_NAME 1
#define PERF_HANDLE_TEMPERATURE 2

typedef enum perf_kind {
    PERF_KIND_EMPTY = 0,
    PERF_KIND_THERMAL = 1,
} perf_kind;

typedef struct perf_object perf_object;
typedef struct wbem_hienum wbem_hienum;
typedef struct wbem_refresher wbem_refresher;
typedef struct wbem_class_factory wbem_class_factory;

struct perf_object {
    IWbemObjectAccess IWbemObjectAccess_iface;
    LONG refs;
    perf_kind kind;
};

struct wbem_hienum {
    IWbemHiPerfEnum IWbemHiPerfEnum_iface;
    LONG refs;
    perf_kind kind;
};

struct wbem_refresher {
    IWbemRefresher IWbemRefresher_iface;
    IWbemConfigureRefresher IWbemConfigureRefresher_iface;
    LONG refs;
    LONG next_id;
};

struct wbem_class_factory {
    IClassFactory IClassFactory_iface;
    LONG refs;
};

static LONG dll_refs;

static const WCHAR thermal_classW[] =
    L"Win32_PerfRawData_Counters_ThermalZoneInformation";
static const WCHAR thermal_nameW[] = L"Thermal Zone 0";
static const WCHAR prop_nameW[] = L"Name";
static const WCHAR prop_temperatureW[] = L"Temperature";

static void trace_ascii(const char *msg)
{
    HANDLE out;
    DWORD len = 0;
    DWORD written = 0;

    while (msg[len]) len++;
    out = GetStdHandle((DWORD)-11);
    if (!out || out == INVALID_HANDLE_VALUE) return;
    WriteFile(out, msg, len, &written, NULL);
}

static void variant_init_local(VARIANT *value)
{
    value->vt = VT_EMPTY;
    value->wReserved1 = 0;
    value->wReserved2 = 0;
    value->wReserved3 = 0;
    value->llVal = 0;
}

static void copy_bytes_local(void *dst, const void *src, SIZE_T len)
{
    BYTE *out = (BYTE *)dst;
    const BYTE *in = (const BYTE *)src;
    SIZE_T i;

    for (i = 0; i < len; ++i) out[i] = in[i];
}

static int guid_equal(REFIID left, REFIID right)
{
    const BYTE *l = (const BYTE *)left;
    const BYTE *r = (const BYTE *)right;
    size_t i;

    for (i = 0; i < sizeof(GUID); ++i)
    {
        if (l[i] != r[i]) return 0;
    }
    return 1;
}

static int wide_equal(LPCWSTR left, LPCWSTR right)
{
    if (!left || !right) return 0;
    return !lstrcmpiW(left, right);
}

static perf_kind perf_kind_from_class_name(LPCWSTR class_name)
{
    if (wide_equal(class_name, thermal_classW)) return PERF_KIND_THERMAL;
    if (class_name && *class_name) return PERF_KIND_THERMAL;
    return PERF_KIND_EMPTY;
}

static const WCHAR *perf_object_name(perf_kind kind)
{
    if (kind == PERF_KIND_THERMAL) return thermal_nameW;
    return L"";
}

static DWORD perf_object_temperature(perf_kind kind)
{
    if (kind == PERF_KIND_THERMAL) return 3000;
    return 0;
}

static inline perf_object *impl_from_IWbemObjectAccess(IWbemObjectAccess *iface)
{
    return (perf_object *)((char *)iface - offsetof(perf_object, IWbemObjectAccess_iface));
}

static inline wbem_hienum *impl_from_IWbemHiPerfEnum(IWbemHiPerfEnum *iface)
{
    return (wbem_hienum *)((char *)iface - offsetof(wbem_hienum, IWbemHiPerfEnum_iface));
}

static inline wbem_refresher *impl_from_IWbemRefresher(IWbemRefresher *iface)
{
    return (wbem_refresher *)((char *)iface - offsetof(wbem_refresher, IWbemRefresher_iface));
}

static inline wbem_refresher *impl_from_IWbemConfigureRefresher(
    IWbemConfigureRefresher *iface)
{
    return (wbem_refresher *)((char *)iface - offsetof(wbem_refresher, IWbemConfigureRefresher_iface));
}

static inline wbem_class_factory *impl_from_IClassFactory(IClassFactory *iface)
{
    return (wbem_class_factory *)((char *)iface - offsetof(wbem_class_factory, IClassFactory_iface));
}

static HRESULT create_perf_object(perf_kind kind, IWbemObjectAccess **out);

static HRESULT perf_object_query_interface(perf_object *self, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (guid_equal(riid, &IID_IUnknown) ||
        guid_equal(riid, &IID_IWbemClassObject) ||
        guid_equal(riid, &IID_IWbemObjectAccess))
    {
        *out = &self->IWbemObjectAccess_iface;
        IWbemObjectAccess_AddRef(&self->IWbemObjectAccess_iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static HRESULT WINAPI perf_object_QueryInterface(
    IWbemObjectAccess *iface, REFIID riid, void **out)
{
    return perf_object_query_interface(impl_from_IWbemObjectAccess(iface), riid, out);
}

static ULONG WINAPI perf_object_AddRef(IWbemObjectAccess *iface)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG WINAPI perf_object_Release(IWbemObjectAccess *iface)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);
    LONG refs = InterlockedDecrement(&self->refs);
    if (!refs)
    {
        InterlockedDecrement(&dll_refs);
        HeapFree(GetProcessHeap(), 0, self);
    }
    return (ULONG)refs;
}

static HRESULT WINAPI perf_object_GetQualifierSet(
    IWbemObjectAccess *iface, IWbemQualifierSet **qual_set)
{
    (void)iface;
    if (qual_set) *qual_set = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_Get(
    IWbemObjectAccess *iface,
    LPCWSTR name,
    LONG flags,
    VARIANT *value,
    CIMTYPE *type,
    LONG *flavor)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);

    (void)flags;
    if (!value) return WBEM_E_INVALID_PARAMETER;

    variant_init_local(value);
    if (type) *type = 0;
    if (flavor) *flavor = 0;

    if (wide_equal(name, prop_nameW))
    {
        trace_ascii("fastprox:Get(Name)\r\n");
        V_VT(value) = VT_BSTR;
        V_BSTR(value) = SysAllocString(perf_object_name(self->kind));
        if (!V_BSTR(value)) return E_OUTOFMEMORY;
        if (type) *type = CIM_STRING;
        return WBEM_S_NO_ERROR;
    }
    if (wide_equal(name, prop_temperatureW))
    {
        trace_ascii("fastprox:Get(Temperature)\r\n");
        V_VT(value) = VT_I4;
        V_I4(value) = (LONG)perf_object_temperature(self->kind);
        if (type) *type = CIM_SINT32;
        return WBEM_S_NO_ERROR;
    }
    return WBEM_E_NOT_FOUND;
}

static HRESULT WINAPI perf_object_Put(
    IWbemObjectAccess *iface, LPCWSTR name, LONG flags, VARIANT *value, CIMTYPE type)
{
    (void)iface;
    (void)name;
    (void)flags;
    (void)value;
    (void)type;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_Delete(IWbemObjectAccess *iface, LPCWSTR name)
{
    (void)iface;
    (void)name;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetNames(
    IWbemObjectAccess *iface,
    LPCWSTR qualifier_name,
    LONG flags,
    VARIANT *qualifier_value,
    SAFEARRAY **names)
{
    (void)iface;
    (void)qualifier_name;
    (void)flags;
    (void)qualifier_value;
    if (names) *names = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_BeginEnumeration(IWbemObjectAccess *iface, LONG enum_flags)
{
    (void)iface;
    (void)enum_flags;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_Next(
    IWbemObjectAccess *iface,
    LONG flags,
    BSTR *name,
    VARIANT *value,
    CIMTYPE *type,
    LONG *flavor)
{
    (void)iface;
    (void)flags;
    if (name) *name = NULL;
    if (value) variant_init_local(value);
    if (type) *type = 0;
    if (flavor) *flavor = 0;
    return WBEM_S_FALSE;
}

static HRESULT WINAPI perf_object_EndEnumeration(IWbemObjectAccess *iface)
{
    (void)iface;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI perf_object_GetPropertyQualifierSet(
    IWbemObjectAccess *iface,
    LPCWSTR property,
    IWbemQualifierSet **qual_set)
{
    (void)iface;
    (void)property;
    if (qual_set) *qual_set = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_Clone(IWbemObjectAccess *iface, IWbemClassObject **copy)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);
    IWbemObjectAccess *clone = NULL;
    HRESULT hr;

    if (!copy) return WBEM_E_INVALID_PARAMETER;
    *copy = NULL;

    hr = create_perf_object(self->kind, &clone);
    if (FAILED(hr)) return hr;
    *copy = (IWbemClassObject *)clone;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI perf_object_GetObjectText(
    IWbemObjectAccess *iface, LONG flags, BSTR *object_text)
{
    (void)iface;
    (void)flags;
    if (object_text) *object_text = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_SpawnDerivedClass(
    IWbemObjectAccess *iface, LONG flags, IWbemClassObject **new_class)
{
    (void)iface;
    (void)flags;
    if (new_class) *new_class = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_SpawnInstance(
    IWbemObjectAccess *iface, LONG flags, IWbemClassObject **new_instance)
{
    (void)iface;
    (void)flags;
    if (new_instance) *new_instance = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_CompareTo(
    IWbemObjectAccess *iface, LONG flags, IWbemClassObject *compare_to)
{
    (void)iface;
    (void)flags;
    (void)compare_to;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetPropertyOrigin(
    IWbemObjectAccess *iface, LPCWSTR name, BSTR *class_name)
{
    (void)iface;
    (void)name;
    if (class_name) *class_name = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_InheritsFrom(IWbemObjectAccess *iface, LPCWSTR ancestor)
{
    (void)iface;
    (void)ancestor;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetMethod(
    IWbemObjectAccess *iface,
    LPCWSTR name,
    LONG flags,
    IWbemClassObject **in_signature,
    IWbemClassObject **out_signature)
{
    (void)iface;
    (void)name;
    (void)flags;
    if (in_signature) *in_signature = NULL;
    if (out_signature) *out_signature = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_PutMethod(
    IWbemObjectAccess *iface,
    LPCWSTR name,
    LONG flags,
    IWbemClassObject *in_signature,
    IWbemClassObject *out_signature)
{
    (void)iface;
    (void)name;
    (void)flags;
    (void)in_signature;
    (void)out_signature;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_DeleteMethod(IWbemObjectAccess *iface, LPCWSTR name)
{
    (void)iface;
    (void)name;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_BeginMethodEnumeration(
    IWbemObjectAccess *iface, LONG enum_flags)
{
    (void)iface;
    (void)enum_flags;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_NextMethod(
    IWbemObjectAccess *iface,
    LONG flags,
    BSTR *name,
    IWbemClassObject **in_signature,
    IWbemClassObject **out_signature)
{
    (void)iface;
    (void)flags;
    if (name) *name = NULL;
    if (in_signature) *in_signature = NULL;
    if (out_signature) *out_signature = NULL;
    return WBEM_S_FALSE;
}

static HRESULT WINAPI perf_object_EndMethodEnumeration(IWbemObjectAccess *iface)
{
    (void)iface;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI perf_object_GetMethodQualifierSet(
    IWbemObjectAccess *iface, LPCWSTR method, IWbemQualifierSet **qual_set)
{
    (void)iface;
    (void)method;
    if (qual_set) *qual_set = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetMethodOrigin(
    IWbemObjectAccess *iface, LPCWSTR method_name, BSTR *class_name)
{
    (void)iface;
    (void)method_name;
    if (class_name) *class_name = NULL;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetPropertyHandle(
    IWbemObjectAccess *iface, LPCWSTR property_name, CIMTYPE *type, LONG *handle)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);

    (void)self;
    if (!handle) return WBEM_E_INVALID_PARAMETER;
    if (type) *type = 0;
    *handle = 0;

    if (wide_equal(property_name, prop_nameW))
    {
        trace_ascii("fastprox:GetPropertyHandle(Name)\r\n");
        *handle = PERF_HANDLE_NAME;
        if (type) *type = CIM_STRING;
        return WBEM_S_NO_ERROR;
    }
    if (wide_equal(property_name, prop_temperatureW))
    {
        trace_ascii("fastprox:GetPropertyHandle(Temperature)\r\n");
        *handle = PERF_HANDLE_TEMPERATURE;
        if (type) *type = CIM_SINT32;
        return WBEM_S_NO_ERROR;
    }
    return WBEM_E_NOT_FOUND;
}

static HRESULT WINAPI perf_object_WritePropertyValue(
    IWbemObjectAccess *iface, LONG handle, LONG num_bytes, const byte *data)
{
    (void)iface;
    (void)handle;
    (void)num_bytes;
    (void)data;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_ReadPropertyValue(
    IWbemObjectAccess *iface,
    LONG handle,
    LONG buffer_size,
    LONG *num_bytes,
    byte *data)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);
    LONG needed = 0;

    if (!num_bytes) return WBEM_E_INVALID_PARAMETER;
    *num_bytes = 0;

    if (handle == PERF_HANDLE_NAME)
    {
        const WCHAR *name = perf_object_name(self->kind);
        needed = (LONG)((lstrlenW(name) + 1) * sizeof(WCHAR));
        *num_bytes = needed;
        if (!data || buffer_size < needed) return WBEM_E_INVALID_PARAMETER;
        copy_bytes_local(data, name, (SIZE_T)needed);
        return WBEM_S_NO_ERROR;
    }
    if (handle == PERF_HANDLE_TEMPERATURE)
    {
        DWORD temp = perf_object_temperature(self->kind);
        needed = (LONG)sizeof(temp);
        *num_bytes = needed;
        if (!data || buffer_size < needed) return WBEM_E_INVALID_PARAMETER;
        copy_bytes_local(data, &temp, sizeof(temp));
        return WBEM_S_NO_ERROR;
    }
    return WBEM_E_NOT_FOUND;
}

static HRESULT WINAPI perf_object_ReadDWORD(
    IWbemObjectAccess *iface, LONG handle, DWORD *value)
{
    perf_object *self = impl_from_IWbemObjectAccess(iface);

    if (!value) return WBEM_E_INVALID_PARAMETER;
    if (handle != PERF_HANDLE_TEMPERATURE) return WBEM_E_NOT_FOUND;
    trace_ascii("fastprox:ReadDWORD(Temperature)\r\n");
    *value = perf_object_temperature(self->kind);
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI perf_object_WriteDWORD(
    IWbemObjectAccess *iface, LONG handle, DWORD value)
{
    (void)iface;
    (void)handle;
    (void)value;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_ReadQWORD(
    IWbemObjectAccess *iface, LONG handle, unsigned __int64 *value)
{
    (void)iface;
    (void)handle;
    if (value) *value = 0;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_WriteQWORD(
    IWbemObjectAccess *iface, LONG handle, unsigned __int64 value)
{
    (void)iface;
    (void)handle;
    (void)value;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI perf_object_GetPropertyInfoByHandle(
    IWbemObjectAccess *iface, LONG handle, BSTR *name, CIMTYPE *type)
{
    (void)iface;
    if (!name) return WBEM_E_INVALID_PARAMETER;
    *name = NULL;
    if (type) *type = 0;

    if (handle == PERF_HANDLE_NAME)
    {
        *name = SysAllocString(prop_nameW);
        if (!*name) return E_OUTOFMEMORY;
        if (type) *type = CIM_STRING;
        return WBEM_S_NO_ERROR;
    }
    if (handle == PERF_HANDLE_TEMPERATURE)
    {
        *name = SysAllocString(prop_temperatureW);
        if (!*name) return E_OUTOFMEMORY;
        if (type) *type = CIM_SINT32;
        return WBEM_S_NO_ERROR;
    }
    return WBEM_E_NOT_FOUND;
}

static HRESULT WINAPI perf_object_Lock(IWbemObjectAccess *iface, LONG flags)
{
    (void)iface;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI perf_object_Unlock(IWbemObjectAccess *iface, LONG flags)
{
    (void)iface;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static IWbemObjectAccessVtbl perf_object_vtbl = {
    perf_object_QueryInterface,
    perf_object_AddRef,
    perf_object_Release,
    perf_object_GetQualifierSet,
    perf_object_Get,
    perf_object_Put,
    perf_object_Delete,
    perf_object_GetNames,
    perf_object_BeginEnumeration,
    perf_object_Next,
    perf_object_EndEnumeration,
    perf_object_GetPropertyQualifierSet,
    perf_object_Clone,
    perf_object_GetObjectText,
    perf_object_SpawnDerivedClass,
    perf_object_SpawnInstance,
    perf_object_CompareTo,
    perf_object_GetPropertyOrigin,
    perf_object_InheritsFrom,
    perf_object_GetMethod,
    perf_object_PutMethod,
    perf_object_DeleteMethod,
    perf_object_BeginMethodEnumeration,
    perf_object_NextMethod,
    perf_object_EndMethodEnumeration,
    perf_object_GetMethodQualifierSet,
    perf_object_GetMethodOrigin,
    perf_object_GetPropertyHandle,
    perf_object_WritePropertyValue,
    perf_object_ReadPropertyValue,
    perf_object_ReadDWORD,
    perf_object_WriteDWORD,
    perf_object_ReadQWORD,
    perf_object_WriteQWORD,
    perf_object_GetPropertyInfoByHandle,
    perf_object_Lock,
    perf_object_Unlock,
};

static HRESULT create_perf_object(perf_kind kind, IWbemObjectAccess **out)
{
    perf_object *self;

    if (!out) return E_POINTER;
    *out = NULL;

    self = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*self));
    if (!self) return E_OUTOFMEMORY;

    self->IWbemObjectAccess_iface.lpVtbl = &perf_object_vtbl;
    self->refs = 1;
    self->kind = kind;
    InterlockedIncrement(&dll_refs);
    *out = &self->IWbemObjectAccess_iface;
    return S_OK;
}

static HRESULT hienum_query_interface(wbem_hienum *self, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (guid_equal(riid, &IID_IUnknown) || guid_equal(riid, &IID_IWbemHiPerfEnum))
    {
        *out = &self->IWbemHiPerfEnum_iface;
        IWbemHiPerfEnum_AddRef(&self->IWbemHiPerfEnum_iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static HRESULT WINAPI hienum_QueryInterface(IWbemHiPerfEnum *iface, REFIID riid, void **out)
{
    return hienum_query_interface(impl_from_IWbemHiPerfEnum(iface), riid, out);
}

static ULONG WINAPI hienum_AddRef(IWbemHiPerfEnum *iface)
{
    wbem_hienum *self = impl_from_IWbemHiPerfEnum(iface);
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG WINAPI hienum_Release(IWbemHiPerfEnum *iface)
{
    wbem_hienum *self = impl_from_IWbemHiPerfEnum(iface);
    LONG refs = InterlockedDecrement(&self->refs);
    if (!refs)
    {
        InterlockedDecrement(&dll_refs);
        HeapFree(GetProcessHeap(), 0, self);
    }
    return (ULONG)refs;
}

static HRESULT WINAPI hienum_AddObjects(
    IWbemHiPerfEnum *iface, long flags, ULONG num_objects, long *ids, IWbemObjectAccess **objects)
{
    (void)iface;
    (void)flags;
    (void)num_objects;
    (void)ids;
    (void)objects;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI hienum_RemoveObjects(
    IWbemHiPerfEnum *iface, long flags, ULONG num_objects, long *ids)
{
    (void)iface;
    (void)flags;
    (void)num_objects;
    (void)ids;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI hienum_GetObjects(
    IWbemHiPerfEnum *iface,
    long flags,
    ULONG num_objects,
    IWbemObjectAccess **objects,
    ULONG *returned)
{
    wbem_hienum *self = impl_from_IWbemHiPerfEnum(iface);
    HRESULT hr;
    ULONG i;

    (void)flags;
    if (!returned) return WBEM_E_INVALID_PARAMETER;
    *returned = 0;

    if (objects)
    {
        for (i = 0; i < num_objects; ++i) objects[i] = NULL;
    }
    if (!objects || !num_objects) return WBEM_E_INVALID_PARAMETER;
    if (self->kind == PERF_KIND_EMPTY) return WBEM_S_FALSE;

    trace_ascii("fastprox:GetObjects\r\n");
    hr = create_perf_object(self->kind, &objects[0]);
    if (FAILED(hr)) return hr;
    *returned = 1;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI hienum_RemoveAll(IWbemHiPerfEnum *iface, long flags)
{
    (void)iface;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static IWbemHiPerfEnumVtbl wbem_hienum_vtbl = {
    hienum_QueryInterface,
    hienum_AddRef,
    hienum_Release,
    hienum_AddObjects,
    hienum_RemoveObjects,
    hienum_GetObjects,
    hienum_RemoveAll,
};

static HRESULT create_hienum(perf_kind kind, IWbemHiPerfEnum **out)
{
    wbem_hienum *self;

    if (!out) return E_POINTER;
    *out = NULL;

    self = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*self));
    if (!self) return E_OUTOFMEMORY;

    self->IWbemHiPerfEnum_iface.lpVtbl = &wbem_hienum_vtbl;
    self->refs = 1;
    self->kind = kind;
    InterlockedIncrement(&dll_refs);
    *out = &self->IWbemHiPerfEnum_iface;
    return S_OK;
}

static HRESULT refresher_query_interface(wbem_refresher *self, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (guid_equal(riid, &IID_IUnknown) || guid_equal(riid, &IID_IWbemRefresher))
    {
        *out = &self->IWbemRefresher_iface;
        IWbemRefresher_AddRef(&self->IWbemRefresher_iface);
        return S_OK;
    }
    if (guid_equal(riid, &IID_IWbemConfigureRefresher))
    {
        *out = &self->IWbemConfigureRefresher_iface;
        IWbemConfigureRefresher_AddRef(&self->IWbemConfigureRefresher_iface);
        return S_OK;
    }
    trace_ascii("fastprox:QI unsupported\r\n");
    return E_NOINTERFACE;
}

static HRESULT WINAPI refresher_QueryInterface(
    IWbemRefresher *iface, REFIID riid, void **out)
{
    return refresher_query_interface(impl_from_IWbemRefresher(iface), riid, out);
}

static ULONG WINAPI refresher_AddRef(IWbemRefresher *iface)
{
    wbem_refresher *self = impl_from_IWbemRefresher(iface);
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG WINAPI refresher_Release(IWbemRefresher *iface)
{
    wbem_refresher *self = impl_from_IWbemRefresher(iface);
    LONG refs = InterlockedDecrement(&self->refs);
    if (!refs)
    {
        InterlockedDecrement(&dll_refs);
        HeapFree(GetProcessHeap(), 0, self);
    }
    return (ULONG)refs;
}

static HRESULT WINAPI refresher_Refresh(IWbemRefresher *iface, long flags)
{
    (void)iface;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static IWbemRefresherVtbl wbem_refresher_vtbl = {
    refresher_QueryInterface,
    refresher_AddRef,
    refresher_Release,
    refresher_Refresh,
};

static HRESULT WINAPI configure_QueryInterface(
    IWbemConfigureRefresher *iface, REFIID riid, void **out)
{
    return refresher_query_interface(impl_from_IWbemConfigureRefresher(iface), riid, out);
}

static ULONG WINAPI configure_AddRef(IWbemConfigureRefresher *iface)
{
    wbem_refresher *self = impl_from_IWbemConfigureRefresher(iface);
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG WINAPI configure_Release(IWbemConfigureRefresher *iface)
{
    wbem_refresher *self = impl_from_IWbemConfigureRefresher(iface);
    LONG refs = InterlockedDecrement(&self->refs);
    if (!refs)
    {
        InterlockedDecrement(&dll_refs);
        HeapFree(GetProcessHeap(), 0, self);
    }
    return (ULONG)refs;
}

static HRESULT WINAPI configure_AddObjectByPath(
    IWbemConfigureRefresher *iface,
    IWbemServices *namespace,
    LPCWSTR path,
    long flags,
    IWbemContext *context,
    IWbemClassObject **refreshable,
    long *id)
{
    (void)iface;
    (void)namespace;
    (void)path;
    (void)flags;
    (void)context;
    if (refreshable) *refreshable = NULL;
    if (id) *id = 0;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI configure_AddObjectByTemplate(
    IWbemConfigureRefresher *iface,
    IWbemServices *namespace,
    IWbemClassObject *templ,
    long flags,
    IWbemContext *context,
    IWbemClassObject **refreshable,
    long *id)
{
    (void)iface;
    (void)namespace;
    (void)templ;
    (void)flags;
    (void)context;
    if (refreshable) *refreshable = NULL;
    if (id) *id = 0;
    return WBEM_E_NOT_SUPPORTED;
}

static HRESULT WINAPI configure_AddRefresher(
    IWbemConfigureRefresher *iface, IWbemRefresher *refresher, long flags, long *id)
{
    wbem_refresher *self = impl_from_IWbemConfigureRefresher(iface);

    (void)refresher;
    (void)flags;
    if (id) *id = InterlockedIncrement(&self->next_id);
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI configure_Remove(IWbemConfigureRefresher *iface, long id, long flags)
{
    (void)iface;
    (void)id;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static HRESULT WINAPI configure_AddEnum(
    IWbemConfigureRefresher *iface,
    IWbemServices *namespace,
    LPCWSTR class_name,
    long flags,
    IWbemContext *context,
    IWbemHiPerfEnum **enum_out,
    long *id)
{
    wbem_refresher *self = impl_from_IWbemConfigureRefresher(iface);
    HRESULT hr;
    perf_kind kind;

    (void)namespace;
    (void)flags;
    (void)context;

    if (!enum_out) return WBEM_E_INVALID_PARAMETER;
    kind = perf_kind_from_class_name(class_name);
    if (kind == PERF_KIND_THERMAL) trace_ascii("fastprox:AddEnum thermal\r\n");
    else trace_ascii("fastprox:AddEnum empty\r\n");
    hr = create_hienum(kind, enum_out);
    if (FAILED(hr))
    {
        if (id) *id = 0;
        return hr;
    }
    if (id) *id = InterlockedIncrement(&self->next_id);
    return WBEM_S_NO_ERROR;
}

static IWbemConfigureRefresherVtbl wbem_configure_refresher_vtbl = {
    configure_QueryInterface,
    configure_AddRef,
    configure_Release,
    configure_AddObjectByPath,
    configure_AddObjectByTemplate,
    configure_AddRefresher,
    configure_Remove,
    configure_AddEnum,
};

static HRESULT create_refresher(REFIID riid, void **out)
{
    wbem_refresher *self;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;

    self = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*self));
    if (!self) return E_OUTOFMEMORY;

    self->IWbemRefresher_iface.lpVtbl = &wbem_refresher_vtbl;
    self->IWbemConfigureRefresher_iface.lpVtbl = &wbem_configure_refresher_vtbl;
    self->refs = 1;
    self->next_id = 0;
    InterlockedIncrement(&dll_refs);

    hr = refresher_query_interface(self, riid, out);
    IWbemRefresher_Release(&self->IWbemRefresher_iface);
    return hr;
}

static HRESULT WINAPI class_factory_QueryInterface(
    IClassFactory *iface, REFIID riid, void **out)
{
    wbem_class_factory *self = impl_from_IClassFactory(iface);

    if (!out) return E_POINTER;
    *out = NULL;

    if (guid_equal(riid, &IID_IUnknown) || guid_equal(riid, &IID_IClassFactory))
    {
        *out = &self->IClassFactory_iface;
        IClassFactory_AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI class_factory_AddRef(IClassFactory *iface)
{
    wbem_class_factory *self = impl_from_IClassFactory(iface);
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG WINAPI class_factory_Release(IClassFactory *iface)
{
    wbem_class_factory *self = impl_from_IClassFactory(iface);
    LONG refs = InterlockedDecrement(&self->refs);
    if (!refs) HeapFree(GetProcessHeap(), 0, self);
    return (ULONG)refs;
}

static HRESULT WINAPI class_factory_CreateInstance(
    IClassFactory *iface, IUnknown *outer, REFIID riid, void **out)
{
    (void)iface;
    if (outer) return CLASS_E_NOAGGREGATION;
    return create_refresher(riid, out);
}

static HRESULT WINAPI class_factory_LockServer(IClassFactory *iface, BOOL lock)
{
    (void)iface;
    if (lock) InterlockedIncrement(&dll_refs);
    else InterlockedDecrement(&dll_refs);
    return S_OK;
}

static IClassFactoryVtbl wbem_class_factory_vtbl = {
    class_factory_QueryInterface,
    class_factory_AddRef,
    class_factory_Release,
    class_factory_CreateInstance,
    class_factory_LockServer,
};

static HRESULT create_class_factory(REFIID riid, void **out)
{
    wbem_class_factory *self;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;

    self = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*self));
    if (!self) return E_OUTOFMEMORY;

    self->IClassFactory_iface.lpVtbl = &wbem_class_factory_vtbl;
    self->refs = 1;
    hr = class_factory_QueryInterface(&self->IClassFactory_iface, riid, out);
    IClassFactory_Release(&self->IClassFactory_iface);
    return hr;
}

HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **out)
{
    if (!guid_equal(rclsid, &CLSID_WbemRefresher)) return CLASS_E_CLASSNOTAVAILABLE;
    return create_class_factory(riid, out);
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return dll_refs ? S_FALSE : S_OK;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

BOOL WINAPI DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    return DllMain(instance, reason, reserved);
}
