#include <windows.h>
#include <oleauto.h>
#include <string>

#pragma comment(lib, "oleaut32.lib")
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@0")

static HMODULE g_hModule = nullptr;

static void WriteMarker(const wchar_t* name) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_hModule, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; --i) {
        if (path[i] == L'\\' || path[i] == L'/') { path[i+1] = 0; break; }
    }
    std::wstring full = std::wstring(path) + name;
    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
static inline void SetRet(BSTR* ret, const wchar_t* s) {
    if (ret) *ret = SysAllocString(s);
}

// IDMPlugIn vtable (self-first!)
struct PlugInObj;
typedef HRESULT (__stdcall* QI_t)(void* self, REFIID, void** );
typedef ULONG   (__stdcall* AR_t)(void* self);
typedef ULONG   (__stdcall* RL_t)(void* self);

typedef void (__stdcall* RetOnly_t)(void* self, BSTR* ret);
typedef void (__stdcall* RetLang_t)(void* self, BSTR* ret, BSTR lang);
typedef void (__stdcall* ProcInit_t)(void* self, void* dmInterface);
typedef void (__stdcall* ProcStr_t)(void* self, BSTR params);
typedef void (__stdcall* ProcVoid_t)(void* self);
typedef void (__stdcall* RetEvent_t)(void* self, BSTR* ret, BSTR eventType, BSTR eventData);

struct PlugInVtbl {
    QI_t QueryInterface;
    AR_t AddRef;
    RL_t Release;

    RetOnly_t getID;
    RetOnly_t GetName;
    RetOnly_t GetVersion;
    RetLang_t GetDescription;
    RetOnly_t GetEmail;
    RetOnly_t GetHomepage;
    RetOnly_t GetCopyright;
    RetOnly_t GetMinAppVersion;

    ProcInit_t PluginInit;
    ProcStr_t  PluginConfigure;
    ProcVoid_t BeforeUnload;

    RetEvent_t EventRaised;
};

struct PlugInObj {
    PlugInVtbl* lpVtbl;
    volatile LONG ref;
    void* dm; // не используем пока
};

static HRESULT __stdcall PI_QI(void* self, REFIID, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = self;
    InterlockedIncrement(&((PlugInObj*)self)->ref);
    WriteMarker(L"ytdlp_QI.txt");
    return S_OK;
}
static ULONG __stdcall PI_AddRef(void* self) {
    WriteMarker(L"ytdlp_AddRef.txt");
    return (ULONG)InterlockedIncrement(&((PlugInObj*)self)->ref);
}
static ULONG __stdcall PI_Release(void* self) {
    WriteMarker(L"ytdlp_Release.txt");
    LONG r = InterlockedDecrement(&((PlugInObj*)self)->ref);
    if (r == 0) delete (PlugInObj*)self;
    return (ULONG)r;
}

static void __stdcall PI_getID(void* /*self*/, BSTR* ret) {
    WriteMarker(L"ytdlp_getID.txt");
    SetRet(ret, L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}");
}
static void __stdcall PI_GetName(void* /*self*/, BSTR* ret) {
    WriteMarker(L"ytdlp_GetName.txt");
    SetRet(ret, L"ytdlp plugin");
}
static void __stdcall PI_GetVersion(void* /*self*/, BSTR* ret) {
    WriteMarker(L"ytdlp_GetVersion.txt");
    SetRet(ret, L"0.1.0");
}
static void __stdcall PI_GetDescription(void* /*self*/, BSTR* ret, BSTR lang) {
    WriteMarker(L"ytdlp_GetDescription.txt");
    const wchar_t* ru = L"Плагин-тест";
    const wchar_t* en = L"Plugin test";
    if (lang) {
        std::wstring l(lang, SysStringLen(lang));
        if (!_wcsicmp(l.c_str(), L"russian") || !_wcsicmp(l.c_str(), L"ukrainian") || !_wcsicmp(l.c_str(), L"belarusian")) {
            SetRet(ret, ru); return;
        }
    }
    SetRet(ret, en);
}
static void __stdcall PI_GetEmail(void* /*self*/, BSTR* ret)    { SetRet(ret, L"dev@example.com"); }
static void __stdcall PI_GetHomepage(void* /*self*/, BSTR* ret) { SetRet(ret, L"https://example.com"); }
static void __stdcall PI_GetCopyright(void* /*self*/, BSTR* ret){ SetRet(ret, L"\x00A9 2025 Example"); }
static void __stdcall PI_GetMinAppVersion(void* /*self*/, BSTR* ret) {
    WriteMarker(L"ytdlp_GetMinAppVersion.txt");
    SetRet(ret, L"5.0.2");
}

static void __stdcall PI_PluginInit(void* self, void* dmInterface) {
    WriteMarker(L"ytdlp_PluginInit.txt");
    ((PlugInObj*)self)->dm = dmInterface;
}
static void __stdcall PI_PluginConfigure(void* /*self*/, BSTR /*params*/) {
    WriteMarker(L"ytdlp_PluginConfigure.txt");
}
static void __stdcall PI_BeforeUnload(void* /*self*/) {
    WriteMarker(L"ytdlp_BeforeUnload.txt");
}

static void __stdcall PI_EventRaised(void* /*self*/, BSTR* ret, BSTR eventType, BSTR /*eventData*/) {
    if (ret) *ret = SysAllocString(L"");
    if (eventType) {
        std::wstring et(eventType, SysStringLen(eventType));
        if (!et.empty()) {
            std::wstring fn = L"ytdlp_ev_" + et + L".txt";
            WriteMarker(fn.c_str());
        }
    }
}

static PlugInVtbl g_vtbl = {
    PI_QI, PI_AddRef, PI_Release,
    PI_getID, PI_GetName, PI_GetVersion, PI_GetDescription,
    PI_GetEmail, PI_GetHomepage, PI_GetCopyright,
    PI_GetMinAppVersion, PI_PluginInit, PI_PluginConfigure,
    PI_BeforeUnload, PI_EventRaised
};

extern "C" void* __stdcall RegisterPlugIn() {
    WriteMarker(L"ytdlp_RegisterPlugIn_called.txt");
    try {
        auto* obj = new PlugInObj();
        obj->lpVtbl = &g_vtbl;
        obj->ref = 1;
        obj->dm = nullptr;
        return obj;
    } catch (...) {
        return nullptr;
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = h;
        WriteMarker(L"ytdlp_DllMain_attach.txt");
    }
    return TRUE;
}
