#include <windows.h>
#include <oleauto.h>
#include <string>

#pragma comment(lib, "oleaut32.lib")
// ВАЖНО: экспортируем имя RegisterPlugIn и его декорированный вариант _RegisterPlugIn@4
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@4")

static HMODULE g_hModule = nullptr;

static void WriteMarker(const wchar_t* name) {
    wchar_t dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_hModule, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; --i) {
        if (dir[i] == L'\\' || dir[i] == L'/') { dir[i+1] = 0; break; }
    }
    std::wstring full = std::wstring(dir) + name;
    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
static inline void SetRet(BSTR* ret, const wchar_t* s) { if (ret) *ret = SysAllocString(s); }

// Виртуальная таблица и объект (Delphi-ABI: ret-first)
struct PlugInObj;
struct PlugInVtbl {
    // IUnknown
    HRESULT (__stdcall* QueryInterface)(void*, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void*);
    ULONG   (__stdcall* Release)(void*);

    // IDMPlugIn (Delphi: WideString-возвраты идут как "out BSTR first, self second")
    void (__stdcall* getID)(BSTR* ret, void* self);
    void (__stdcall* GetName)(BSTR* ret, void* self);
    void (__stdcall* GetVersion)(BSTR* ret, void* self);
    void (__stdcall* GetDescription)(BSTR* ret, void* self, BSTR language);
    void (__stdcall* GetEmail)(BSTR* ret, void* self);
    void (__stdcall* GetHomepage)(BSTR* ret, void* self);
    void (__stdcall* GetCopyright)(BSTR* ret, void* self);
    void (__stdcall* GetMinAppVersion)(BSTR* ret, void* self);

    void (__stdcall* PluginInit)(void* self, void* dmInterface);
    void (__stdcall* PluginConfigure)(void* self, BSTR params);
    void (__stdcall* BeforeUnload)(void* self);

    void (__stdcall* EventRaised)(BSTR* ret, void* self, BSTR eventType, BSTR eventData);
};

struct PlugInObj {
    PlugInVtbl* lpVtbl;
    volatile LONG ref;
    void* dm;
};

// IUnknown (делаем максимально простыми и с маркерами)
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

// Геттеры/методы (ret-first сигнатуры)
static void __stdcall PI_getID(BSTR* ret, void*)            { WriteMarker(L"ytdlp_getID.txt");            SetRet(ret, L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}"); }
static void __stdcall PI_GetName(BSTR* ret, void*)          { WriteMarker(L"ytdlp_GetName.txt");          SetRet(ret, L"ytdlp plugin"); }
static void __stdcall PI_GetVersion(BSTR* ret, void*)       { WriteMarker(L"ytdlp_GetVersion.txt");       SetRet(ret, L"0.1.0"); }
static void __stdcall PI_GetDescription(BSTR* ret, void*, BSTR language) {
    WriteMarker(L"ytdlp_GetDescription.txt");
    const wchar_t* ru = L"Плагин-тест";
    const wchar_t* en = L"Plugin test";
    if (language) {
        std::wstring l(language, SysStringLen(language));
        if (!_wcsicmp(l.c_str(), L"russian") || !_wcsicmp(l.c_str(), L"ukrainian") || !_wcsicmp(l.c_str(), L"belarusian")) {
            SetRet(ret, ru); return;
        }
    }
    SetRet(ret, en);
}
static void __stdcall PI_GetEmail(BSTR* ret, void*)         { WriteMarker(L"ytdlp_GetEmail.txt");         SetRet(ret, L"dev@example.com"); }
static void __stdcall PI_GetHomepage(BSTR* ret, void*)      { WriteMarker(L"ytdlp_GetHomepage.txt");      SetRet(ret, L"https://example.com"); }
static void __stdcall PI_GetCopyright(BSTR* ret, void*)     { WriteMarker(L"ytdlp_GetCopyright.txt");     SetRet(ret, L"\x00A9 2025 Example"); }
static void __stdcall PI_GetMinAppVersion(BSTR* ret, void*) { WriteMarker(L"ytdlp_GetMinAppVersion.txt"); SetRet(ret, L"5.0.2"); }

static void __stdcall PI_PluginInit(void* self, void* dmInterface) {
    WriteMarker(L"ytdlp_PluginInit.txt");
    ((PlugInObj*)self)->dm = dmInterface;
}
static void __stdcall PI_PluginConfigure(void*, BSTR)       { WriteMarker(L"ytdlp_PluginConfigure.txt"); }
static void __stdcall PI_BeforeUnload(void*)                { WriteMarker(L"ytdlp_BeforeUnload.txt"); }

static void __stdcall PI_EventRaised(BSTR* ret, void*, BSTR eventType, BSTR) {
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

// ВАЖНО: DM, судя по твоей версии, ждёт вариант с out-параметром
extern "C" __declspec(dllexport) HRESULT __stdcall RegisterPlugIn(void** out) {
    WriteMarker(L"ytdlp_RegisterPlugIn_called.txt");
    if (!out) return E_POINTER;
    auto* obj = new PlugInObj();
    obj->lpVtbl = &g_vtbl;
    obj->ref = 1;
    obj->dm = nullptr;
    *out = obj;
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = h;
        WriteMarker(L"ytdlp_DllMain_attach.txt");
    }
    return TRUE;
}
