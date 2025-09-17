#include <windows.h>
#include <oleauto.h>
#include <string>

#pragma comment(lib, "oleaut32.lib")
// Двойной экспорт, как на форуме (и красиво, и совместимо)
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@0")

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

// Наш «объект интерфейса»
struct PlugInObj;
struct PlugInVtbl {
    // IUnknown
    HRESULT (__stdcall* QueryInterface)(void*, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void*);
    ULONG   (__stdcall* Release)(void*);
    // IDMPlugIn: последовательность как в DMPluginIntf.pas
    void (__stdcall* getID)(void);            // thunk
    void (__stdcall* GetName)(void);          // thunk
    void (__stdcall* GetVersion)(void);       // thunk
    void (__stdcall* GetDescription)(void);   // thunk (3 args)
    void (__stdcall* GetEmail)(void);         // thunk
    void (__stdcall* GetHomepage)(void);      // thunk
    void (__stdcall* GetCopyright)(void);     // thunk
    void (__stdcall* GetMinAppVersion)(void); // thunk
    void (__stdcall* PluginInit)(void*, void* dm);
    void (__stdcall* PluginConfigure)(void*, BSTR params);
    void (__stdcall* BeforeUnload)(void*);
    void (__stdcall* EventRaised)(void);      // thunk (3 args)
};
struct PlugInObj {
    PlugInVtbl* lpVtbl;
    volatile LONG ref;
    void* dm;
};

// IUnknown
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

// Реализации (C++) — только маркеры/строки
static void __stdcall impl_getID(PlugInObj*, BSTR* ret)                 { WriteMarker(L"ytdlp_getID.txt");                 SetRet(ret, L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}"); }
static void __stdcall impl_GetName(PlugInObj*, BSTR* ret)               { WriteMarker(L"ytdlp_GetName.txt");               SetRet(ret, L"ytdlp plugin"); }
static void __stdcall impl_GetVersion(PlugInObj*, BSTR* ret)            { WriteMarker(L"ytdlp_GetVersion.txt");            SetRet(ret, L"0.1.0"); }
static void __stdcall impl_GetEmail(PlugInObj*, BSTR* ret)              { WriteMarker(L"ytdlp_GetEmail.txt");              SetRet(ret, L"dev@example.com"); }
static void __stdcall impl_GetHomepage(PlugInObj*, BSTR* ret)           { WriteMarker(L"ytdlp_GetHomepage.txt");           SetRet(ret, L"https://example.com"); }
static void __stdcall impl_GetCopyright(PlugInObj*, BSTR* ret)          { WriteMarker(L"ytdlp_GetCopyright.txt");          SetRet(ret, L"\x00A9 2025 Example"); }
static void __stdcall impl_GetMinAppVersion(PlugInObj*, BSTR* ret)      { WriteMarker(L"ytdlp_GetMinAppVersion.txt");      SetRet(ret, L"5.0.2"); }
static void __stdcall impl_GetDescription(PlugInObj*, BSTR* ret, BSTR lang) {
    WriteMarker(L"ytdlp_GetDescription.txt");
    const wchar_t* ru = L"Плагин-тест";
    const wchar_t* en = L"Plugin test";
    if (lang) {
        std::wstring l(lang, SysStringLen(lang));
        if (!_wcsicmp(l.c_str(), L"russian") || !_wcsicmp(l.c_str(), L"ukrainian") || !_wcsicmp(l.c_str(), L"belarusian")) { SetRet(ret, ru); return; }
    }
    SetRet(ret, en);
}
static void __stdcall impl_EventRaised(PlugInObj*, BSTR* ret, BSTR eventType, BSTR /*eventData*/) {
    if (ret) *ret = SysAllocString(L"");
    if (eventType) {
        std::wstring et(eventType, SysStringLen(eventType));
        if (!et.empty()) {
            std::wstring fn = L"ytdlp_ev_" + et + L".txt";
            WriteMarker(fn.c_str());
        }
    }
}
static void __stdcall PI_PluginInit(void* self, void* dmInterface) { WriteMarker(L"ytdlp_PluginInit.txt"); ((PlugInObj*)self)->dm = dmInterface; }
static void __stdcall PI_PluginConfigure(void*, BSTR)              { WriteMarker(L"ytdlp_PluginConfigure.txt"); }
static void __stdcall PI_BeforeUnload(void*)                       { WriteMarker(L"ytdlp_BeforeUnload.txt"); }

// Универсальные thunks: определяют, что из первых двух параметров — self (по vtbl), и зовут impl(...) в правильном порядке
// Два аргумента (self, ret) — 7 функций
#define MAKE_THUNK2(name, implfn) \
__declspec(naked) static void __stdcall name() { \
    __asm { \
        mov eax, [esp+4]    /* a1 */ \
        mov edx, [esp+8]    /* a2 */ \
        mov ecx, [eax]      /* [a1] -> vtbl? */ \
        cmp ecx, offset g_vtbl \
        je  L_self_eax_##name \
        mov ecx, [edx] \
        cmp ecx, offset g_vtbl \
        je  L_self_edx_##name \
        /* fallback: a1=self, a2=ret */ \
    L_self_eax_##name: \
        push edx            /* ret */ \
        push eax            /* self */ \
        call implfn \
        ret 8 \
    L_self_edx_##name: \
        push eax            /* ret */ \
        push edx            /* self */ \
        call implfn \
        ret 8 \
    } \
}

// Три аргумента (self, ret, lang/eventType/eventData) — 2 функции
#define MAKE_THUNK3(name, implfn) \
__declspec(naked) static void __stdcall name() { \
    __asm { \
        mov eax, [esp+4]    /* a1 */ \
        mov edx, [esp+8]    /* a2 */ \
        mov ebx, [esp+12]   /* a3 (lang or eventType) */ \
        mov ecx, [eax] \
        cmp ecx, offset g_vtbl \
        je  L_self_eax_##name \
        mov ecx, [edx] \
        cmp ecx, offset g_vtbl \
        je  L_self_edx_##name \
        /* fallback: a1=self, a2=ret */ \
    L_self_eax_##name: \
        push ebx            /* a3 */ \
        push edx            /* ret */ \
        push eax            /* self */ \
        call implfn \
        ret 12 \
    L_self_edx_##name: \
        push ebx            /* a3 */ \
        push eax            /* ret */ \
        push edx            /* self */ \
        call implfn \
        ret 12 \
    } \
}

// Для EventRaised 4 аргумента: (self, ret, eventType, eventData)
__declspec(naked) static void __stdcall THUNK_EventRaised() {
    __asm {
        mov eax, [esp+4]    /* a1 */
        mov edx, [esp+8]    /* a2 */
        mov ecx, [eax]
        cmp ecx, offset g_vtbl
        je  L_self_eax
        mov ecx, [edx]
        cmp ecx, offset g_vtbl
        je  L_self_edx
        /* fallback: a1=self, a2=ret */
    L_self_eax:
        mov ebx, [esp+12]   /* eventType */
        mov ecx, [esp+16]   /* eventData */
        push ecx
        push ebx
        push edx            /* ret */
        push eax            /* self */
        call impl_EventRaised
        ret 16
    L_self_edx:
        mov ebx, [esp+12]
        mov ecx, [esp+16]
        push ecx
        push ebx
        push eax            /* ret */
        push edx            /* self */
        call impl_EventRaised
        ret 16
    }
}

// Сгенерим thunks
MAKE_THUNK2(THUNK_getID,            impl_getID)
MAKE_THUNK2(THUNK_GetName,          impl_GetName)
MAKE_THUNK2(THUNK_GetVersion,       impl_GetVersion)
MAKE_THUNK2(THUNK_GetEmail,         impl_GetEmail)
MAKE_THUNK2(THUNK_GetHomepage,      impl_GetHomepage)
MAKE_THUNK2(THUNK_GetCopyright,     impl_GetCopyright)
MAKE_THUNK2(THUNK_GetMinAppVersion, impl_GetMinAppVersion)
MAKE_THUNK3(THUNK_GetDescription,   impl_GetDescription)

static PlugInVtbl g_vtbl = {
    PI_QI, PI_AddRef, PI_Release,
    (void(__stdcall*)(void))THUNK_getID,
    (void(__stdcall*)(void))THUNK_GetName,
    (void(__stdcall*)(void))THUNK_GetVersion,
    (void(__stdcall*)(void))THUNK_GetDescription,
    (void(__stdcall*)(void))THUNK_GetEmail,
    (void(__stdcall*)(void))THUNK_GetHomepage,
    (void(__stdcall*)(void))THUNK_GetCopyright,
    (void(__stdcall*)(void))THUNK_GetMinAppVersion,
    PI_PluginInit, PI_PluginConfigure, PI_BeforeUnload,
    (void(__stdcall*)(void))THUNK_EventRaised
};

extern "C" void* __stdcall RegisterPlugIn() {
    WriteMarker(L"ytdlp_RegisterPlugIn_called.txt");
    auto* obj = new PlugInObj();
    obj->lpVtbl = &g_vtbl;
    obj->ref = 1;
    obj->dm = nullptr;
    return obj;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = h;
        WriteMarker(L"ytdlp_DllMain_attach.txt");
    }
    return TRUE;
}
