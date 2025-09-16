// ytdlp_plugin.cpp — Delphi-ABI совместимый плагин для Download Master.
// Build: MSVC x86, /MT. Links: oleaut32.lib
// Путь к yt-dlp: из Plugins\ytdlp.ini ([ytdlp] path=...), иначе из PATH.

#include <windows.h>
#include <oleauto.h>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "oleaut32.lib")
// Даем DM сразу два имени экспорта: RegisterPlugIn и _RegisterPlugIn@0
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@0")

// IID'ы
static const IID IID_IUnknown    = {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IDMPlugIn   = {0x959CD0D3,0x83FD,0x40F7,{0xA7,0x5A,0xE5,0xC6,0x50,0x0B,0x58,0xDF}}; // из DMPluginIntf
// У IDMInterface GUID в DMPluginIntf есть только как тип Delphi; он нам не нужен здесь для QI.

// Утилиты
static HMODULE g_hModule = nullptr;

static void WriteMarker(const std::wstring& name) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_hModule, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; --i) {
        if (path[i] == L'\\' || path[i] == L'/') { path[i+1] = 0; break; }
    }
    std::wstring f = std::wstring(path) + name;
    HANDLE h = CreateFileW(f.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

static inline std::wstring WFromUTF8(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static inline std::wstring XmlEscape(const std::wstring& in) {
    std::wstring out; out.reserve(in.size()+16);
    for (wchar_t c: in) {
        switch(c){
            case L'&': out+=L"&amp;"; break;
            case L'<': out+=L"&lt;"; break;
            case L'>': out+=L"&gt;"; break;
            case L'"': out+=L"&quot;"; break;
            case L'\'':out+=L"&apos;"; break;
            default: out+=c; break;
        }
    }
    return out;
}
static inline std::wstring PathJoin(const std::wstring& a, const std::wstring& b){
    if (a.empty()) return b;
    if (a.back()==L'\\' || a.back()==L'/') return a + b;
    return a + L"\\" + b;
}
static bool RunProcessCapture(const std::wstring& app, const std::wstring& args, std::string& outUtf8, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE r=NULL,w=NULL;
    if (!CreatePipe(&r,&w,&sa,0)) return false;
    SetHandleInformation(r,HANDLE_FLAG_INHERIT,0);

    std::wstring cmd = L"\"" + app + L"\" " + args;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb=sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput=w; si.hStdError=w;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(w);
    if (!ok) { CloseHandle(r); return false; }

    char tmp[4096]; DWORD read=0; outUtf8.clear();
    while (ReadFile(r, tmp, sizeof(tmp), &read, nullptr) && read>0) outUtf8.append(tmp, tmp+read);
    CloseHandle(r);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return true;
}

// Виртуальные таблицы с «дельфи-ABI»

// IDMInterface (хост DM)
struct DMInterfaceVtbl {
    // IUnknown
    HRESULT (__stdcall* QueryInterface)(void* self, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void* self);
    ULONG   (__stdcall* Release)(void* self);
    // DoAction: фактически "procedure(out BSTR; self; BSTR action; BSTR params)"
    void    (__stdcall* DoAction)(BSTR* ret, void* self, BSTR action, BSTR params);
};
struct DMInterface {
    DMInterfaceVtbl* lpVtbl;
};

// Обёртка для вызова DoAction с «дельфи» сигнатурой
static std::wstring DM_DoAction(void* pDm, const std::wstring& a, const std::wstring& p) {
    if (!pDm) return L"";
    DMInterface* dm = reinterpret_cast<DMInterface*>(pDm);
    if (!dm->lpVtbl || !dm->lpVtbl->DoAction) return L"";
    BSTR ret = nullptr;
    BSTR ba = SysAllocStringLen(a.data(), (UINT)a.size());
    BSTR bp = SysAllocStringLen(p.data(), (UINT)p.size());
    dm->lpVtbl->DoAction(&ret, pDm, ba, bp);
    if (ba) SysFreeString(ba);
    if (bp) SysFreeString(bp);
    std::wstring w = ret ? std::wstring(ret, SysStringLen(ret)) : L"";
    if (ret) SysFreeString(ret);
    return w;
}

// IDMPlugIn vtable — методы с out BSTR (ret), затем self, затем явные параметры
struct PlugInObj;

typedef HRESULT (__stdcall* QI_t)(void* self, REFIID, void**);
typedef ULONG   (__stdcall* AR_t)(void* self);
typedef ULONG   (__stdcall* RL_t)(void* self);

typedef void (__stdcall* RetOnly_t)(BSTR* ret, void* self);
typedef void (__stdcall* RetLang_t)(BSTR* ret, void* self, BSTR language);
typedef void (__stdcall* ProcInit_t)(void* self, void* dmInterface);
typedef void (__stdcall* ProcStr_t)(void* self, BSTR params);
typedef void (__stdcall* ProcVoid_t)(void* self);
typedef void (__stdcall* RetEvent_t)(BSTR* ret, void* self, BSTR eventType, BSTR eventData);

struct PlugInVtbl {
    // IUnknown
    QI_t QueryInterface;
    AR_t AddRef;
    RL_t Release;
    // IDMPlugIn
    RetOnly_t  getID;
    RetOnly_t  GetName;
    RetOnly_t  GetVersion;
    RetLang_t  GetDescription;
    RetOnly_t  GetEmail;
    RetOnly_t  GetHomepage;
    RetOnly_t  GetCopyright;
    RetOnly_t  GetMinAppVersion;
    ProcInit_t PluginInit;
    ProcStr_t  PluginConfigure;
    ProcVoid_t BeforeUnload;
    RetEvent_t EventRaised;
};

struct PlugInObj {
    PlugInVtbl* lpVtbl;
    volatile LONG ref;
    void* dm;                // IDMInterface* (но звоним по Delphi-ABI)
    std::wstring pluginDir;
};

// Предварительные декларации
static void __stdcall PI_getID(BSTR* ret, void* self);
static void __stdcall PI_GetName(BSTR* ret, void* self);
static void __stdcall PI_GetVersion(BSTR* ret, void* self);
static void __stdcall PI_GetDescription(BSTR* ret, void* self, BSTR language);
static void __stdcall PI_GetEmail(BSTR* ret, void* self);
static void __stdcall PI_GetHomepage(BSTR* ret, void* self);
static void __stdcall PI_GetCopyright(BSTR* ret, void* self);
static void __stdcall PI_GetMinAppVersion(BSTR* ret, void* self);
static void __stdcall PI_PluginInit(void* self, void* dmInterface);
static void __stdcall PI_PluginConfigure(void* self, BSTR params);
static void __stdcall PI_BeforeUnload(void* self);
static void __stdcall PI_EventRaised(BSTR* ret, void* self, BSTR eventType, BSTR eventData);

static HRESULT __stdcall PI_QI(void* self, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IDMPlugIn)) {
        *ppv = self;
        ((PlugInObj*)self)->ref++;
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}
static ULONG __stdcall PI_AddRef(void* self) {
    return (ULONG)InterlockedIncrement(&((PlugInObj*)self)->ref);
}
static ULONG __stdcall PI_Release(void* self) {
    LONG r = InterlockedDecrement(&((PlugInObj*)self)->ref);
    if (r == 0) {
        delete (PlugInObj*)self;
    }
    return (ULONG)r;
}

static PlugInVtbl g_vtbl = {
    // IUnknown
    PI_QI, PI_AddRef, PI_Release,
    // IDMPlugIn
    PI_getID,
    PI_GetName,
    PI_GetVersion,
    PI_GetDescription,
    PI_GetEmail,
    PI_GetHomepage,
    PI_GetCopyright,
    PI_GetMinAppVersion,
    PI_PluginInit,
    PI_PluginConfigure,
    PI_BeforeUnload,
    PI_EventRaised
};

// Тело методов IDMPlugIn (в «дельфи»-сигнатурах)
static void SetRet(BSTR* ret, const std::wstring& s) {
    if (ret) *ret = SysAllocStringLen(s.data(), (UINT)s.size());
}

static void __stdcall PI_getID(BSTR* ret, void* /*self*/) {
    SetRet(ret, L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}");
}
static void __stdcall PI_GetName(BSTR* ret, void* /*self*/) {
    SetRet(ret, L"ytdlp plugin");
}
static void __stdcall PI_GetVersion(BSTR* ret, void* /*self*/) {
    SetRet(ret, L"0.1.0");
}
static void __stdcall PI_GetDescription(BSTR* ret, void* /*self*/, BSTR language) {
    std::wstring l = language ? std::wstring(language, SysStringLen(language)) : L"";
    if (!_wcsicmp(l.c_str(), L"russian") || !_wcsicmp(l.c_str(), L"ukrainian") || !_wcsicmp(l.c_str(), L"belarusian"))
        SetRet(ret, L"Плагин: пробует yt-dlp и заполняет описание.");
    else
        SetRet(ret, L"Plugin: runs yt-dlp and fills description.");
}
static void __stdcall PI_GetEmail(BSTR* ret, void* /*self*/)    { SetRet(ret, L"dev@example.com"); }
static void __stdcall PI_GetHomepage(BSTR* ret, void* /*self*/) { SetRet(ret, L"https://example.com"); }
static void __stdcall PI_GetCopyright(BSTR* ret, void* /*self*/){ SetRet(ret, L"\x00A9 2025 Example"); }
static void __stdcall PI_GetMinAppVersion(BSTR* ret, void* /*self*/) { SetRet(ret, L"5.0.2"); }

static std::wstring ReadIniYtDlp(const std::wstring& pluginDir) {
    if (pluginDir.empty()) return L"yt-dlp.exe";
    std::wstring ini = PathJoin(pluginDir, L"ytdlp.ini");
    DWORD attr = GetFileAttributesW(ini.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        wchar_t buf[1024]= {0};
        DWORD n = GetPrivateProfileStringW(L"ytdlp", L"path", L"", buf, 1024, ini.c_str());
        if (n>0) return std::wstring(buf, n);
    }
    return L"yt-dlp.exe";
}

static void __stdcall PI_PluginInit(void* self, void* dmInterface) {
    WriteMarker(L"ytdlp_PluginInit.txt");
    PlugInObj* obj = (PlugInObj*)self;
    // Сохраняем pointer DM
    obj->dm = dmInterface;
    // Получим папку плагинов
    obj->pluginDir = DM_DoAction(obj->dm, L"GetPluginDir", L"");
    for (auto& ch: obj->pluginDir) if (ch==L'/') ch=L'\\';
}
static void __stdcall PI_PluginConfigure(void* /*self*/, BSTR /*params*/) {
    // Пока пусто
}
static void __stdcall PI_BeforeUnload(void* self) {
    PlugInObj* obj = (PlugInObj*)self;
    obj->dm = nullptr;
}

static void AddLog(PlugInObj* obj, const std::wstring& id, int type, const std::wstring& msg) {
    if (!obj || !obj->dm) return;
    std::wstring xml = L"<id>"+id+L"</id><type>"+std::to_wstring(type)+L"</type><logstring>"+XmlEscape(msg)+L"</logstring>";
    DM_DoAction(obj->dm, L"AddStringToLog", xml);
}

static void __stdcall PI_EventRaised(BSTR* ret, void* self, BSTR eventType, BSTR eventData) {
    // По DM спецификации можно вернуть строку; вернём пустую
    if (ret) *ret = SysAllocString(L"");
    PlugInObj* obj = (PlugInObj*)self;
    std::wstring et = eventType ? std::wstring(eventType, SysStringLen(eventType)) : L"";
    std::wstring ed = eventData ? std::wstring(eventData, SysStringLen(eventData)) : L"";

    // Создадим маркер события
    if (!et.empty()) WriteMarker(L"ytdlp_ev_" + et + L".txt");

    // Реакция только на dm_download_added
    if (et == L"dm_download_added" && obj && obj->dm) {
        const std::wstring id = ed; // eventData = "ID"
        AddLog(obj, id, 2, L"[ytdlp] dm_download_added");

        // Получаем URL
        std::wstring info = DM_DoAction(obj->dm, L"GetDownloadInfoByID", id);
        // простенький парсер <url>...</url>
        auto findTag = [](const std::wstring& s, const wchar_t* tag)->std::wstring{
            std::wstring open = L"<"; open += tag; open += L">";
            std::wstring close = L"</"; close += tag; close += L">";
            size_t i = s.find(open); if (i==std::wstring::npos) return L"";
            i += open.size();
            size_t j = s.find(close, i); if (j==std::wstring::npos) return L"";
            return s.substr(i, j-i);
        };
        std::wstring url = findTag(info, L"url");
        if (url.empty()) {
            AddLog(obj, id, 3, L"[ytdlp] empty url");
            return;
        }

        // Путь к yt-dlp
        std::wstring ytdlp = ReadIniYtDlp(obj->pluginDir);

        // Быстрый режим: получить только title (-e)
        std::wstring args = L"-e --no-warnings -- \"" + url + L"\"";
        std::string out; DWORD ec=0;
        bool ok = RunProcessCapture(ytdlp, args, out, ec);

        if (!ok || ec != 0 || out.empty()) {
            AddLog(obj, id, 3, L"[ytdlp] probe failed");
            return;
        }

        // Обрежем \r\n
        while (!out.empty() && (out.back()=='\r' || out.back()=='\n')) out.pop_back();
        std::wstring title = WFromUTF8(out);

        if (!title.empty()) {
            // Обновим описание
            std::wstring patch = L"<id>"+id+L"</id><description>"+XmlEscape(title)+L" [yt-dlp]</description>";
            DM_DoAction(obj->dm, L"SetDownloadInfoByID", patch);
            AddLog(obj, id, 2, L"[ytdlp] title set");
        } else {
            AddLog(obj, id, 3, L"[ytdlp] empty title");
        }
    }
}

// Экспорт
extern "C" IDMPlugIn* __stdcall RegisterPlugIn() {
    WriteMarker(L"ytdlp_RegisterPlugIn_called.txt");
    try {
        PlugInObj* obj = new PlugInObj();
        obj->lpVtbl = &g_vtbl;
        obj->ref = 1;
        obj->dm = nullptr;
        return reinterpret_cast<IDMPlugIn*>(obj);
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
