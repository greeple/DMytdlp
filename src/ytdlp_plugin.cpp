#include <windows.h>
#include <oleaut32.h>
#include <string>
#include <vector>

#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
// Экспорт красивого имени + stdcall-декоратора @4 (out-параметр)
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@4")

static HMODULE g_hModule = nullptr;

// ---------- Утилиты ----------
static void WriteMarker(const wchar_t* name) {
    wchar_t dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_hModule, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; --i) {
        if (dir[i] == L'\\' || dir[i] == L'/') { dir[i + 1] = 0; break; }
    }
    std::wstring full = std::wstring(dir) + name;
    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
static inline void SetRet(BSTR* ret, const wchar_t* s) { if (ret) *ret = SysAllocString(s); }
static std::wstring BSTRtoW(BSTR s) { return s ? std::wstring(s, SysStringLen(s)) : L""; }

static std::string WToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], n, nullptr, nullptr);
    return out;
}
static std::wstring NowTs() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}
static void AppendTrace(const std::wstring& line) {
    // путь к ytdlp_trace.txt рядом с DLL
    wchar_t dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_hModule, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; --i) {
        if (dir[i] == L'\\' || dir[i] == L'/') { dir[i + 1] = 0; break; }
    }
    std::wstring path = std::wstring(dir) + L"ytdlp_trace.txt";

    // Создадим файл и при необходимости запишем BOM
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    bool newFile = !GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad);

    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    if (newFile) {
        static const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
        DWORD wr; WriteFile(h, bom, 3, &wr, nullptr);
    }

    std::wstring full = NowTs() + L" " + line + L"\r\n";
    std::string utf8 = WToUtf8(full);
    DWORD wr; WriteFile(h, utf8.data(), (DWORD)utf8.size(), &wr, nullptr);
    CloseHandle(h);
}

static bool ParseLeadingInt(const std::wstring& s, int& out) {
    const wchar_t* p = s.c_str();
    wchar_t* end = nullptr;
    long v = wcstol(p, &end, 10);
    if (p == end) return false;
    out = (int)v;
    return true;
}

static std::wstring XmlEscape(const std::wstring& in) {
    std::wstring out; out.reserve(in.size() + 16);
    for (wchar_t c : in) {
        switch (c) {
            case L'&': out += L"&amp;";  break;
            case L'<': out += L"&lt;";   break;
            case L'>': out += L"&gt;";   break;
            case L'"': out += L"&quot;"; break;
            case L'\'':out += L"&apos;"; break;
            default:   out += c;         break;
        }
    }
    return out;
}

static std::wstring PathJoin(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

static std::wstring ExtractTag(const std::wstring& xml, const wchar_t* t) {
    std::wstring open = L"<"; open += t; open += L">";
    std::wstring close = L"</"; close += t; close += L">";
    size_t i = xml.find(open);
    if (i == std::wstring::npos) return L"";
    i += open.size();
    size_t j = xml.find(close, i);
    if (j == std::wstring::npos) return L"";
    return xml.substr(i, j - i);
}

// ---------- DMInterface (Delphi-ABI ret-first) ----------
struct DMInterfaceVtbl {
    HRESULT (__stdcall* QueryInterface)(void*, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void*);
    ULONG   (__stdcall* Release)(void*);
    void    (__stdcall* DoAction)(BSTR* ret, void* self, BSTR action, BSTR parameters);
};
struct DMInterface { DMInterfaceVtbl* lpVtbl; };

static std::wstring DM_DoAction(void* pDm, const std::wstring& a, const std::wstring& p) {
    if (!pDm) return L"";
    auto* dm = reinterpret_cast<DMInterface*>(pDm);
    if (!dm->lpVtbl || !dm->lpVtbl->DoAction) return L"";

    // логируем, что отправляем
    std::wstring pLog = p.substr(0, 512);
    AppendTrace(L"[DoAction] action=\"" + a + L"\" params=\"" + pLog + L"\"");

    BSTR ret = nullptr;
    BSTR ba = SysAllocStringLen(a.data(), (UINT)a.size());
    BSTR bp = SysAllocStringLen(p.data(), (UINT)p.size());
    dm->lpVtbl->DoAction(&ret, pDm, ba, bp);
    if (ba) SysFreeString(ba);
    if (bp) SysFreeString(bp);

    std::wstring w = BSTRtoW(ret);
    if (ret) SysFreeString(ret);

    AppendTrace(L"[DoActionResult] action=\"" + a + L"\" result_len=" + std::to_wstring(w.size()));
    return w;
}

// ---------- запуск внешнего процесса ----------
static bool RunProcessCapture(const std::wstring& app, const std::wstring& args, std::string& outUtf8, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE r = NULL, w = NULL;
    if (!CreatePipe(&r, &w, &sa, 0)) return false;
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmd = L"\"" + app + L"\" " + args;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = w; si.hStdError = w;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    AppendTrace(L"[RunApp] " + cmd + (ok ? L" (OK)" : L" (FAIL)"));
    CloseHandle(w);
    if (!ok) { CloseHandle(r); return false; }

    char tmp[4096]; DWORD rd = 0; outUtf8.clear();
    while (ReadFile(r, tmp, sizeof(tmp), &rd, nullptr) && rd > 0) outUtf8.append(tmp, tmp + rd);
    CloseHandle(r);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    AppendTrace(L"[RunAppExit] code=" + std::to_wstring(exitCode));
    return true;
}

static std::wstring Utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring ReadIniYtDlp(const std::wstring& dir) {
    if (dir.empty()) return L"yt-dlp.exe";
    std::wstring ini = PathJoin(dir, L"ytdlp.ini");
    DWORD attr = GetFileAttributesW(ini.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        wchar_t buf[1024] = {0};
        DWORD n = GetPrivateProfileStringW(L"ytdlp", L"path", L"", buf, 1024, ini.c_str());
        if (n > 0) return std::wstring(buf, n);
    }
    return L"yt-dlp.exe";
}

// ---------- Плагин (Delphi-ABI ret-first) ----------
struct PlugInObj;
struct PlugInVtbl {
    // IUnknown
    HRESULT (__stdcall* QueryInterface)(void*, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void*);
    ULONG   (__stdcall* Release)(void*);
    // IDMPlugIn
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
    std::wstring pluginDir;
    std::wstring ytdlpPath;
};

static void AddLog(PlugInObj* o, const std::wstring& id, int type, const std::wstring& msg) {
    if (!o || !o->dm) return;
    std::wstring xml = L"<id>" + id + L"</id><type>" + std::to_wstring(type) + L"</type><logstring>" + XmlEscape(msg) + L"</logstring>";
    DM_DoAction(o->dm, L"AddStringToLog", xml);
}

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

// Инфо
static void __stdcall PI_getID(BSTR* ret, void*)            { WriteMarker(L"ytdlp_getID.txt");            SetRet(ret, L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}"); }
static void __stdcall PI_GetName(BSTR* ret, void*)          { WriteMarker(L"ytdlp_GetName.txt");          SetRet(ret, L"ytdlp plugin"); }
static void __stdcall PI_GetVersion(BSTR* ret, void*)       { WriteMarker(L"ytdlp_GetVersion.txt");       SetRet(ret, L"0.1.0"); }
static void __stdcall PI_GetDescription(BSTR* ret, void*, BSTR /*language*/) {
    WriteMarker(L"ytdlp_GetDescription.txt");
    SetRet(ret, L"YTDLP test plugin (fills title via yt-dlp).");
}
static void __stdcall PI_GetEmail(BSTR* ret, void*)         { WriteMarker(L"ytdlp_GetEmail.txt");         SetRet(ret, L"dev@example.com"); }
static void __stdcall PI_GetHomepage(BSTR* ret, void*)      { WriteMarker(L"ytdlp_GetHomepage.txt");      SetRet(ret, L"https://example.com"); }
static void __stdcall PI_GetCopyright(BSTR* ret, void*)     { WriteMarker(L"ytdlp_GetCopyright.txt");     SetRet(ret, L"\x00A9 2025 Example"); }
static void __stdcall PI_GetMinAppVersion(BSTR* ret, void*) { WriteMarker(L"ytdlp_GetMinAppVersion.txt"); SetRet(ret, L"5.0.2"); }

// AddRef на DM-интерфейс в PluginInit, Release в BeforeUnload — для фоновых потоков
static void __stdcall PI_PluginInit(void* self, void* dmInterface) {
    WriteMarker(L"ytdlp_PluginInit.txt");
    auto* o = (PlugInObj*)self;
    o->dm = dmInterface;
    if (o->dm) {
        auto* dm = reinterpret_cast<DMInterface*>(o->dm);
        if (dm->lpVtbl && dm->lpVtbl->AddRef) dm->lpVtbl->AddRef(o->dm);
    }

    o->pluginDir = DM_DoAction(o->dm, L"GetPluginDir", L"");
    for (auto& ch : o->pluginDir) if (ch == L'/') ch = L'\\';
    o->ytdlpPath = ReadIniYtDlp(o->pluginDir);

    std::wstring pn = DM_DoAction(o->dm, L"GetProgramName", L"");
    AppendTrace(pn.empty() ? L"[ProgName] FAIL" : L"[ProgName] " + pn);
}
static void __stdcall PI_PluginConfigure(void*, BSTR /*params*/) {
    WriteMarker(L"ytdlp_PluginConfigure.txt");
    MessageBoxW(nullptr, L"YTDLP plugin settings (stub)", L"ytdlp", MB_OK | MB_ICONINFORMATION);
}
static void __stdcall PI_BeforeUnload(void* self) {
    WriteMarker(L"ytdlp_BeforeUnload.txt");
    auto* o = (PlugInObj*)self;
    if (o->dm) {
        auto* dm = reinterpret_cast<DMInterface*>(o->dm);
        if (dm->lpVtbl && dm->lpVtbl->Release) dm->lpVtbl->Release(o->dm);
        o->dm = nullptr;
    }
}

// ---------- Worker (фоновая задача) ----------
struct TaskCtx {
    PlugInObj* o;
    std::wstring id;
    bool fromState;
};

static DWORD WINAPI WorkerProc(LPVOID param) {
    std::unique_ptr<TaskCtx> ctx(reinterpret_cast<TaskCtx*>(param));
    PlugInObj* o = ctx->o;
    if (!o || !o->dm) return 0;

    // держим плагин живым на время
    InterlockedIncrement(&o->ref);

    AppendTrace(L"[Worker] start id=" + ctx->id + (ctx->fromState ? L" [state]" : L" [added]"));

    // 1) получить info
    std::wstring info = DM_DoAction(o->dm, L"GetDownloadInfoByID", ctx->id);
    AppendTrace(L"[Worker] info_len=" + std::to_wstring(info.size()));
    if (info.empty()) {
        AppendTrace(L"[Worker] no info");
        InterlockedDecrement(&o->ref);
        return 0;
    }

    // 2) достать URL
    std::wstring url = ExtractTag(info, L"url");
    if (url.empty()) {
        AppendTrace(L"[Worker] no url");
        InterlockedDecrement(&o->ref);
        return 0;
    }

    // 3) yt-dlp -e (title)
    std::wstring app = o->ytdlpPath.empty() ? L"yt-dlp.exe" : o->ytdlpPath;
    std::wstring args = L"-e --no-warnings -- \"" + url + L"\"";
    std::string out; DWORD ec = 0;
    bool ok = RunProcessCapture(app, args, out, ec);
    if (!ok || ec != 0 || out.empty()) {
        AppendTrace(L"[Worker] yt-dlp failed code=" + std::to_wstring(ec));
        InterlockedDecrement(&o->ref);
        return 0;
    }
    while (!out.empty() && (out.back()=='\r' || out.back()=='\n')) out.pop_back();
    std::wstring title = Utf8ToW(out);
    AppendTrace(L"[Worker] title=\"" + title + L"\"");
    if (title.empty()) {
        InterlockedDecrement(&o->ref);
        return 0;
    }

    // 4) поставить описание
    std::wstring patch = L"<id>" + ctx->id + L"</id><description>" + XmlEscape(title) + L" [yt-dlp]</description>";
    std::wstring setRes = DM_DoAction(o->dm, L"SetDownloadInfoByID", patch);
    AppendTrace(L"[Worker] set_desc_len=" + std::to_wstring(setRes.size()));

    // 5) в лог DM
    std::wstring logmsg = ctx->fromState ? L"[ytdlp] title set (state)" : L"[ytdlp] title set";
    std::wstring logxml = L"<id>" + ctx->id + L"</id><type>2</type><logstring>" + XmlEscape(logmsg) + L"</logstring>";
    DM_DoAction(o->dm, L"AddStringToLog", logxml);

    InterlockedDecrement(&o->ref);
    return 0;
}

static void StartWorker(PlugInObj* o, const std::wstring& id, bool fromState) {
    auto* ctx = new TaskCtx{ o, id, fromState };
    HANDLE h = CreateThread(nullptr, 0, WorkerProc, ctx, 0, nullptr);
    if (h) CloseHandle(h);
    else {
        AppendTrace(L"[Worker] CreateThread FAIL");
        delete ctx;
    }
}

// События (без таймеров)
static void __stdcall PI_EventRaised(BSTR* ret, void* self, BSTR eventType, BSTR eventData) {
    if (ret) *ret = SysAllocString(L"");
    auto* o = (PlugInObj*)self;
    if (!o || !o->dm) return;

    std::wstring et = BSTRtoW(eventType);
    std::wstring ed = BSTRtoW(eventData);

    // Не пишем таймеры в trace
    if (et.rfind(L"dm_timer_", 0) != 0) {
        AppendTrace(L"[Event] " + et + L" | " + ed);
    }

    auto getIdStr = [&](const std::wstring& s)->std::wstring {
        int id = 0;
        if (!ParseLeadingInt(s, id)) return L"";
        return std::to_wstring(id);
    };

    if (et.find(L"dm_download_added") != std::wstring::npos) {
        std::wstring id = getIdStr(ed);
        if (id.empty()) { AppendTrace(L"[Added] ParseID FAIL"); return; }
        AppendTrace(L"[Added] id=" + id);
        StartWorker(o, id, false);
        return;
    }

    if (et.find(L"dm_download_state") != std::wstring::npos) {
        int id = 0, state = 0;
        {
            const wchar_t* p = ed.c_str(); wchar_t* end = nullptr;
            long v1 = wcstol(p, &end, 10);
            if (p == end) { AppendTrace(L"[State] ParseID FAIL"); return; }
            id = (int)v1;
            if (*end) {
                const wchar_t* p2 = end;
                long v2 = wcstol(p2, nullptr, 10);
                state = (int)v2;
            }
        }
        AppendTrace(L"[State] id=" + std::to_wstring(id) + L" state=" + std::to_wstring(state));
        if (id > 0 && state == 3) {
            StartWorker(o, std::to_wstring(id), true);
        }
        return;
    }
}

// vtable
static PlugInVtbl g_vtbl = {
    PI_QI, PI_AddRef, PI_Release,
    PI_getID, PI_GetName, PI_GetVersion, PI_GetDescription,
    PI_GetEmail, PI_GetHomepage, PI_GetCopyright,
    PI_GetMinAppVersion, PI_PluginInit, PI_PluginConfigure,
    PI_BeforeUnload, PI_EventRaised
};

// RegisterPlugIn с out-параметром
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
