#include <windows.h>
#include <oleauto.h>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>

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

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

// json unescape (\uXXXX, базовые \n\t\r"\KATEX_INLINE_CLOSE
static int HexVal(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
    if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
    return -1;
}
static std::wstring JsonUnescape(const std::wstring& s) {
    std::wstring out; out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t c = s[i];
        if (c != L'\\') { out += c; continue; }
        if (i + 1 >= s.size()) { out += c; break; }
        wchar_t n = s[++i];
        switch (n) {
            case L'"':  out += L'"';  break;
            case L'\\': out += L'\\'; break;
            case L'/':  out += L'/';  break;
            case L'b':  out += L'\b'; break;
            case L'f':  out += L'\f'; break;
            case L'n':  out += L'\n'; break;
            case L'r':  out += L'\r'; break;
            case L't':  out += L'\t'; break;
            case L'u': {
                if (i + 4 >= s.size()) { out += L'?'; break; }
                int h1 = HexVal(s[i+1]), h2 = HexVal(s[i+2]), h3 = HexVal(s[i+3]), h4 = HexVal(s[i+4]);
                if (h1<0||h2<0||h3<0||h4<0) { out += L'?'; break; }
                wchar_t w = (wchar_t)((h1<<12)|(h2<<8)|(h3<<4)|h4);
                i += 4;
                // суррогаты
                if (w >= 0xD800 && w <= 0xDBFF) {
                    if (i + 6 < s.size() && s[i+1] == L'\\' && s[i+2] == L'u') {
                        int h5=HexVal(s[i+3]), h6=HexVal(s[i+4]), h7=HexVal(s[i+5]), h8=HexVal(s[i+6]);
                        wchar_t w2 = (wchar_t)((h5<<12)|(h6<<8)|(h7<<4)|h8);
                        if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                            out += w; out += w2; i += 6; break;
                        }
                    }
                }
                out += w;
                break;
            }
            default: out += n; break;
        }
    }
    return out;
}

static bool IsVideoSite(const std::wstring& url) {
    std::wstring u = ToLower(url);
    return (u.find(L"youtube.com/") != std::wstring::npos) ||
           (u.find(L"youtu.be/")   != std::wstring::npos) ||
           (u.find(L"vimeo.com/")  != std::wstring::npos) ||
           (u.find(L"vk.com/")     != std::wstring::npos && u.find(L"/video") != std::wstring::npos) ||
           (u.find(L"vkvideo.ru/") != std::wstring::npos) ||
           (u.find(L"rutube.ru/")  != std::wstring::npos) ||
           (u.find(L"dailymotion.")!= std::wstring::npos);
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
    std::wstring pLog = p.substr(0, 512);
    AppendTrace(L"[DoAction] action=\"" + a + L"\" params=\"" + pLog + L"\"");
    BSTR ret=nullptr, ba=SysAllocStringLen(a.data(), (UINT)a.size()), bp=SysAllocStringLen(p.data(), (UINT)p.size());
    dm->lpVtbl->DoAction(&ret, pDm, ba, bp);
    if (ba) SysFreeString(ba); if (bp) SysFreeString(bp);
    std::wstring w = BSTRtoW(ret);
    if (ret) SysFreeString(ret);
    AppendTrace(L"[DoActionResult] action=\"" + a + L"\" result_len=" + std::to_wstring(w.size()));
    return w;
}

// ---------- запуск внешнего процесса ----------
static bool RunProcessCapture(const std::wstring& app, const std::wstring& args, std::string& outUtf8, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE r=NULL,w=NULL; if (!CreatePipe(&r,&w,&sa,0)) return false;
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    std::wstring cmd=L"\""+app+L"\" "+args;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(L'\0');
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE; si.hStdOutput=w; si.hStdError=w;
    PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    AppendTrace(L"[RunApp] " + cmd + (ok ? L" (OK)" : L" (FAIL)"));
    CloseHandle(w); if(!ok){ CloseHandle(r); return false; }
    char tmp[4096]; DWORD rd=0; outUtf8.clear();
    while (ReadFile(r,tmp,sizeof(tmp),&rd,nullptr) && rd>0) outUtf8.append(tmp,tmp+rd);
    CloseHandle(r);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    AppendTrace(L"[RunAppExit] code=" + std::to_wstring(exitCode));
    return true;
}
static bool RunProcessDetached(const std::wstring& app, const std::wstring& args) {
    std::wstring cmd=L"\""+app+L"\" "+args;
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    AppendTrace(L"[RunDetached] " + cmd + (ok ? L" (OK)" : L" (FAIL)"));
    if (ok) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
    return ok == TRUE;
}
static std::wstring Utf8ToW(const std::string& s){
    if(s.empty()) return L"";
    int n=MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0);
    std::wstring w(n,L'\0'); MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),&w[0],n);
    return w;
}
static std::wstring ReadIniYtDlp(const std::wstring& dir){
    if(dir.empty()) return L"yt-dlp.exe";
    std::wstring ini=PathJoin(dir,L"ytdlp.ini");
    DWORD attr=GetFileAttributesW(ini.c_str());
    if(attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_DIRECTORY)){
        wchar_t buf[1024]={0}; DWORD n=GetPrivateProfileStringW(L"ytdlp",L"path",L"",buf,1024,ini.c_str());
        if(n>0) return std::wstring(buf,n);
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
};

static DWORD WINAPI WorkerProc(LPVOID param) {
    std::unique_ptr<TaskCtx> ctx(reinterpret_cast<TaskCtx*>(param));
    PlugInObj* o = ctx->o;
    if (!o || !o->dm) return 0;

    InterlockedIncrement(&o->ref);
    AppendTrace(L"[Worker] start id=" + ctx->id);

    // 1) info
    std::wstring info = DM_DoAction(o->dm, L"GetDownloadInfoByID", ctx->id);
    AppendTrace(L"[Worker] info_len=" + std::to_wstring(info.size()));
    if (info.empty()) { AppendTrace(L"[Worker] no info"); InterlockedDecrement(&o->ref); return 0; }

    // 2) url, savepath, filename
    std::wstring url = ExtractTag(info, L"url");
    std::wstring savepath = ExtractTag(info, L"savepath");
    std::wstring filename = ExtractTag(info, L"filename");
    if (url.empty()) { AppendTrace(L"[Worker] no url"); InterlockedDecrement(&o->ref); return 0; }

    // 3) title из JSON
    std::wstring app = o->ytdlpPath.empty() ? L"yt-dlp.exe" : o->ytdlpPath;
    std::wstring argsJ = L"-J --no-warnings --dump-single-json -- \"" + url + L"\"";
    std::string outJ; DWORD ecJ = 0;
    bool okJ = RunProcessCapture(app, argsJ, outJ, ecJ);
    std::wstring title;
    if (okJ && ecJ==0 && !outJ.empty()) {
        std::wstring json = Utf8ToW(outJ);
        size_t k = json.find(L"\"title\"");
        if (k != std::wstring::npos) {
            k = json.find(L":", k);
            if (k != std::wstring::npos) {
                size_t q1 = json.find(L"\"", k + 1);
                size_t q2 = (q1 != std::wstring::npos) ? json.find(L"\"", q1 + 1) : std::wstring::npos;
                if (q1 != std::wstring::npos && q2 != std::wstring::npos && q2 > q1) {
                    title = json.substr(q1 + 1, q2 - q1 - 1);
                }
            }
        }
        title = JsonUnescape(title);
    }
    AppendTrace(L"[Worker] title=\"" + title + L"\"");

    // 4) попробуем получить прямой URL (прогрессивный) — одна строка
    std::wstring argsG = L"-g -f \"best[acodec!=none][vcodec!=none][protocol!=m3u8][protocol!=http_dash_segments]/best\" --no-warnings -- \"" + url + L"\"";
    std::string outG; DWORD ecG=0;
    bool okG = RunProcessCapture(app, argsG, outG, ecG);
    AppendTrace(L"[Worker] -g exit=" + std::to_wstring(ecG) + L" bytes=" + std::to_wstring(outG.size()));

    std::wstring directUrl;
    if (okG && ecG==0 && !outG.empty()) {
        // split by lines
        size_t pos=0; int lines=0;
        std::wstring lastLine;
        while (pos < outG.size()) {
            size_t nl = outG.find('\n', pos);
            std::string line = outG.substr(pos, (nl==std::string::npos? outG.size():nl)-pos);
            // trim \r
            if (!line.empty() && line.back()=='\r') line.pop_back();
            if (!line.empty()) { ++lines; lastLine = Utf8ToW(line); }
            if (nl==std::string::npos) break;
            pos = nl+1;
        }
        if (lines == 1) directUrl = lastLine;
        AppendTrace(L"[Worker] lines=" + std::to_wstring(lines) + L" direct=" + (directUrl.empty()?L"NO":L"YES"));
    }

    // 5) если есть direct — подменим URL и рестартуем DM
    if (!directUrl.empty()) {
        // referer — исходный url, часто нужен
        std::wstring patch = L"<id>" + ctx->id + L"</id>"
                             L"<url>" + XmlEscape(directUrl) + L"</url>"
                             L"<referer>" + XmlEscape(url) + L"</referer>"
                             L"<description>" + XmlEscape(title.empty()?L"[yt-dlp]":title + L" [yt-dlp]") + L"</description>";
        DM_DoAction(o->dm, L"SetDownloadInfoByID", patch);
        AppendTrace(L"[Worker] direct url set, restarting DM");
        DM_DoAction(o->dm, L"StartDownloads", ctx->id);
        InterlockedDecrement(&o->ref);
        return 0;
    }

    // 6) иначе — делегируем внешнему yt-dlp (не ждём). Ставим описание.
    if (!savepath.empty() && !filename.empty()) {
        // Правим недопустимые символы в имени (на всякий)
        auto sanitize = [](std::wstring s){
            for (auto& ch: s) {
                if (ch==L'<'||ch==L'>'||ch==L':'||ch==L'"'||ch==L'/'||ch==L'\\'||ch==L'|'||ch==L'?'||ch==L'*')
                    ch=L'_';
            }
            return s;
        };
        std::wstring outBase = PathJoin(savepath, sanitize(filename));
        // Пусть yt-dlp сам добавит расширение по формату
        std::wstring argsDl = L"-f best --merge-output-format mp4 --no-warnings --no-progress -o \"" + outBase + L".%(ext)s\" -- \"" + url + L"\"";
        RunProcessDetached(app, argsDl);
        // Обновим описание
        std::wstring desc = title.empty()? L"[yt-dlp] external" : title + L" [yt-dlp] (external)";
        std::wstring patchDesc = L"<id>" + ctx->id + L"</id><description>" + XmlEscape(desc) + L"</description>";
        DM_DoAction(o->dm, L"SetDownloadInfoByID", patchDesc);
        AppendTrace(L"[Worker] external yt-dlp launched");
    } else {
        AppendTrace(L"[Worker] no savepath/filename for external dl");
    }

    InterlockedDecrement(&o->ref);
    return 0;
}

static void StartWorker(PlugInObj* o, const std::wstring& id) {
    auto* ctx = new TaskCtx{ o, id };
    HANDLE h = CreateThread(nullptr, 0, WorkerProc, ctx, 0, nullptr);
    if (h) CloseHandle(h);
    else { AppendTrace(L"[Worker] CreateThread FAIL"); delete ctx; }
}

// ---------- События ----------
static void __stdcall PI_EventRaised(BSTR* ret, void* self, BSTR eventType, BSTR eventData) {
    if (ret) *ret = SysAllocString(L"");
    auto* o = (PlugInObj*)self;
    if (!o || !o->dm) return;

    std::wstring et = BSTRtoW(eventType);
    std::wstring ed = BSTRtoW(eventData);

    if (et.rfind(L"dm_timer_", 0) != 0) { // не пишем таймеры
        AppendTrace(L"[Event] " + et + L" | " + ed);
    }

    // dm_download_state: "ID STATE"
    if (et.find(L"dm_download_state") != std::wstring::npos) {
        int id = 0, state = 0;
        {
            const wchar_t* p = ed.c_str(); wchar_t* end = nullptr;
            long v1 = wcstol(p, &end, 10);
            if (p == end) return;
            id = (int)v1;
            if (*end) {
                const wchar_t* p2 = end;
                long v2 = wcstol(p2, nullptr, 10);
                state = (int)v2;
            }
        }
        if (id <= 0) return;
        std::wstring sid = std::to_wstring(id);
        AppendTrace(L"[State] id=" + sid + L" state=" + std::to_wstring(state));

        if (state == 3) {
            // Пропускаем не-видео: читаем info и смотрим URL
            std::wstring info = DM_DoAction(o->dm, L"GetDownloadInfoByID", sid);
            std::wstring url  = ExtractTag(info, L"url");
            if (url.empty() || !IsVideoSite(url)) {
                AppendTrace(L"[State3] skip non-video");
                return;
            }
            // Если уже проставили ранее
            if (info.find(L"[yt-dlp]") != std::wstring::npos) {
                AppendTrace(L"[State3] already processed");
                return;
            }

            // Стоп DM, запустить воркер, пусть подменит URL или делегирует
            DM_DoAction(o->dm, L"StopDownloads", sid);
            AppendTrace(L"[State3] StopDownloads sent; start worker");
            StartWorker(o, sid);
            return;
        }
    }

    // dm_download_added — информативно
    if (et.find(L"dm_download_added") != std::wstring::npos) {
        AppendTrace(L"[Added] raw=" + ed);
        return;
    }
}

// vtable
struct PlugInVtbl;
static HRESULT __stdcall PI_QI(void*, REFIID, void**);
static ULONG   __stdcall PI_AddRef(void*);
static ULONG   __stdcall PI_Release(void*);
static void    __stdcall PI_getID(BSTR*,void*);
static void    __stdcall PI_GetName(BSTR*,void*);
static void    __stdcall PI_GetVersion(BSTR*,void*);
static void    __stdcall PI_GetDescription(BSTR*,void*,BSTR);
static void    __stdcall PI_GetEmail(BSTR*,void*);
static void    __stdcall PI_GetHomepage(BSTR*,void*);
static void    __stdcall PI_GetCopyright(BSTR*,void*);
static void    __stdcall PI_GetMinAppVersion(BSTR*,void*);
static void    __stdcall PI_PluginInit(void*,void*);
static void    __stdcall PI_PluginConfigure(void*,BSTR);
static void    __stdcall PI_BeforeUnload(void*);
static void    __stdcall PI_EventRaised(BSTR*,void*,BSTR,BSTR);

struct PlugInVtbl {
    HRESULT (__stdcall* QueryInterface)(void*, REFIID, void**);
    ULONG   (__stdcall* AddRef)(void*);
    ULONG   (__stdcall* Release)(void*);
    void    (__stdcall* getID)(BSTR* ret, void* self);
    void    (__stdcall* GetName)(BSTR* ret, void* self);
    void    (__stdcall* GetVersion)(BSTR* ret, void* self);
    void    (__stdcall* GetDescription)(BSTR* ret, void* self, BSTR language);
    void    (__stdcall* GetEmail)(BSTR* ret, void* self);
    void    (__stdcall* GetHomepage)(BSTR* ret, void* self);
    void    (__stdcall* GetCopyright)(BSTR* ret, void* self);
    void    (__stdcall* GetMinAppVersion)(BSTR* ret, void* self);
    void    (__stdcall* PluginInit)(void* self, void* dmInterface);
    void    (__stdcall* PluginConfigure)(void* self, BSTR params);
    void    (__stdcall* BeforeUnload)(void* self);
    void    (__stdcall* EventRaised)(BSTR* ret, void* self, BSTR eventType, BSTR eventData);
};

struct PlugInObj {
    PlugInVtbl* lpVtbl;
    volatile LONG ref;
    void* dm;
    std::wstring pluginDir;
    std::wstring ytdlpPath;
};

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
