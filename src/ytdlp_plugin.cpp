// ytdlp_plugin.cpp
// Build: MSVC x86, /MT. Link: oleaut32.lib
// Place ytdlp.dll into Download Master\Plugins\

#include <windows.h>
#include <oleauto.h>
#include <string>
#include <sstream>
#include <vector>
#include <memory>

#pragma comment(lib, "oleaut32.lib")
#pragma comment(linker, "/export:RegisterPlugIn=_RegisterPlugIn@0")
// GUIDs из DMPluginIntf.pas
struct __declspec(uuid("B412B405-0578-4B99-BB06-368CDA0B2F8C")) IDMInterface : public IUnknown {
    virtual BSTR __stdcall DoAction(BSTR action, BSTR parameters) = 0;
};

struct __declspec(uuid("959CD0D3-83FD-40F7-A75A-E5C6500B58DF")) IDMPlugIn : public IUnknown {
    virtual BSTR __stdcall getID() = 0;
    virtual BSTR __stdcall GetName() = 0;
    virtual BSTR __stdcall GetVersion() = 0;
    virtual BSTR __stdcall GetDescription(BSTR language) = 0;
    virtual BSTR __stdcall GetEmail() = 0;
    virtual BSTR __stdcall GetHomepage() = 0;
    virtual BSTR __stdcall GetCopyright() = 0;
    virtual BSTR __stdcall GetMinAppVersion() = 0;
    virtual void __stdcall PluginInit(IDMInterface* dm) = 0;
    virtual void __stdcall PluginConfigure(BSTR params) = 0;
    virtual void __stdcall BeforeUnload() = 0;
    virtual BSTR __stdcall EventRaised(BSTR eventType, BSTR eventData) = 0;
};

static inline BSTR ToBSTR(const std::wstring& s) { return SysAllocStringLen(s.data(), (UINT)s.size()); }
static inline std::wstring FromBSTR(BSTR b)      { return b ? std::wstring(b, SysStringLen(b)) : L""; }

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
static std::wstring ExtractXmlField(const std::wstring& xml, const std::wstring& tag) {
    std::wstring open = L"<" + tag + L">";
    std::wstring close = L"</" + tag + L">";
    size_t i = xml.find(open);
    if (i == std::wstring::npos) return L"";
    i += open.size();
    size_t j = xml.find(close, i);
    if (j == std::wstring::npos) return L"";
    return xml.substr(i, j - i);
}
static std::wstring Utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static std::wstring PathJoin(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}
static bool RunProcessCapture(const std::wstring& app, const std::wstring& args, std::string& outUtf8, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE r = NULL, w = NULL;
    if (!CreatePipe(&r, &w, &sa, 0)) return false;
    if (!SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0)) { CloseHandle(r); CloseHandle(w); return false; }

    std::wstring cmd = L"\"" + app + L"\" " + args;
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = w; si.hStdError = w;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(w);
    if (!ok) { CloseHandle(r); return false; }

    char buf[4096]; DWORD read = 0; outUtf8.clear();
    while (ReadFile(r, buf, sizeof(buf), &read, nullptr) && read > 0) outUtf8.append(buf, buf + read);
    CloseHandle(r);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return true;
}

class Plugin final : public IDMPlugIn {
public:
    Plugin() : m_ref(1), m_dm(nullptr) {}

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDMPlugIn)) {
            *ppv = static_cast<IDMPlugIn*>(this);
            AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG __stdcall AddRef() override { return (ULONG)InterlockedIncrement(&m_ref); }
    ULONG __stdcall Release() override {
        ULONG r = (ULONG)InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }

    // Info
    BSTR __stdcall getID() override             { return ToBSTR(L"{F1E5C3A0-8C33-4D4C-8DE0-6B5ACF0F31C5}"); }
    BSTR __stdcall GetName() override           { return ToBSTR(L"ytdlp plugin"); }
    BSTR __stdcall GetVersion() override        { return ToBSTR(L"0.1.0"); }
    BSTR __stdcall GetDescription(BSTR lang) override {
        std::wstring l = FromBSTR(lang);
        if (!_wcsicmp(l.c_str(), L"russian") || !_wcsicmp(l.c_str(), L"ukrainian") || !_wcsicmp(l.c_str(), L"belarusian"))
            return ToBSTR(L"Плагин: пробует yt-dlp -J и заполняет описание.");
        return ToBSTR(L"Plugin: runs yt-dlp -J and fills description.");
    }
    BSTR __stdcall GetEmail() override          { return ToBSTR(L"dev@example.com"); }
    BSTR __stdcall GetHomepage() override       { return ToBSTR(L"https://example.com"); }
    BSTR __stdcall GetCopyright() override      { return ToBSTR(L"\x00A9 2025 Example"); }
    BSTR __stdcall GetMinAppVersion() override  { return ToBSTR(L"5.0.2"); }

    // Lifecycle
    void __stdcall PluginInit(IDMInterface* dm) override {
        OutputDebugStringW(L"[ytdlp] PluginInit\n");
        if (m_dm) { m_dm->Release(); m_dm = nullptr; }
        m_dm = dm; if (m_dm) m_dm->AddRef();

        m_pluginDir = DoActionW(L"GetPluginDir", L"");
        for (auto& ch : m_pluginDir) if (ch == L'/') ch = L'\\';
    }
    void __stdcall PluginConfigure(BSTR /*params*/) override {
        // TODO
    }
    void __stdcall BeforeUnload() override {
        OutputDebugStringW(L"[ytdlp] BeforeUnload\n");
        if (m_dm) { m_dm->Release(); m_dm = nullptr; }
    }

    BSTR __stdcall EventRaised(BSTR eventType, BSTR eventData) override {
        std::wstring et = FromBSTR(eventType);
        std::wstring ed = FromBSTR(eventData);

        if (et == L"dm_download_added") {
            const std::wstring id = ed;
            const std::wstring info = DoActionW(L"GetDownloadInfoByID", id);
            const std::wstring url  = ExtractXmlField(info, L"url");

            if (!url.empty()) {
                struct Ctx { Plugin* self; std::wstring id, url; };
                auto* ctx = new Ctx{ this, id, url };
                AddRef();

                HANDLE h = CreateThread(nullptr, 0,
                    [](LPVOID p)->DWORD {
                        std::unique_ptr<Ctx> ctx((Ctx*)p);
                        Plugin* self = ctx->self;

                        const std::wstring ytdlpPath = self->GetYtDlpPath();
                        std::wstring args = L"-J --no-warnings --dump-single-json -- \"" + ctx->url + L"\"";

                        std::string outUtf8; DWORD code = 0;
                        bool ok = RunProcessCapture(ytdlpPath, args, outUtf8, code);

                        std::wstring title;
                        if (ok && code == 0 && !outUtf8.empty()) {
                            std::wstring jsonW = Utf8ToW(outUtf8);
                            size_t k = jsonW.find(L"\"title\"");
                            if (k != std::wstring::npos) {
                                k = jsonW.find(L":", k);
                                if (k != std::wstring::npos) {
                                    size_t q1 = jsonW.find(L"\"", k + 1);
                                    size_t q2 = (q1 != std::wstring::npos) ? jsonW.find(L"\"", q1 + 1) : std::wstring::npos;
                                    if (q1 != std::wstring::npos && q2 != std::wstring::npos && q2 > q1)
                                        title = jsonW.substr(q1 + 1, q2 - q1 - 1);
                                }
                            }
                        }

                        if (!title.empty()) {
                            const std::wstring patch = L"<id>" + ctx->id + L"</id><description>" + XmlEscape(title) + L" [yt-dlp]</description>";
                            self->DoActionW(L"SetDownloadInfoByID", patch);
                            self->DoActionW(L"AddStringToLog", L"<id>"+ctx->id+L"</id><type>2</type><logstring>[ytdlp] title set</logstring>");
                        } else {
                            self->DoActionW(L"AddStringToLog", L"<id>"+ctx->id+L"</id><type>3</type><logstring>[ytdlp] probe failed</logstring>");
                        }

                        self->Release();
                        return 0;
                    },
                    ctx, 0, nullptr);

                if (h) CloseHandle(h);
                else Release();
            }
        }

        return ToBSTR(L"");
    }

private:
    ~Plugin() { if (m_dm) { m_dm->Release(); m_dm = nullptr; } }

    std::wstring DoActionW(const std::wstring& action, const std::wstring& params) const {
        if (!m_dm) return L"";
        BSTR a = ToBSTR(action), p = ToBSTR(params);
        BSTR r = m_dm->DoAction(a, p);
        SysFreeString(a); SysFreeString(p);
        std::wstring s = FromBSTR(r);
        if (r) SysFreeString(r);
        return s;
    }
    std::wstring GetYtDlpPath() const {
        if (!m_pluginDir.empty()) {
            const std::wstring ini = PathJoin(m_pluginDir, L"ytdlp.ini");
            DWORD attrs = GetFileAttributesW(ini.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                wchar_t buf[1024] = {0};
                DWORD n = GetPrivateProfileStringW(L"ytdlp", L"path", L"", buf, 1024, ini.c_str());
                if (n > 0) return std::wstring(buf, n);
            }
        }
        return L"yt-dlp.exe";
    }

private:
    volatile LONG m_ref;
    IDMInterface* m_dm;
    std::wstring  m_pluginDir;
};
static HMODULE g_hModule = nullptr;

static void WriteMarker(LPCWSTR name) {
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
extern "C" __declspec(dllexport) IDMPlugIn* __stdcall RegisterPlugIn() {
    OutputDebugStringW(L"[ytdlp] RegisterPlugIn called\n");
    WriteMarker(L"ytdlp_RegisterPlugIn_called.txt");
    try {
        return new Plugin();
    } catch (...) {
        return nullptr;
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = h;
        OutputDebugStringW(L"[ytdlp] DllMain attach\n");
    }
    return TRUE;
}
