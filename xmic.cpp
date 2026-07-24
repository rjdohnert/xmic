#define _WIN32_DCOM
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <utility>
#include <set>
#include <map>
#include <cwctype>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <windows.h>
#include <mi.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "mi.lib")

// --- Helper Data Structures & Configs ---

struct WmiSecurityConfig {
    LONG authnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    LONG impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
};

enum class TransportMode {
    DcomRpc,
    WinRm
};

enum class WinRmBackendMode {
    PowerShell,
    Native
};

struct WmiTargetConfig {
    std::wstring node = L".";
    std::wstring user;
    std::wstring password;
    std::wstring domain;
    std::wstring wmiNamespace = L"ROOT\\CIMV2";
    TransportMode transport = TransportMode::DcomRpc;
    WinRmBackendMode winrmBackend = WinRmBackendMode::PowerShell;
};

enum class OutputFormat {
    Table,
    Csv,
    Json
};

enum class ConsoleEncoding {
    Utf16,
    Utf8
};

struct OutputOptions {
    OutputFormat format = OutputFormat::Table;
    bool noHeader = false;
    std::wstring outputFile;
};

enum ExitCode {
    EXIT_OK = 0,
    EXIT_BAD_ARGS = 2,
    EXIT_UNKNOWN_COMMAND = 3,
    EXIT_WMI_FAILURE = 4,
    EXIT_NO_DATA = 5
};

OutputOptions g_outputOptions;
bool g_lastNoData = false;

bool TryParseTransportMode(const std::wstring& input, TransportMode& mode) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"dcom" || value == L"rpc" || value == L"dcom-rpc") {
        mode = TransportMode::DcomRpc;
        return true;
    }

    if (value == L"winrm" || value == L"wsman" || value == L"ws-management") {
        mode = TransportMode::WinRm;
        return true;
    }

    return false;
}

bool TryParseWinRmBackendMode(const std::wstring& input, WinRmBackendMode& mode) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"powershell" || value == L"ps") {
        mode = WinRmBackendMode::PowerShell;
        return true;
    }

    if (value == L"native" || value == L"wwsapi" || value == L"cpp") {
        mode = WinRmBackendMode::Native;
        return true;
    }

    return false;
}

bool TryParseConsoleEncoding(const std::wstring& input, ConsoleEncoding& encoding) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"utf16" || value == L"utf-16") {
        encoding = ConsoleEncoding::Utf16;
        return true;
    }

    if (value == L"utf8" || value == L"utf-8") {
        encoding = ConsoleEncoding::Utf8;
        return true;
    }

    return false;
}

bool ConfigureConsoleOutputMode(ConsoleEncoding encoding) {
    if (encoding == ConsoleEncoding::Utf8) {
        if (!SetConsoleOutputCP(CP_UTF8)) {
            return false;
        }
        SetConsoleCP(CP_UTF8);
        if (_setmode(_fileno(stdout), _O_U8TEXT) == -1) {
            return false;
        }
        if (_setmode(_fileno(stderr), _O_U8TEXT) == -1) {
            return false;
        }
        return true;
    }

    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        return false;
    }
    if (_setmode(_fileno(stderr), _O_U16TEXT) == -1) {
        return false;
    }
    return true;
}

bool ReadHiddenConsoleLine(const std::wstring& prompt, std::wstring& value, std::wstring& error) {
    value.clear();
    error.clear();

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput == NULL || hInput == INVALID_HANDLE_VALUE) {
        error = L"No interactive console input handle is available.";
        return false;
    }

    DWORD originalMode = 0;
    if (!GetConsoleMode(hInput, &originalMode)) {
        error = L"Interactive password prompt requires an attached console input.";
        return false;
    }

    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOutput != NULL && hOutput != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteConsoleW(hOutput, prompt.c_str(), static_cast<DWORD>(prompt.size()), &written, NULL);
    } else {
        std::wcout << prompt;
    }

    DWORD hiddenMode = originalMode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hInput, hiddenMode)) {
        error = L"Failed to disable console input echo for password entry.";
        return false;
    }

    wchar_t buffer[512] = {};
    DWORD charsRead = 0;
    BOOL readOk = ReadConsoleW(hInput, buffer, 511, &charsRead, NULL);

    SetConsoleMode(hInput, originalMode);

    if (hOutput != NULL && hOutput != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteConsoleW(hOutput, L"\n", 1, &written, NULL);
    } else {
        std::wcout << L"\n";
    }

    if (!readOk) {
        SecureZeroMemory(buffer, sizeof(buffer));
        error = L"Failed to read password from console.";
        return false;
    }

    while (charsRead > 0 && (buffer[charsRead - 1] == L'\n' || buffer[charsRead - 1] == L'\r')) {
        --charsRead;
    }

    value.assign(buffer, charsRead);
    SecureZeroMemory(buffer, sizeof(buffer));
    return true;
}

// --- RAII Output Redirection ---

class StdoutRedirector {
private:
    std::wofstream fileStream;
    std::wstreambuf* oldBuffer;

public:
    StdoutRedirector() : oldBuffer(nullptr) {}

    bool RedirectToFile(const std::wstring& filePath) {
        fileStream.open(filePath, std::ios::out | std::ios::trunc);
        if (!fileStream.is_open()) return false;
        
        fileStream.imbue(std::locale(""));
        oldBuffer = std::wcout.rdbuf();
        std::wcout.rdbuf(fileStream.rdbuf());
        return true;
    }

    ~StdoutRedirector() {
        if (oldBuffer) {
            std::wcout.rdbuf(oldBuffer);
        }
        if (fileStream.is_open()) {
            fileStream.close();
        }
    }
};

// --- Process Privilege Elevation ---

bool EnableTokenPrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    }

    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

void EnableCommonPrivileges() {
    EnableTokenPrivilege(L"SeDebugPrivilege");
    EnableTokenPrivilege(L"SeShutdownPrivilege");
    EnableTokenPrivilege(L"SeRemoteShutdownPrivilege");
    EnableTokenPrivilege(L"SeSecurityPrivilege");
    EnableTokenPrivilege(L"SeSystemtimePrivilege");
}

// --- Connection Helper with Remote Auth Support ---

bool ConnectWmiServices(
    const WmiTargetConfig& target,
    const std::wstring& defaultNamespace,
    const WmiSecurityConfig& securityConfig,
    const std::wstring& wmiLocale,
    IWbemServices** ppSvc
) {
    *ppSvc = NULL;
    IWbemLocator* pLoc = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    std::wstring targetNs = defaultNamespace.empty() ? L"ROOT\\CIMV2" : defaultNamespace;
    std::wstring fullPath = (target.node == L"." || target.node.empty())
        ? targetNs
        : (L"\\\\" + target.node + L"\\" + targetNs);

    _bstr_t bstrPath(fullPath.c_str());
    _bstr_t bstrUser(target.user.empty() ? NULL : target.user.c_str());
    _bstr_t bstrPass(target.password.empty() ? NULL : target.password.c_str());
    _bstr_t bstrLocale(wmiLocale.empty() ? NULL : wmiLocale.c_str());

    hr = pLoc->ConnectServer(bstrPath, bstrUser, bstrPass, bstrLocale, 0, 0, 0, ppSvc);
    pLoc->Release();

    if (FAILED(hr) || !*ppSvc) return false;

    SEC_WINNT_AUTH_IDENTITY_W authIdent = { 0 };
    SEC_WINNT_AUTH_IDENTITY_W* pAuthIdent = NULL;

    if (!target.user.empty()) {
        authIdent.User = (RPC_WSTR)target.user.c_str();
        authIdent.UserLength = (ULONG)target.user.length();
        authIdent.Password = (RPC_WSTR)target.password.c_str();
        authIdent.PasswordLength = (ULONG)target.password.length();
        authIdent.Domain = (RPC_WSTR)target.domain.c_str();
        authIdent.DomainLength = (ULONG)target.domain.length();
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        pAuthIdent = &authIdent;
    }

    CoSetProxyBlanket(
        *ppSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        pAuthIdent,
        EOAC_NONE
    );

    return true;
}

// --- Original Helper Functions ---

std::wstring FormatBytes(unsigned long long bytes) {
    if (bytes == 0) return L"N/A";
    double gb = static_cast<double>(bytes) / (1024 * 1024 * 1024);
    wchar_t buf[32];
    if (gb >= 1.0) {
        swprintf_s(buf, L"%.2f GB", gb);
        return buf;
    }
    double mb = static_cast<double>(bytes) / (1024 * 1024);
    swprintf_s(buf, L"%.2f MB", mb);
    return buf;
}

std::wstring VariantToString(VARIANT& vtProp) {
    if (V_VT(&vtProp) == VT_EMPTY || V_VT(&vtProp) == VT_NULL) return L"N/A";
    if (V_VT(&vtProp) == VT_BSTR && V_BSTR(&vtProp) != NULL) return std::wstring(V_BSTR(&vtProp));
    if (V_VT(&vtProp) == VT_I4) return std::to_wstring(V_I4(&vtProp));
    if (V_VT(&vtProp) == VT_UI4) return std::to_wstring(V_UI4(&vtProp));
    if (V_VT(&vtProp) == VT_UI8) return std::to_wstring(V_UI8(&vtProp));
    if (V_VT(&vtProp) == VT_I8) return std::to_wstring(V_I8(&vtProp));
    if (V_VT(&vtProp) == VT_BOOL) return (V_BOOL(&vtProp) ? L"True" : L"False");

    // Handle SafeArray of Strings (e.g., Network IPAddresses)
    if ((V_VT(&vtProp) & VT_ARRAY) && (V_VT(&vtProp) & VT_BSTR)) {
        SAFEARRAY* psa = V_ARRAY(&vtProp);
        BSTR* bstrData;
        std::wstring result = L"";
        if (SUCCEEDED(SafeArrayAccessData(psa, (void**)&bstrData))) {
            long lBound, uBound;
            SafeArrayGetLBound(psa, 1, &lBound);
            SafeArrayGetUBound(psa, 1, &uBound);
            
            std::vector<std::wstring> items;
            for (long i = lBound; i <= uBound; ++i) {
                if (bstrData[i] != NULL) {
                    std::wstring str = bstrData[i];
                    if (!str.empty()) items.push_back(str);
                }
            }
            SafeArrayUnaccessData(psa);

            // Put IPv4 before IPv6 addresses for cleaner network outputs
            std::stable_sort(items.begin(), items.end(), [](const std::wstring& a, const std::wstring& b) {
                bool a_has_colon = (a.find(L':') != std::wstring::npos);
                bool b_has_colon = (b.find(L':') != std::wstring::npos);
                return !a_has_colon && b_has_colon;
            });

            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) result += L", ";
                result += items[i];
            }
            return result.empty() ? L"N/A" : result;
        }
    }

    // Generic conversion attempt
    VARIANT dest;
    VariantInit(&dest);
    if (SUCCEEDED(VariantChangeType(&dest, &vtProp, 0, VT_BSTR))) {
        std::wstring str(V_BSTR(&dest) ? V_BSTR(&dest) : L"");
        VariantClear(&dest);
        return str;
    }
    return L"<Data>";
}

std::wstring FormatWmiDateTime(const std::wstring& wmiDateTime) {
    if (wmiDateTime.length() < 14) return wmiDateTime;

    std::wstring year = wmiDateTime.substr(0, 4);
    std::wstring month = wmiDateTime.substr(4, 2);
    std::wstring day = wmiDateTime.substr(6, 2);
    std::wstring hour = wmiDateTime.substr(8, 2);
    std::wstring minute = wmiDateTime.substr(10, 2);
    std::wstring second = wmiDateTime.substr(12, 2);

    return year + L"-" + month + L"-" + day + L" " + hour + L":" + minute + L":" + second;
}

std::wstring EscapeJson(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size() + 8);

    for (wchar_t ch : input) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'\"': out += L"\\\""; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch >= 0 && ch <= 0x1F) {
                wchar_t buf[7];
                swprintf_s(buf, L"\\u%04X", static_cast<unsigned int>(ch));
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }

    return out;
}

std::wstring EscapeCsv(const std::wstring& input) {
    bool needsQuotes = false;
    std::wstring normalized;
    normalized.reserve(input.size() + 8);

    for (wchar_t ch : input) {
        if (ch >= 0 && ch <= 0x1F) {
            wchar_t buf[5];
            swprintf_s(buf, L"\\x%02X", static_cast<unsigned int>(ch));
            normalized += buf;
            needsQuotes = true;
        } else {
            if (ch == L',' || ch == L'\"' || ch == L'\n' || ch == L'\r') {
                needsQuotes = true;
            }
            normalized += ch;
        }
    }

    if (!needsQuotes) return normalized;

    std::wstring out = L"\"";
    for (wchar_t ch : normalized) {
        if (ch == L'\"') out += L"\"\"";
        else out += ch;
    }
    out += L"\"";
    return out;
}

std::wstring EscapePowerShellSingleQuoted(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size() + 8);
    for (wchar_t ch : input) {
        if (ch == L'\'') {
            out += L"''";
        } else {
            out += ch;
        }
    }
    return out;
}

bool RunPowerShellCommandCapture(const std::wstring& script, std::wstring& output, int& exitCode) {
    std::wstring command = L"powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + script + L"\"";
    FILE* pipe = _wpopen(command.c_str(), L"rt");
    if (!pipe) {
        exitCode = -1;
        return false;
    }

    output.clear();
    wchar_t buffer[1024];
    while (fgetws(buffer, static_cast<int>(sizeof(buffer) / sizeof(wchar_t)), pipe) != NULL) {
        output += buffer;
    }

    int status = _pclose(pipe);
    exitCode = status;
    return true;
}

class IWinRmBackend {
public:
    virtual ~IWinRmBackend() {}

    virtual bool ExecuteQuery(
        const WmiTargetConfig& target,
        const std::wstring& wqlQuery,
        const std::vector<std::wstring>& properties,
        const OutputOptions& outputOptions,
        std::wstring& output,
        bool& noData,
        std::wstring& error
    ) const = 0;

    virtual bool ExecuteMethodCall(
        const WmiTargetConfig& target,
        const std::wstring& classNameOrPath,
        const std::wstring& methodName,
        const std::map<std::wstring, std::wstring>& inputArgs,
        std::wstring& output,
        std::wstring& error
    ) const = 0;
};

class WinRmPowerShellBackend final : public IWinRmBackend {
private:
    static std::wstring BuildSessionBlock(const WmiTargetConfig& target) {
        std::wstring block;
        block += L"$opts=@{};";
        if (!(target.node.empty() || target.node == L".")) {
            block += L"$opts.ComputerName='" + EscapePowerShellSingleQuoted(target.node) + L"';";
        }
        if (!target.user.empty()) {
            block += L"$sec=ConvertTo-SecureString '" + EscapePowerShellSingleQuoted(target.password) + L"' -AsPlainText -Force;";
            block += L"$usr='" + EscapePowerShellSingleQuoted(target.user) + L"';";
            if (!target.domain.empty()) {
                block += L"$usr='" + EscapePowerShellSingleQuoted(target.domain) + L"\\" + EscapePowerShellSingleQuoted(target.user) + L"';";
            }
            block += L"$opts.Credential=New-Object System.Management.Automation.PSCredential($usr,$sec);";
        }
        if (!target.wmiNamespace.empty()) {
            block += L"$opts.Namespace='" + EscapePowerShellSingleQuoted(target.wmiNamespace) + L"';";
        }
        return block;
    }

public:
    bool ExecuteQuery(
        const WmiTargetConfig& target,
        const std::wstring& wqlQuery,
        const std::vector<std::wstring>& properties,
        const OutputOptions& outputOptions,
        std::wstring& output,
        bool& noData,
        std::wstring& error
    ) const override {
        auto buildSelectList = [&]() -> std::wstring {
            if (properties.empty()) {
                return L"*";
            }
            std::wstring list;
            for (size_t i = 0; i < properties.size(); ++i) {
                if (i > 0) list += L",";
                list += L"'" + EscapePowerShellSingleQuoted(properties[i]) + L"'";
            }
            return list;
        };

        std::wstring script = BuildSessionBlock(target);
        script += L"$rows=Get-CimInstance @opts -Query '" + EscapePowerShellSingleQuoted(wqlQuery) + L"'";
        script += L"| Select-Object -Property " + buildSelectList() + L";";
        script += L"if($null -eq $rows){$rows=@();}";

        if (outputOptions.format == OutputFormat::Json) {
            script += L"$rows | ConvertTo-Json -Depth 6 -Compress";
        } else if (outputOptions.format == OutputFormat::Csv) {
            script += L"$csv=$rows | ConvertTo-Csv -NoTypeInformation;";
            if (outputOptions.noHeader) {
                script += L"if($csv.Count -gt 1){$csv = $csv[1..($csv.Count-1)]}else{$csv=@()};";
            }
            script += L"$csv";
        } else {
            script += L"$rows | Format-Table -AutoSize";
        }

        int code = -1;
        if (!RunPowerShellCommandCapture(script, output, code) || code != 0) {
            error = L"WinRM PowerShell query backend failed.";
            return false;
        }

        noData = output.empty() || output.find_first_not_of(L" \t\r\n") == std::wstring::npos;
        return true;
    }

    bool ExecuteMethodCall(
        const WmiTargetConfig& target,
        const std::wstring& classNameOrPath,
        const std::wstring& methodName,
        const std::map<std::wstring, std::wstring>& inputArgs,
        std::wstring& output,
        std::wstring& error
    ) const override {
        std::wstring argScript = L"$argMap=@{};";
        for (const auto& kv : inputArgs) {
            argScript += L"$argMap['" + EscapePowerShellSingleQuoted(kv.first) + L"']='" + EscapePowerShellSingleQuoted(kv.second) + L"';";
        }

        std::wstring script = BuildSessionBlock(target);
        script += argScript;
        script += L"$r=Invoke-CimMethod @opts -ClassName '" + EscapePowerShellSingleQuoted(classNameOrPath) + L"' -MethodName '" + EscapePowerShellSingleQuoted(methodName) + L"' -Arguments $argMap;";
        script += L"if($null -ne $r -and $null -ne $r.ReturnValue){'ReturnValue=' + $r.ReturnValue}else{'Method Executed Successfully'}";

        int code = -1;
        if (!RunPowerShellCommandCapture(script, output, code) || code != 0) {
            error = L"WinRM PowerShell method backend failed.";
            return false;
        }

        return true;
    }
};

class WinRmNativeBackendStub final : public IWinRmBackend {
private:
    static std::vector<std::wstring> SplitCsvLikeValues(const std::wstring& input) {
        std::vector<std::wstring> parts;
        std::wstringstream ss(input);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            size_t start = 0;
            while (start < item.size() && iswspace(item[start])) ++start;
            size_t end = item.size();
            while (end > start && iswspace(item[end - 1])) --end;
            std::wstring trimmed = item.substr(start, end - start);
            if (!trimmed.empty()) parts.push_back(trimmed);
        }
        return parts;
    }

    static std::wstring FormatMiDateTime(const MI_Datetime& dt) {
        if (dt.isTimestamp) {
            const MI_Timestamp& ts = dt.u.timestamp;
            wchar_t buf[64];
            swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u", ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second);
            return std::wstring(buf);
        }

        const MI_Interval& iv = dt.u.interval;
        return std::to_wstring(iv.days) + L"d " +
               std::to_wstring(iv.hours) + L"h " +
               std::to_wstring(iv.minutes) + L"m " +
               std::to_wstring(iv.seconds) + L"s";
    }

    static std::wstring JoinArrayItems(const std::vector<std::wstring>& items) {
        std::wstring out;
        for (size_t i = 0; i < items.size(); ++i) {
            if (i > 0) out += L", ";
            out += items[i];
        }
        return out.empty() ? L"N/A" : out;
    }

    static std::wstring MiValueToString(const MI_Value& value, MI_Type type, MI_Uint32 flags) {
        if (flags & MI_FLAG_NULL) {
            return L"N/A";
        }

        switch (type) {
        case MI_STRING:
            return value.string ? std::wstring(value.string) : L"N/A";
        case MI_BOOLEAN:
            return value.boolean ? L"True" : L"False";
        case MI_UINT8:
            return std::to_wstring(value.uint8);
        case MI_SINT8:
            return std::to_wstring(value.sint8);
        case MI_UINT16:
            return std::to_wstring(value.uint16);
        case MI_SINT16:
            return std::to_wstring(value.sint16);
        case MI_UINT32:
            return std::to_wstring(value.uint32);
        case MI_SINT32:
            return std::to_wstring(value.sint32);
        case MI_UINT64:
            return std::to_wstring(value.uint64);
        case MI_SINT64:
            return std::to_wstring(value.sint64);
        case MI_REAL32:
            return std::to_wstring(value.real32);
        case MI_REAL64:
            return std::to_wstring(value.real64);
        case MI_CHAR16:
            return std::wstring(1, static_cast<wchar_t>(value.char16));
        case MI_DATETIME:
            return FormatMiDateTime(value.datetime);
        case MI_REFERENCE:
            return L"<Reference>";
        case MI_INSTANCE:
            return L"<Instance>";
        case MI_STRINGA: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.stringa.size; ++i) {
                items.push_back(value.stringa.data[i] ? std::wstring(value.stringa.data[i]) : L"");
            }
            return JoinArrayItems(items);
        }
        case MI_UINT32A: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.uint32a.size; ++i) items.push_back(std::to_wstring(value.uint32a.data[i]));
            return JoinArrayItems(items);
        }
        case MI_SINT32A: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.sint32a.size; ++i) items.push_back(std::to_wstring(value.sint32a.data[i]));
            return JoinArrayItems(items);
        }
        case MI_UINT64A: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.uint64a.size; ++i) items.push_back(std::to_wstring(value.uint64a.data[i]));
            return JoinArrayItems(items);
        }
        case MI_SINT64A: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.sint64a.size; ++i) items.push_back(std::to_wstring(value.sint64a.data[i]));
            return JoinArrayItems(items);
        }
        case MI_BOOLEANA: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.booleana.size; ++i) items.push_back(value.booleana.data[i] ? L"True" : L"False");
            return JoinArrayItems(items);
        }
        case MI_DATETIMEA: {
            std::vector<std::wstring> items;
            for (MI_Uint32 i = 0; i < value.datetimea.size; ++i) items.push_back(FormatMiDateTime(value.datetimea.data[i]));
            return JoinArrayItems(items);
        }
        default:
            return L"<Data>";
        }
    }

    static std::wstring BuildOutputString(
        const std::vector<std::wstring>& headers,
        const std::vector<std::vector<std::wstring>>& rows,
        const OutputOptions& outputOptions
    ) {
        std::wstringstream out;

        if (outputOptions.format == OutputFormat::Csv) {
            if (!outputOptions.noHeader) {
                for (size_t i = 0; i < headers.size(); ++i) {
                    if (i > 0) out << L",";
                    out << EscapeCsv(headers[i]);
                }
                out << L"\n";
            }
            for (const auto& row : rows) {
                for (size_t i = 0; i < headers.size(); ++i) {
                    if (i > 0) out << L",";
                    std::wstring cell = (i < row.size()) ? row[i] : L"";
                    out << EscapeCsv(cell);
                }
                out << L"\n";
            }
            return out.str();
        }

        if (outputOptions.format == OutputFormat::Json) {
            out << L"[";
            for (size_t r = 0; r < rows.size(); ++r) {
                if (r > 0) out << L",";
                out << L"{";
                for (size_t c = 0; c < headers.size(); ++c) {
                    if (c > 0) out << L",";
                    std::wstring key = EscapeJson(headers[c]);
                    std::wstring val = (c < rows[r].size()) ? EscapeJson(rows[r][c]) : L"";
                    out << L"\"" << key << L"\":\"" << val << L"\"";
                }
                out << L"}";
            }
            out << L"]\n";
            return out.str();
        }

        std::vector<size_t> widths(headers.size(), 0);
        for (size_t i = 0; i < headers.size(); ++i) widths[i] = headers[i].size();
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
                widths[i] = (std::max)(widths[i], row[i].size());
            }
        }

        out << L"\n";
        if (!outputOptions.noHeader) {
            for (size_t i = 0; i < headers.size(); ++i) {
                out << std::left << std::setw(static_cast<int>(widths[i] + 3)) << headers[i];
            }
            out << L"\n";
            size_t totalWidth = 0;
            for (size_t w : widths) totalWidth += w + 3;
            out << std::wstring(totalWidth, L'-') << L"\n";
        }

        for (const auto& row : rows) {
            for (size_t i = 0; i < headers.size(); ++i) {
                std::wstring cell = (i < row.size()) ? row[i] : L"";
                out << std::left << std::setw(static_cast<int>(widths[i] + 3)) << cell;
            }
            out << L"\n";
        }
        out << L"\n";
        return out.str();
    }

public:
    bool ExecuteQuery(
        const WmiTargetConfig& target,
        const std::wstring& wqlQuery,
        const std::vector<std::wstring>& properties,
        const OutputOptions& outputOptions,
        std::wstring& output,
        bool& noData,
        std::wstring& error
    ) const override {
        MI_Application application = MI_APPLICATION_NULL;
        MI_DestinationOptions destinationOptions = MI_DESTINATIONOPTIONS_NULL;
        MI_Session session = MI_SESSION_NULL;
        MI_Operation operation = MI_OPERATION_NULL;
        MI_Instance* extendedError = NULL;

        auto closeAll = [&]() {
            if (operation.ft) {
                MI_Operation_Close(&operation);
            }
            if (session.ft) {
                MI_Session_Close(&session, NULL, NULL);
            }
            if (destinationOptions.ft) {
                MI_DestinationOptions_Delete(&destinationOptions);
            }
            if (application.ft) {
                MI_Application_Close(&application);
            }
            if (extendedError) {
                MI_Instance_Delete(extendedError);
                extendedError = NULL;
            }
        };

        MI_Result miResult = MI_Application_Initialize(0, NULL, &extendedError, &application);
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_Initialize failed.";
            closeAll();
            return false;
        }

        miResult = MI_Application_NewDestinationOptions(&application, &destinationOptions);
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_NewDestinationOptions failed.";
            closeAll();
            return false;
        }

        if (!target.user.empty()) {
            MI_UserCredentials creds;
            memset(&creds, 0, sizeof(creds));
            creds.authenticationType = MI_AUTH_TYPE_NEGO_WITH_CREDS;
            creds.credentials.usernamePassword.domain = target.domain.empty() ? NULL : target.domain.c_str();
            creds.credentials.usernamePassword.username = target.user.c_str();
            creds.credentials.usernamePassword.password = target.password.c_str();
            miResult = MI_DestinationOptions_AddDestinationCredentials(&destinationOptions, &creds);
            if (miResult != MI_RESULT_OK) {
                error = L"MI_DestinationOptions_AddDestinationCredentials failed.";
                closeAll();
                return false;
            }
        }

        const MI_Char* destination = (target.node.empty() || target.node == L".") ? NULL : target.node.c_str();
        miResult = MI_Application_NewSession(
            &application,
            MI_T("WINRM"),
            destination,
            &destinationOptions,
            NULL,
            &extendedError,
            &session
        );
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_NewSession failed.";
            closeAll();
            return false;
        }

        MI_Session_QueryInstances(
            &session,
            0,
            NULL,
            target.wmiNamespace.c_str(),
            MI_T("WQL"),
            wqlQuery.c_str(),
            NULL,
            &operation
        );

        std::vector<std::wstring> headers = properties;
        std::vector<std::vector<std::wstring>> rows;

        for (;;) {
            const MI_Instance* instance = NULL;
            MI_Boolean moreResults = MI_FALSE;
            MI_Result operationResult = MI_RESULT_OK;
            const MI_Char* errorMessage = NULL;
            const MI_Instance* completionDetails = NULL;

            miResult = MI_Operation_GetInstance(
                &operation,
                &instance,
                &moreResults,
                &operationResult,
                &errorMessage,
                &completionDetails
            );

            if (miResult != MI_RESULT_OK) {
                error = L"MI_Operation_GetInstance failed.";
                closeAll();
                return false;
            }

            if (instance) {
                if (headers.empty()) {
                    MI_Uint32 count = 0;
                    if (MI_Instance_GetElementCount(instance, &count) == MI_RESULT_OK) {
                        for (MI_Uint32 i = 0; i < count; ++i) {
                            const MI_Char* name = NULL;
                            if (MI_Instance_GetElementAt(instance, i, &name, NULL, NULL, NULL) == MI_RESULT_OK && name) {
                                headers.push_back(name);
                            }
                        }
                    }
                }

                std::vector<std::wstring> row;
                for (const auto& prop : headers) {
                    MI_Value value;
                    memset(&value, 0, sizeof(value));
                    MI_Type type = MI_STRING;
                    MI_Uint32 flags = 0;
                    if (MI_Instance_GetElement(instance, prop.c_str(), &value, &type, &flags, NULL) == MI_RESULT_OK) {
                        row.push_back(MiValueToString(value, type, flags));
                    } else {
                        row.push_back(L"N/A");
                    }
                }
                rows.push_back(row);
            }

            if (!moreResults) {
                if (operationResult != MI_RESULT_OK) {
                    error = errorMessage ? std::wstring(errorMessage) : L"MI query operation failed.";
                    closeAll();
                    return false;
                }
                break;
            }
        }

        noData = rows.empty();
        output = noData ? L"" : BuildOutputString(headers, rows, outputOptions);
        closeAll();
        return true;
    }

    bool ExecuteMethodCall(
        const WmiTargetConfig& target,
        const std::wstring& classNameOrPath,
        const std::wstring& methodName,
        const std::map<std::wstring, std::wstring>& inputArgs,
        std::wstring& output,
        std::wstring& error
    ) const override {
        MI_Application application = MI_APPLICATION_NULL;
        MI_DestinationOptions destinationOptions = MI_DESTINATIONOPTIONS_NULL;
        MI_Session session = MI_SESSION_NULL;
        MI_Operation classOperation = MI_OPERATION_NULL;
        MI_Operation invokeOperation = MI_OPERATION_NULL;
        MI_Instance* extendedError = NULL;
        MI_Instance* invokeInputParams = NULL;

        auto closeAll = [&]() {
            if (invokeOperation.ft) {
                MI_Operation_Close(&invokeOperation);
            }
            if (classOperation.ft) {
                MI_Operation_Close(&classOperation);
            }
            if (invokeInputParams) {
                MI_Instance_Delete(invokeInputParams);
                invokeInputParams = NULL;
            }
            if (session.ft) {
                MI_Session_Close(&session, NULL, NULL);
            }
            if (destinationOptions.ft) {
                MI_DestinationOptions_Delete(&destinationOptions);
            }
            if (application.ft) {
                MI_Application_Close(&application);
            }
            if (extendedError) {
                MI_Instance_Delete(extendedError);
                extendedError = NULL;
            }
        };

        auto extractClassName = [](const std::wstring& raw) -> std::wstring {
            if (raw.find(L'=') != std::wstring::npos) {
                size_t dotPos = raw.find(L'.');
                if (dotPos != std::wstring::npos && dotPos > 0) {
                    return raw.substr(0, dotPos);
                }
            }
            return raw;
        };

        auto parseBoolean = [](const std::wstring& raw, MI_Boolean& out) -> bool {
            std::wstring lowered = raw;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(), towlower);
            if (lowered == L"true" || lowered == L"1") {
                out = MI_TRUE;
                return true;
            }
            if (lowered == L"false" || lowered == L"0") {
                out = MI_FALSE;
                return true;
            }
            return false;
        };

        auto isIntegerLiteral = [](const std::wstring& value) -> bool {
            if (value.empty()) return false;
            size_t start = 0;
            if (value[0] == L'+' || value[0] == L'-') {
                if (value.size() == 1) return false;
                start = 1;
            }
            for (size_t i = start; i < value.size(); ++i) {
                if (!iswdigit(value[i])) return false;
            }
            return true;
        };

        auto addTypedElement = [&](MI_Instance* targetInstance, const std::wstring& name, MI_Type declaredType, const std::wstring& rawValue, bool hasDeclaredType) -> bool {
            auto add = [&](const MI_Value& value, MI_Type type) -> bool {
                return MI_Instance_AddElement(targetInstance, name.c_str(), &value, type, 0) == MI_RESULT_OK;
            };

            auto addFallback = [&]() -> bool {
                if (isIntegerLiteral(rawValue)) {
                    try {
                        MI_Value value;
                        memset(&value, 0, sizeof(value));
                        value.sint64 = static_cast<MI_Sint64>(std::stoll(rawValue));
                        if (add(value, MI_SINT64)) {
                            return true;
                        }
                    } catch (...) {
                    }
                }

                MI_Boolean boolVal;
                if (parseBoolean(rawValue, boolVal)) {
                    MI_Value value;
                    memset(&value, 0, sizeof(value));
                    value.boolean = boolVal;
                    if (add(value, MI_BOOLEAN)) {
                        return true;
                    }
                }

                MI_Value value;
                memset(&value, 0, sizeof(value));
                value.string = const_cast<MI_Char*>(rawValue.c_str());
                return add(value, MI_STRING);
            };

            if (!hasDeclaredType) {
                return addFallback();
            }

            try {
                switch (declaredType) {
                case MI_SINT8: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint8 = static_cast<MI_Sint8>(std::stoi(rawValue));
                    return add(value, MI_SINT8);
                }
                case MI_UINT8: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint8 = static_cast<MI_Uint8>(std::stoul(rawValue));
                    return add(value, MI_UINT8);
                }
                case MI_SINT16: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint16 = static_cast<MI_Sint16>(std::stoi(rawValue));
                    return add(value, MI_SINT16);
                }
                case MI_UINT16: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint16 = static_cast<MI_Uint16>(std::stoul(rawValue));
                    return add(value, MI_UINT16);
                }
                case MI_SINT32: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint32 = static_cast<MI_Sint32>(std::stol(rawValue));
                    return add(value, MI_SINT32);
                }
                case MI_UINT32: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint32 = static_cast<MI_Uint32>(std::stoul(rawValue));
                    return add(value, MI_UINT32);
                }
                case MI_SINT64: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint64 = static_cast<MI_Sint64>(std::stoll(rawValue));
                    return add(value, MI_SINT64);
                }
                case MI_UINT64: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint64 = static_cast<MI_Uint64>(std::stoull(rawValue));
                    return add(value, MI_UINT64);
                }
                case MI_REAL32: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.real32 = static_cast<MI_Real32>(std::stof(rawValue));
                    return add(value, MI_REAL32);
                }
                case MI_REAL64: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.real64 = static_cast<MI_Real64>(std::stod(rawValue));
                    return add(value, MI_REAL64);
                }
                case MI_BOOLEAN: {
                    MI_Boolean boolVal;
                    if (!parseBoolean(rawValue, boolVal)) {
                        return false;
                    }
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.boolean = boolVal;
                    return add(value, MI_BOOLEAN);
                }
                case MI_CHAR16: {
                    if (rawValue.empty()) {
                        return false;
                    }
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.char16 = static_cast<MI_Char16>(rawValue[0]);
                    return add(value, MI_CHAR16);
                }
                case MI_STRING:
                case MI_REFERENCE:
                case MI_DATETIME: {
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.string = const_cast<MI_Char*>(rawValue.c_str());
                    return add(value, MI_STRING);
                }
                case MI_SINT32A: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Sint32> values;
                    values.reserve(items.size());
                    for (const auto& item : items) values.push_back(static_cast<MI_Sint32>(std::stol(item)));
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint32a.data = values.data(); value.sint32a.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_SINT32A);
                }
                case MI_UINT32A: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Uint32> values;
                    values.reserve(items.size());
                    for (const auto& item : items) values.push_back(static_cast<MI_Uint32>(std::stoul(item)));
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint32a.data = values.data(); value.uint32a.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_UINT32A);
                }
                case MI_SINT64A: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Sint64> values;
                    values.reserve(items.size());
                    for (const auto& item : items) values.push_back(static_cast<MI_Sint64>(std::stoll(item)));
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.sint64a.data = values.data(); value.sint64a.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_SINT64A);
                }
                case MI_UINT64A: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Uint64> values;
                    values.reserve(items.size());
                    for (const auto& item : items) values.push_back(static_cast<MI_Uint64>(std::stoull(item)));
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.uint64a.data = values.data(); value.uint64a.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_UINT64A);
                }
                case MI_BOOLEANA: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Boolean> values;
                    values.reserve(items.size());
                    for (const auto& item : items) {
                        MI_Boolean boolVal;
                        if (!parseBoolean(item, boolVal)) {
                            return false;
                        }
                        values.push_back(boolVal);
                    }
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.booleana.data = values.data(); value.booleana.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_BOOLEANA);
                }
                case MI_STRINGA: {
                    std::vector<std::wstring> items = SplitCsvLikeValues(rawValue);
                    std::vector<MI_Char*> values;
                    values.reserve(items.size());
                    for (auto& item : items) values.push_back(const_cast<MI_Char*>(item.c_str()));
                    MI_Value value; memset(&value, 0, sizeof(value));
                    value.stringa.data = values.data(); value.stringa.size = static_cast<MI_Uint32>(values.size());
                    return !values.empty() && add(value, MI_STRINGA);
                }
                default:
                    return addFallback();
                }
            } catch (...) {
                return false;
            }
        };

        std::wstring className = extractClassName(classNameOrPath);

        MI_Result miResult = MI_Application_Initialize(0, NULL, &extendedError, &application);
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_Initialize failed.";
            closeAll();
            return false;
        }

        miResult = MI_Application_NewDestinationOptions(&application, &destinationOptions);
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_NewDestinationOptions failed.";
            closeAll();
            return false;
        }

        if (!target.user.empty()) {
            MI_UserCredentials creds;
            memset(&creds, 0, sizeof(creds));
            creds.authenticationType = MI_AUTH_TYPE_NEGO_WITH_CREDS;
            creds.credentials.usernamePassword.domain = target.domain.empty() ? NULL : target.domain.c_str();
            creds.credentials.usernamePassword.username = target.user.c_str();
            creds.credentials.usernamePassword.password = target.password.c_str();
            miResult = MI_DestinationOptions_AddDestinationCredentials(&destinationOptions, &creds);
            if (miResult != MI_RESULT_OK) {
                error = L"MI_DestinationOptions_AddDestinationCredentials failed.";
                closeAll();
                return false;
            }
        }

        const MI_Char* destination = (target.node.empty() || target.node == L".") ? NULL : target.node.c_str();
        miResult = MI_Application_NewSession(
            &application,
            MI_T("WINRM"),
            destination,
            &destinationOptions,
            NULL,
            &extendedError,
            &session
        );
        if (miResult != MI_RESULT_OK) {
            error = L"MI_Application_NewSession failed.";
            closeAll();
            return false;
        }

        std::map<std::wstring, MI_Type> methodParameterTypes;
        MI_Session_GetClass(
            &session,
            0,
            NULL,
            target.wmiNamespace.c_str(),
            className.c_str(),
            NULL,
            &classOperation
        );

        const MI_Class* methodClass = NULL;
        for (;;) {
            const MI_Class* classResult = NULL;
            MI_Boolean moreResults = MI_FALSE;
            MI_Result operationResult = MI_RESULT_OK;
            const MI_Char* errorMessage = NULL;
            const MI_Instance* completionDetails = NULL;

            miResult = MI_Operation_GetClass(
                &classOperation,
                &classResult,
                &moreResults,
                &operationResult,
                &errorMessage,
                &completionDetails
            );

            if (miResult != MI_RESULT_OK) {
                break;
            }

            if (classResult) {
                methodClass = classResult;
            }

            if (!moreResults) {
                break;
            }
        }

        if (methodClass) {
            MI_ParameterSet methodParams;
            memset(&methodParams, 0, sizeof(methodParams));
            miResult = MI_Class_GetMethod(methodClass, methodName.c_str(), NULL, &methodParams, NULL);
            if (miResult == MI_RESULT_OK) {
                MI_Uint32 count = 0;
                if (MI_ParameterSet_GetParameterCount(&methodParams, &count) == MI_RESULT_OK) {
                    for (MI_Uint32 i = 0; i < count; ++i) {
                        const MI_Char* paramName = NULL;
                        MI_Type paramType = MI_STRING;
                        if (MI_ParameterSet_GetParameterAt(&methodParams, i, &paramName, &paramType, NULL, NULL) == MI_RESULT_OK && paramName) {
                            methodParameterTypes[paramName] = paramType;
                        }
                    }
                }
            }
        }

        if (classOperation.ft) {
            MI_Operation_Close(&classOperation);
            memset(&classOperation, 0, sizeof(classOperation));
        }

        if (!inputArgs.empty()) {
            miResult = MI_Application_NewInstance(&application, className.c_str(), NULL, &invokeInputParams);
            if (miResult != MI_RESULT_OK || !invokeInputParams) {
                error = L"MI_Application_NewInstance failed for method parameters.";
                closeAll();
                return false;
            }

            for (const auto& kv : inputArgs) {
                auto it = methodParameterTypes.find(kv.first);
                bool hasType = (it != methodParameterTypes.end());
                MI_Type paramType = hasType ? it->second : MI_STRING;
                if (!addTypedElement(invokeInputParams, kv.first, paramType, kv.second, hasType)) {
                    error = L"Failed to convert method input parameter: " + kv.first;
                    closeAll();
                    return false;
                }
            }
        }

        MI_Session_Invoke(
            &session,
            0,
            NULL,
            target.wmiNamespace.c_str(),
            className.c_str(),
            methodName.c_str(),
            NULL,
            invokeInputParams,
            NULL,
            &invokeOperation
        );

        std::vector<std::pair<std::wstring, std::wstring>> outputPairs;
        for (;;) {
            const MI_Instance* instance = NULL;
            MI_Boolean moreResults = MI_FALSE;
            MI_Result operationResult = MI_RESULT_OK;
            const MI_Char* errorMessage = NULL;
            const MI_Instance* completionDetails = NULL;

            miResult = MI_Operation_GetInstance(
                &invokeOperation,
                &instance,
                &moreResults,
                &operationResult,
                &errorMessage,
                &completionDetails
            );

            if (miResult != MI_RESULT_OK) {
                error = L"MI_Operation_GetInstance failed during method invocation.";
                closeAll();
                return false;
            }

            if (instance) {
                MI_Uint32 count = 0;
                if (MI_Instance_GetElementCount(instance, &count) == MI_RESULT_OK) {
                    for (MI_Uint32 i = 0; i < count; ++i) {
                        const MI_Char* name = NULL;
                        MI_Value value;
                        memset(&value, 0, sizeof(value));
                        MI_Type type = MI_STRING;
                        MI_Uint32 flags = 0;
                        if (MI_Instance_GetElementAt(instance, i, &name, &value, &type, &flags) == MI_RESULT_OK && name) {
                            outputPairs.push_back({ name, MiValueToString(value, type, flags) });
                        }
                    }
                }
            }

            if (!moreResults) {
                if (operationResult != MI_RESULT_OK) {
                    error = errorMessage ? std::wstring(errorMessage) : L"MI invoke operation failed.";
                    closeAll();
                    return false;
                }
                break;
            }
        }

        output.clear();
        auto returnIt = std::find_if(outputPairs.begin(), outputPairs.end(), [](const std::pair<std::wstring, std::wstring>& kv) {
            return _wcsicmp(kv.first.c_str(), L"ReturnValue") == 0;
        });

        if (returnIt != outputPairs.end()) {
            output = L"ReturnValue=" + returnIt->second;
            for (const auto& kv : outputPairs) {
                if (_wcsicmp(kv.first.c_str(), L"ReturnValue") == 0) {
                    continue;
                }
                output += L"; " + kv.first + L"=" + kv.second;
            }
        } else {
            for (size_t i = 0; i < outputPairs.size(); ++i) {
                if (i > 0) output += L"; ";
                output += outputPairs[i].first + L"=" + outputPairs[i].second;
            }
        }

        closeAll();
        return true;
    }
};

const IWinRmBackend& GetWinRmBackend(WinRmBackendMode mode) {
    static WinRmPowerShellBackend powershellBackend;
    static WinRmNativeBackendStub nativeStubBackend;
    return (mode == WinRmBackendMode::Native)
        ? static_cast<const IWinRmBackend&>(nativeStubBackend)
        : static_cast<const IWinRmBackend&>(powershellBackend);
}

std::vector<std::wstring> SplitAndTrimCommaList(const std::wstring& input) {
    std::vector<std::wstring> parts;
    std::wstringstream ss(input);
    std::wstring item;

    while (std::getline(ss, item, L',')) {
        size_t start = 0;
        while (start < item.size() && iswspace(item[start])) {
            ++start;
        }

        size_t end = item.size();
        while (end > start && iswspace(item[end - 1])) {
            --end;
        }

        std::wstring trimmed = item.substr(start, end - start);
        if (!trimmed.empty()) {
            parts.push_back(trimmed);
        }
    }

    return parts;
}

std::wstring TrimMatchingQuotes(const std::wstring& input) {
    if (input.size() >= 2) {
        wchar_t first = input.front();
        wchar_t last = input.back();
        if ((first == L'"' && last == L'"') || (first == L'\'' && last == L'\'')) {
            return input.substr(1, input.size() - 2);
        }
    }
    return input;
}

bool ParseNamedCallArguments(int startIndex, int argc, wchar_t* argv[], std::map<std::wstring, std::wstring>& argsOut, std::wstring& errorOut) {
    argsOut.clear();
    std::wstring currentKey;

    for (int i = startIndex; i < argc; ++i) {
        std::wstring token = argv[i];
        size_t eqPos = token.find(L'=');

        if (eqPos != std::wstring::npos && eqPos > 0) {
            std::wstring key = token.substr(0, eqPos);
            std::wstring value = TrimMatchingQuotes(token.substr(eqPos + 1));
            argsOut[key] = value;
            currentKey = key;
            continue;
        }

        if (!currentKey.empty()) {
            argsOut[currentKey] += L" " + TrimMatchingQuotes(token);
            continue;
        }

        errorOut = L"Unexpected call argument fragment: " + token + L" (expected Name=Value)";
        return false;
    }

    return true;
}

std::wstring NormalizeForKey(const std::wstring& input) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);
    return value;
}

std::wstring BuildDeviceDedupKey(
    const std::wstring& name,
    const std::wstring& deviceClass,
    const std::wstring& manufacturer,
    const std::wstring& status
) {
    return NormalizeForKey(name) + L"\x1f" +
           NormalizeForKey(deviceClass) + L"\x1f" +
           NormalizeForKey(manufacturer) + L"\x1f" +
           NormalizeForKey(status);
}

struct Table {
    std::vector<std::wstring> headers;
    std::vector<std::vector<std::wstring>> rows;

    void Print() {
        if (headers.empty()) return;

        if (g_outputOptions.format == OutputFormat::Csv) {
            if (!g_outputOptions.noHeader) {
                for (size_t i = 0; i < headers.size(); ++i) {
                    if (i > 0) std::wcout << L",";
                    std::wcout << EscapeCsv(headers[i]);
                }
                std::wcout << L"\n";
            }

            for (const auto& row : rows) {
                for (size_t i = 0; i < headers.size(); ++i) {
                    if (i > 0) std::wcout << L",";
                    std::wstring cell = (i < row.size()) ? row[i] : L"";
                    std::wcout << EscapeCsv(cell);
                }
                std::wcout << L"\n";
            }
            std::wcout << std::flush;
            return;
        }

        if (g_outputOptions.format == OutputFormat::Json) {
            std::wcout << L"[";
            for (size_t r = 0; r < rows.size(); ++r) {
                if (r > 0) std::wcout << L",";
                std::wcout << L"{";
                for (size_t c = 0; c < headers.size(); ++c) {
                    if (c > 0) std::wcout << L",";
                    std::wstring key = EscapeJson(headers[c]);
                    std::wstring val = (c < rows[r].size()) ? EscapeJson(rows[r][c]) : L"";
                    std::wcout << L"\"" << key << L"\":\"" << val << L"\"";
                }
                std::wcout << L"}";
            }
            std::wcout << L"]\n";
            std::wcout << std::flush;
            return;
        }

        std::vector<size_t> widths(headers.size());
        for (size_t i = 0; i < headers.size(); ++i) {
            widths[i] = headers[i].length();
        }

        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
                widths[i] = (std::max)(widths[i], row[i].length());
            }
        }

        std::wcout << L"\n";
        if (!g_outputOptions.noHeader) {
            for (size_t i = 0; i < headers.size(); ++i) {
                std::wcout << std::left << std::setw(widths[i] + 3) << headers[i];
            }
            std::wcout << L"\n";

            size_t totalWidth = 0;
            for (size_t w : widths) totalWidth += w + 3;
            std::wcout << std::wstring(totalWidth, L'-') << L"\n";
        }

        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
                std::wcout << std::left << std::setw(widths[i] + 3) << row[i];
            }
            std::wcout << L"\n";
        }
        std::wcout << L"\n";
    }
};

std::wstring FormatSwitchState(const std::wstring& value) {
    if (value == L"True") return L"Enabled";
    if (value == L"False") return L"Disabled";
    return value;
}

struct InstalledAppRecord {
    std::wstring name;
    std::wstring version;
    std::wstring publisher;
};

struct CpuRecord {
    std::wstring name;
    std::wstring numberOfCores;
    std::wstring logicalProcessors;
    std::wstring maxClockMhz;
    std::wstring loadPercentage;
};

struct NetRecord {
    std::wstring adapter;
    std::wstring macAddress;
    std::wstring ipAddresses;
};

struct DeviceRecord {
    std::wstring name;
    std::wstring deviceClass;
    std::wstring manufacturer;
    std::wstring status;
};

bool TryParseWmiSecurity(const std::wstring& input, WmiSecurityConfig& config) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"default") { config.authnLevel = RPC_C_AUTHN_LEVEL_DEFAULT; return true; }
    if (value == L"connect") { config.authnLevel = RPC_C_AUTHN_LEVEL_CONNECT; return true; }
    if (value == L"call") { config.authnLevel = RPC_C_AUTHN_LEVEL_CALL; return true; }
    if (value == L"pkt") { config.authnLevel = RPC_C_AUTHN_LEVEL_PKT; return true; }
    if (value == L"pktprivacy") { config.authnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY; return true; }

    return false;
}

bool TryParseOutputFormat(const std::wstring& input, OutputFormat& format) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"table") { format = OutputFormat::Table; return true; }
    if (value == L"csv") { format = OutputFormat::Csv; return true; }
    if (value == L"json") { format = OutputFormat::Json; return true; }

    return false;
}

std::wstring MapLicenseStatusCode(const std::wstring& rawValue) {
    if (rawValue == L"0") return L"Unlicensed";
    if (rawValue == L"1") return L"Licensed";
    if (rawValue == L"2") return L"OOB Grace";
    if (rawValue == L"3") return L"OOT Grace";
    if (rawValue == L"4") return L"Non-Genuine Grace";
    if (rawValue == L"5") return L"Notification";
    if (rawValue == L"6") return L"Extended Grace";
    return rawValue;
}

std::wstring GetWindowsActivationStatus(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return L"N/A";
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return L"N/A";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (FAILED(hr) || uReturn == 0) {
        pEnumerator->Release();
        pSvc->Release();
        return L"N/A";
    }

    VARIANT vtStatus;
    VariantInit(&vtStatus);
    std::wstring status = L"N/A";
    if (SUCCEEDED(pclsObj->Get(L"LicenseStatus", 0, &vtStatus, 0, 0))) {
        status = MapLicenseStatusCode(VariantToString(vtStatus));
    }
    VariantClear(&vtStatus);

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();

    return status;
}

bool ExecuteOSInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Caption, Version, OSArchitecture, NumberOfUsers, InstallDate FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (FAILED(hr) || uReturn == 0) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        pEnumerator->Release();
        pSvc->Release();
        return false;
    }

    auto readProp = [&](const wchar_t* propName) -> std::wstring {
        VARIANT vtProp;
        VariantInit(&vtProp);
        std::wstring value = L"N/A";
        if (SUCCEEDED(pclsObj->Get(propName, 0, &vtProp, 0, 0))) {
            value = VariantToString(vtProp);
            if (std::wstring(propName) == L"InstallDate") {
                value = FormatWmiDateTime(value);
            }
        }
        VariantClear(&vtProp);
        return value;
    };

    std::wstring caption = readProp(L"Caption");
    std::wstring version = readProp(L"Version");
    std::wstring architecture = readProp(L"OSArchitecture");
    std::wstring numberOfUsers = readProp(L"NumberOfUsers");
    std::wstring installDate = readProp(L"InstallDate");
    std::wstring activationStatus = GetWindowsActivationStatus(target, wmiLocale, securityConfig);

    Table table;
    if (g_outputOptions.format == OutputFormat::Table) {
        table.headers = { L"Property", L"Value" };
        table.rows.push_back({ L"System", caption });
        table.rows.push_back({ L"Version", version });
        table.rows.push_back({ L"OS Architecture", architecture });
        table.rows.push_back({ L"Number of Users", numberOfUsers });
        table.rows.push_back({ L"Install Date", installDate });
        table.rows.push_back({ L"Activation Status", activationStatus });
    } else {
        table.headers = {
            L"Caption", L"Version", L"OS Architecture", L"Number of Users", L"Install Date", L"Activation Status"
        };
        table.rows.push_back({
            caption, version, architecture, numberOfUsers, installDate, activationStatus
        });
    }

    table.Print();

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();

    return true;
}

bool ExecuteSystemInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    auto querySingleRow = [&](const std::wstring& wqlQuery, const std::vector<std::wstring>& props, std::vector<std::wstring>& outValues) -> bool {
        IEnumWbemClassObject* pEnumerator = NULL;
        HRESULT qhr = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(wqlQuery.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(qhr)) return false;

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        qhr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(qhr) || uReturn == 0) {
            pEnumerator->Release();
            return false;
        }

        outValues.clear();
        for (const auto& prop : props) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            std::wstring val = L"N/A";
            if (SUCCEEDED(pclsObj->Get(prop.c_str(), 0, &vtProp, 0, 0))) {
                val = VariantToString(vtProp);
            }
            VariantClear(&vtProp);
            outValues.push_back(val);
        }

        pclsObj->Release();
        pEnumerator->Release();
        return true;
    };

    std::vector<std::wstring> computerValues;
    std::vector<std::wstring> biosValues;
    bool hasComputer = querySingleRow(
        L"SELECT Manufacturer, Model, SystemType FROM Win32_ComputerSystem",
        { L"Manufacturer", L"Model", L"SystemType" },
        computerValues
    );

    bool hasBios = querySingleRow(
        L"SELECT SMBIOSBIOSVersion, SerialNumber FROM Win32_BIOS",
        { L"SMBIOSBIOSVersion", L"SerialNumber" },
        biosValues
    );

    pSvc->Release();

    if (!hasComputer && !hasBios) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        return false;
    }

    std::wstring manufacturer = hasComputer && computerValues.size() > 0 ? computerValues[0] : L"N/A";
    std::wstring model = hasComputer && computerValues.size() > 1 ? computerValues[1] : L"N/A";
    std::wstring systemType = hasComputer && computerValues.size() > 2 ? computerValues[2] : L"N/A";
    std::wstring biosVersion = hasBios && biosValues.size() > 0 ? biosValues[0] : L"N/A";
    std::wstring serialNumber = hasBios && biosValues.size() > 1 ? biosValues[1] : L"N/A";

    Table table;
    if (g_outputOptions.format == OutputFormat::Table) {
        table.headers = { L"Property", L"Value" };
        table.rows.push_back({ L"Manufacturer", manufacturer });
        table.rows.push_back({ L"Model", model });
        table.rows.push_back({ L"System Type", systemType });
        table.rows.push_back({ L"BIOS Version", biosVersion });
        table.rows.push_back({ L"Serial Number", serialNumber });
    } else {
        table.headers = { L"Manufacturer", L"Model", L"System Type", L"BIOS Version", L"Serial Number" };
        table.rows.push_back({ manufacturer, model, systemType, biosVersion, serialNumber });
    }

    table.Print();
    return true;
}

bool ExecuteCpuInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, LoadPercentage FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    std::vector<CpuRecord> records;
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;

        auto readProp = [&](const wchar_t* propName) -> std::wstring {
            VARIANT vtProp;
            VariantInit(&vtProp);
            std::wstring value = L"N/A";
            if (SUCCEEDED(pclsObj->Get(propName, 0, &vtProp, 0, 0))) {
                value = VariantToString(vtProp);
            }
            VariantClear(&vtProp);
            return value;
        };

        CpuRecord rec;
        rec.name = readProp(L"Name");
        rec.numberOfCores = readProp(L"NumberOfCores");
        rec.logicalProcessors = readProp(L"NumberOfLogicalProcessors");
        rec.maxClockMhz = readProp(L"MaxClockSpeed");
        if (rec.maxClockMhz != L"N/A") rec.maxClockMhz += L" MHz";
        rec.loadPercentage = readProp(L"LoadPercentage");
        if (rec.loadPercentage != L"N/A") rec.loadPercentage += L"%";
        records.push_back(rec);

        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();

    if (records.empty()) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        return false;
    }

    Table table;
    if (g_outputOptions.format == OutputFormat::Table && records.size() == 1) {
        table.headers = { L"Property", L"Value" };
        table.rows.push_back({ L"CPU Name", records[0].name });
        table.rows.push_back({ L"Physical Cores", records[0].numberOfCores });
        table.rows.push_back({ L"Logical Processors", records[0].logicalProcessors });
        table.rows.push_back({ L"Max Clock", records[0].maxClockMhz });
        table.rows.push_back({ L"Current Load", records[0].loadPercentage });
    } else {
        table.headers = { L"CPU", L"Name", L"Physical Cores", L"Logical Processors", L"Max Clock", L"Load" };
        for (size_t i = 0; i < records.size(); ++i) {
            std::wstring cpuLabel = L"CPU " + std::to_wstring(i);
            table.rows.push_back({
                cpuLabel, records[i].name, records[i].numberOfCores, records[i].logicalProcessors, records[i].maxClockMhz, records[i].loadPercentage
            });
        }
    }

    table.Print();
    return true;
}

bool ExecuteNetInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    std::vector<NetRecord> records;
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;

        auto readProp = [&](const wchar_t* propName) -> std::wstring {
            VARIANT vtProp;
            VariantInit(&vtProp);
            std::wstring value = L"N/A";
            if (SUCCEEDED(pclsObj->Get(propName, 0, &vtProp, 0, 0))) {
                value = VariantToString(vtProp);
            }
            VariantClear(&vtProp);
            return value;
        };

        NetRecord rec;
        rec.adapter = readProp(L"Description");
        rec.macAddress = readProp(L"MACAddress");
        rec.ipAddresses = readProp(L"IPAddress");
        records.push_back(rec);

        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();

    if (records.empty()) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        return false;
    }

    Table table;
    if (g_outputOptions.format == OutputFormat::Table && records.size() == 1) {
        table.headers = { L"Property", L"Value" };
        table.rows.push_back({ L"Adapter", records[0].adapter });
        table.rows.push_back({ L"MAC Address", records[0].macAddress });

        std::vector<std::wstring> ipList = SplitAndTrimCommaList(records[0].ipAddresses);
        if (ipList.empty()) {
            table.rows.push_back({ L"IP Addresses", records[0].ipAddresses });
        } else {
            for (size_t i = 0; i < ipList.size(); ++i) {
                std::wstring label = (i == 0) ? L"IP Address" : L"";
                table.rows.push_back({ label, ipList[i] });
            }
        }
    } else {
        table.headers = { L"Adapter", L"MAC Address", L"IP Addresses" };
        for (const auto& rec : records) {
            table.rows.push_back({ rec.adapter, rec.macAddress, rec.ipAddresses });
        }
    }

    table.Print();
    return true;
}

bool ExecuteDevicesInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Name, PNPClass, Manufacturer, Status FROM Win32_PnPEntity"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    std::vector<DeviceRecord> records;
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;

        auto readProp = [&](const wchar_t* propName) -> std::wstring {
            VARIANT vtProp;
            VariantInit(&vtProp);
            std::wstring value = L"N/A";
            if (SUCCEEDED(pclsObj->Get(propName, 0, &vtProp, 0, 0))) {
                value = VariantToString(vtProp);
            }
            VariantClear(&vtProp);
            return value;
        };

        DeviceRecord rec;
        rec.name = readProp(L"Name");
        rec.deviceClass = readProp(L"PNPClass");
        rec.manufacturer = readProp(L"Manufacturer");
        rec.status = readProp(L"Status");
        records.push_back(rec);

        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();

    std::set<std::wstring> seen;
    std::vector<DeviceRecord> uniqueRecords;
    uniqueRecords.reserve(records.size());

    for (const auto& rec : records) {
        std::wstring key = BuildDeviceDedupKey(rec.name, rec.deviceClass, rec.manufacturer, rec.status);
        if (seen.insert(key).second) {
            uniqueRecords.push_back(rec);
        }
    }
    records.swap(uniqueRecords);

    if (records.empty()) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        return false;
    }

    if (g_outputOptions.format == OutputFormat::Table) {
        for (size_t i = 0; i < records.size(); ++i) {
            std::wcout << L"\nDevice " << (i + 1) << L":" << std::endl;
            Table detail;
            detail.headers = { L"Property", L"Value" };
            detail.rows.push_back({ L"Name", records[i].name });
            detail.rows.push_back({ L"Class", records[i].deviceClass });
            detail.rows.push_back({ L"Manufacturer", records[i].manufacturer });
            detail.rows.push_back({ L"Status", records[i].status });
            detail.Print();
        }
        return true;
    }

    Table table;
    table.headers = { L"Name", L"Class", L"Manufacturer", L"Status" };
    for (const auto& rec : records) {
        table.rows.push_back({ rec.name, rec.deviceClass, rec.manufacturer, rec.status });
    }
    table.Print();
    return true;
}

bool ExecuteThreadsInfoQuery(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Threads FROM Win32_PerfFormattedData_PerfOS_System"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (FAILED(hr) || uReturn == 0) {
        g_lastNoData = true;
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"  No data available.\n" << std::endl;
        }
        pEnumerator->Release();
        pSvc->Release();
        return false;
    }

    VARIANT vtThreads;
    VariantInit(&vtThreads);
    std::wstring threads = L"N/A";
    if (SUCCEEDED(pclsObj->Get(L"Threads", 0, &vtThreads, 0, 0))) {
        threads = VariantToString(vtThreads);
    }
    VariantClear(&vtThreads);

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();

    Table table;
    if (g_outputOptions.format == OutputFormat::Table) {
        table.headers = { L"Property", L"Value" };
        table.rows.push_back({ L"Running Threads", threads });
    } else {
        table.headers = { L"Running Threads" };
        table.rows.push_back({ threads });
    }

    table.Print();
    return true;
}

std::wstring HResultToHex(HRESULT hr) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << static_cast<unsigned long>(hr);
    return ss.str();
}

bool ProbeWmiSecurityLevel(const WmiTargetConfig& target, const WmiSecurityConfig& securityConfig, const std::wstring& wmiLocale, std::wstring& details) {
    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        details = L"ConnectServer/ProxyBlanket failed";
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Caption FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        details = L"WMI probe query failed (" + HResultToHex(hr) + L")";
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    bool available = SUCCEEDED(hr) && uReturn > 0;

    if (available) {
        details = L"Available";
        pclsObj->Release();
    } else {
        details = L"Probe returned no data (" + HResultToHex(hr) + L")";
    }

    pEnumerator->Release();
    pSvc->Release();

    return available;
}

void PrintWmiSecurityAvailability(const WmiTargetConfig& target, const std::wstring& wmiLocale) {
    std::vector<std::wstring> levels = { L"default", L"connect", L"call", L"pkt", L"pktprivacy" };

    Table table;
    table.headers = { L"Security Level", L"Status", L"Details" };

    for (const auto& level : levels) {
        WmiSecurityConfig cfg;
        TryParseWmiSecurity(level, cfg);

        std::wstring details;
        bool ok = ProbeWmiSecurityLevel(target, cfg, wmiLocale, details);
        table.rows.push_back({ level, ok ? L"Available" : L"Unavailable", details });
    }

    if (g_outputOptions.format == OutputFormat::Table) {
        std::wcout << L"\nWMI Security Capability Check:" << std::endl;
    }
    table.Print();
}

std::wstring ReadRegistryStringValue(IWbemServices* pSvc, IWbemClassObject* pRegClass, const std::wstring& subKey, const std::wstring& valueName) {
    IWbemClassObject* pInDef = NULL;
    HRESULT hr = pRegClass->GetMethod(L"GetStringValue", 0, &pInDef, NULL);
    if (FAILED(hr) || pInDef == NULL) return L"";

    IWbemClassObject* pInParams = NULL;
    hr = pInDef->SpawnInstance(0, &pInParams);
    pInDef->Release();
    if (FAILED(hr) || pInParams == NULL) return L"";

    VARIANT vt;
    VariantInit(&vt);

    V_VT(&vt) = VT_UI4;
    V_UI4(&vt) = 0x80000002; // HKEY_LOCAL_MACHINE
    pInParams->Put(L"hDefKey", 0, &vt, 0);
    VariantClear(&vt);

    V_VT(&vt) = VT_BSTR;
    V_BSTR(&vt) = SysAllocString(subKey.c_str());
    pInParams->Put(L"sSubKeyName", 0, &vt, 0);
    VariantClear(&vt);

    V_VT(&vt) = VT_BSTR;
    V_BSTR(&vt) = SysAllocString(valueName.c_str());
    pInParams->Put(L"sValueName", 0, &vt, 0);
    VariantClear(&vt);

    IWbemClassObject* pOutParams = NULL;
    hr = pSvc->ExecMethod(_bstr_t(L"StdRegProv"), _bstr_t(L"GetStringValue"), 0, NULL, pInParams, &pOutParams, NULL);
    pInParams->Release();
    if (FAILED(hr) || pOutParams == NULL) return L"";

    VARIANT vtOut;
    VariantInit(&vtOut);
    std::wstring result;
    hr = pOutParams->Get(L"sValue", 0, &vtOut, NULL, NULL);
    if (SUCCEEDED(hr) && V_VT(&vtOut) == VT_BSTR && V_BSTR(&vtOut) != NULL) {
        result = V_BSTR(&vtOut);
    }
    VariantClear(&vtOut);
    pOutParams->Release();
    return result;
}

bool PrintInstalledAppsByArchitecture(const WmiTargetConfig& target, bool showWin32Apps, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\DEFAULT", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IWbemClassObject* pRegClass = NULL;
    HRESULT hr = pSvc->GetObject(_bstr_t(L"StdRegProv"), 0, NULL, &pRegClass, NULL);
    if (FAILED(hr) || pRegClass == NULL) {
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pInDef = NULL;
    hr = pRegClass->GetMethod(L"EnumKey", 0, &pInDef, NULL);
    if (FAILED(hr) || pInDef == NULL) {
        pRegClass->Release();
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pInParams = NULL;
    hr = pInDef->SpawnInstance(0, &pInParams);
    pInDef->Release();
    if (FAILED(hr) || pInParams == NULL) {
        pRegClass->Release();
        pSvc->Release();
        return false;
    }

    const std::wstring uninstallPath = showWin32Apps
        ? L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        : L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    VARIANT vt;
    VariantInit(&vt);

    V_VT(&vt) = VT_UI4;
    V_UI4(&vt) = 0x80000002; // HKEY_LOCAL_MACHINE
    pInParams->Put(L"hDefKey", 0, &vt, 0);
    VariantClear(&vt);

    V_VT(&vt) = VT_BSTR;
    V_BSTR(&vt) = SysAllocString(uninstallPath.c_str());
    pInParams->Put(L"sSubKeyName", 0, &vt, 0);
    VariantClear(&vt);

    IWbemClassObject* pOutParams = NULL;
    hr = pSvc->ExecMethod(_bstr_t(L"StdRegProv"), _bstr_t(L"EnumKey"), 0, NULL, pInParams, &pOutParams, NULL);
    pInParams->Release();
    if (FAILED(hr) || pOutParams == NULL) {
        pRegClass->Release();
        pSvc->Release();
        return false;
    }

    VARIANT vtNames;
    VariantInit(&vtNames);
    hr = pOutParams->Get(L"sNames", 0, &vtNames, NULL, NULL);
    if (FAILED(hr) || !(V_VT(&vtNames) & VT_ARRAY) || V_ARRAY(&vtNames) == NULL) {
        VariantClear(&vtNames);
        pOutParams->Release();
        pRegClass->Release();
        pSvc->Release();
        return false;
    }

    long lBound = 0;
    long uBound = -1;
    SafeArrayGetLBound(V_ARRAY(&vtNames), 1, &lBound);
    SafeArrayGetUBound(V_ARRAY(&vtNames), 1, &uBound);

    std::vector<InstalledAppRecord> records;
    for (long i = lBound; i <= uBound; ++i) {
        BSTR keyNameBstr = NULL;
        hr = SafeArrayGetElement(V_ARRAY(&vtNames), &i, &keyNameBstr);
        if (FAILED(hr) || keyNameBstr == NULL) {
            continue;
        }

        std::wstring keyName = keyNameBstr;
        SysFreeString(keyNameBstr);

        std::wstring fullSubKey = uninstallPath + L"\\" + keyName;
        std::wstring appName = ReadRegistryStringValue(pSvc, pRegClass, fullSubKey, L"DisplayName");
        if (appName.empty()) {
            continue;
        }

        InstalledAppRecord rec;
        rec.name = appName;
        rec.version = ReadRegistryStringValue(pSvc, pRegClass, fullSubKey, L"DisplayVersion");
        rec.publisher = ReadRegistryStringValue(pSvc, pRegClass, fullSubKey, L"Publisher");
        if (rec.version.empty()) rec.version = L"N/A";
        if (rec.publisher.empty()) rec.publisher = L"N/A";
        records.push_back(rec);
    }

    VariantClear(&vtNames);
    pOutParams->Release();
    pRegClass->Release();
    pSvc->Release();

    std::sort(records.begin(), records.end(), [](const InstalledAppRecord& a, const InstalledAppRecord& b) {
        return a.name < b.name;
    });

    Table table;
    table.headers = { L"Name", L"Version", L"Publisher" };
    for (const auto& rec : records) {
        table.rows.push_back({ rec.name, rec.version, rec.publisher });
    }

    if (g_outputOptions.format == OutputFormat::Table) {
        std::wcout << L"\n"
                   << (showWin32Apps ? L"Installed Win32 Applications:" : L"Installed Win64 Applications:")
                   << std::endl;
    }

    if (table.rows.empty()) {
        g_lastNoData = true;
        std::wcout << L"  No data available.\n" << std::endl;
        return true;
    }

    table.Print();
    return true;
}

bool ExecuteWMISwitchStateQuery(
    const WmiTargetConfig& target,
    const std::wstring& sectionTitle,
    const std::wstring& wqlQuery,
    const std::vector<std::pair<std::wstring, std::wstring>>& switches,
    const std::wstring& wmiLocale = L"",
    const WmiSecurityConfig& securityConfig = WmiSecurityConfig()
) {
    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wqlQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        std::wcerr << L"[!] WMI Query execution failed." << std::endl;
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

    if (g_outputOptions.format == OutputFormat::Table) {
        std::wcout << L"\n" << sectionTitle << L":" << std::endl;
    }
    if (uReturn == 0 || FAILED(hr)) {
        g_lastNoData = true;
        std::wcout << L"  No data available.\n" << std::endl;
        pEnumerator->Release();
        pSvc->Release();
        return false;
    }

    Table table;
    table.headers = { L"Switch", L"State" };

    for (const auto& sw : switches) {
        VARIANT vtProp;
        VariantInit(&vtProp);

        hr = pclsObj->Get(sw.first.c_str(), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            table.rows.push_back({ sw.second, FormatSwitchState(VariantToString(vtProp)) });
            VariantClear(&vtProp);
        } else {
            table.rows.push_back({ sw.second, L"N/A" });
        }
    }

    table.Print();

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();
    return true;
}

// Main WMI Query Execution Core
bool ExecuteWMIQuery(
    const WmiTargetConfig& target,
    const std::wstring& wqlQuery,
    const std::vector<std::wstring>& properties,
    bool autoByteFormat = true,
    const std::wstring& wmiLocale = L"",
    const std::vector<std::wstring>& displayHeaders = {},
    const WmiSecurityConfig& securityConfig = WmiSecurityConfig()
) {
    if (target.transport == TransportMode::WinRm) {
        const IWinRmBackend& backend = GetWinRmBackend(target.winrmBackend);
        std::wstring out;
        std::wstring error;
        bool noData = false;
        if (!backend.ExecuteQuery(target, wqlQuery, properties, g_outputOptions, out, noData, error)) {
            std::wcerr << L"[!] " << error << std::endl;
            return false;
        }

        if (noData) {
            g_lastNoData = true;
            return true;
        }

        std::wcout << out;
        if (!out.empty() && out.back() != L'\n') std::wcout << L"\n";
        return true;
    }

    g_lastNoData = false;

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, target.wmiNamespace, securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wqlQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        std::wcerr << L"[!] WMI Query execution failed." << std::endl;
        pSvc->Release();
        return false;
    }

    Table table;
    if (!displayHeaders.empty() && displayHeaders.size() == properties.size()) {
        table.headers = displayHeaders;
    } else {
        table.headers = properties;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        std::vector<std::wstring> row;
        for (const auto& prop : properties) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(prop.c_str(), 0, &vtProp, 0, 0);

            if (SUCCEEDED(hr)) {
                std::wstring val = VariantToString(vtProp);

                if (prop == L"InstallDate" || prop == L"ReleaseDate") {
                    val = FormatWmiDateTime(val);
                }

                if (prop == L"LicenseStatus") {
                    val = MapLicenseStatusCode(val);
                }
                
                if (autoByteFormat && (prop == L"Size" || prop == L"FreeSpace" || prop == L"Capacity" || prop == L"WorkingSetSize")) {
                    try {
                        unsigned long long bytes = std::stoull(val);
                        val = FormatBytes(bytes);
                    } catch (...) {}
                }
                
                row.push_back(val);
                VariantClear(&vtProp);
            } else {
                row.push_back(L"N/A");
            }
        }
        table.rows.push_back(row);
        pclsObj->Release();
    }

    if (table.rows.empty()) {
        g_lastNoData = true;
    }

    table.Print();

    pEnumerator->Release();
    pSvc->Release();
    return true;
}

// --- WMI Method Execution (`call`) ---

bool ExecuteWmiMethodCall(
    const WmiTargetConfig& target,
    const std::wstring& classNameOrPath,
    const std::wstring& methodName,
    const std::map<std::wstring, std::wstring>& inputArgs,
    const std::wstring& wmiLocale,
    const WmiSecurityConfig& securityConfig
) {
    if (target.transport == TransportMode::WinRm) {
        const IWinRmBackend& backend = GetWinRmBackend(target.winrmBackend);
        std::wstring out;
        std::wstring error;
        if (!backend.ExecuteMethodCall(target, classNameOrPath, methodName, inputArgs, out, error)) {
            std::wcerr << L"[!] " << error << std::endl;
            return false;
        }

        std::wcout << L"\nMethod Execution Successful.";
        if (!out.empty()) {
            std::wstring trimmed = out;
            while (!trimmed.empty() && (trimmed.back() == L'\n' || trimmed.back() == L'\r')) trimmed.pop_back();
            if (!trimmed.empty()) std::wcout << L" " << trimmed;
        }
        std::wcout << L"\n" << std::endl;
        return true;
    }

    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, target.wmiNamespace, securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IWbemClassObject* pClass = NULL;
    HRESULT hr = pSvc->GetObject(_bstr_t(classNameOrPath.c_str()), 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        std::wcerr << L"[!] Failed to get target object/class for method execution." << std::endl;
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pInParamsDef = NULL;
    hr = pClass->GetMethod(methodName.c_str(), 0, &pInParamsDef, NULL);
    if (FAILED(hr)) {
        std::wcerr << L"[!] Method signature lookup failed for: " << methodName << std::endl;
        pClass->Release();
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pInClass = NULL;
    if (pInParamsDef) {
        hr = pInParamsDef->SpawnInstance(0, &pInClass);
        if (FAILED(hr) || pInClass == NULL) {
            std::wcerr << L"[!] Failed to create method input parameter instance." << std::endl;
            pInParamsDef->Release();
            pClass->Release();
            pSvc->Release();
            return false;
        }

        auto isIntegerLiteral = [](const std::wstring& value) -> bool {
            if (value.empty()) return false;

            size_t start = 0;
            if (value[0] == L'+' || value[0] == L'-') {
                if (value.size() == 1) return false;
                start = 1;
            }

            for (size_t i = start; i < value.size(); ++i) {
                if (!iswdigit(value[i])) return false;
            }
            return true;
        };

        auto mapCimToVariantType = [](CIMTYPE baseType, VARTYPE& vtOut) -> bool {
            switch (baseType) {
            case CIM_SINT8: vtOut = VT_I1; return true;
            case CIM_UINT8: vtOut = VT_UI1; return true;
            case CIM_SINT16: vtOut = VT_I2; return true;
            case CIM_UINT16: vtOut = VT_UI2; return true;
            case CIM_SINT32: vtOut = VT_I4; return true;
            case CIM_UINT32: vtOut = VT_UI4; return true;
            case CIM_SINT64: vtOut = VT_I8; return true;
            case CIM_UINT64: vtOut = VT_UI8; return true;
            case CIM_REAL32: vtOut = VT_R4; return true;
            case CIM_REAL64: vtOut = VT_R8; return true;
            case CIM_BOOLEAN: vtOut = VT_BOOL; return true;
            case CIM_STRING:
            case CIM_DATETIME:
            case CIM_REFERENCE:
            case CIM_CHAR16:
            case CIM_OBJECT:
                vtOut = VT_BSTR;
                return true;
            default:
                return false;
            }
        };

        auto tryBuildScalarVariant = [&](CIMTYPE baseType, const std::wstring& rawValue, VARIANT& vtOut) -> bool {
            try {
                switch (baseType) {
                case CIM_SINT8:
                    V_VT(&vtOut) = VT_I1;
                    V_I1(&vtOut) = static_cast<CHAR>(std::stoi(rawValue));
                    return true;
                case CIM_UINT8:
                    V_VT(&vtOut) = VT_UI1;
                    V_UI1(&vtOut) = static_cast<BYTE>(std::stoul(rawValue));
                    return true;
                case CIM_SINT16:
                    V_VT(&vtOut) = VT_I2;
                    V_I2(&vtOut) = static_cast<SHORT>(std::stoi(rawValue));
                    return true;
                case CIM_UINT16:
                    V_VT(&vtOut) = VT_UI2;
                    V_UI2(&vtOut) = static_cast<USHORT>(std::stoul(rawValue));
                    return true;
                case CIM_SINT32:
                    V_VT(&vtOut) = VT_I4;
                    V_I4(&vtOut) = static_cast<LONG>(std::stol(rawValue));
                    return true;
                case CIM_UINT32:
                    V_VT(&vtOut) = VT_UI4;
                    V_UI4(&vtOut) = static_cast<ULONG>(std::stoul(rawValue));
                    return true;
                case CIM_SINT64:
                    V_VT(&vtOut) = VT_I8;
                    V_I8(&vtOut) = static_cast<LONGLONG>(std::stoll(rawValue));
                    return true;
                case CIM_UINT64:
                    V_VT(&vtOut) = VT_UI8;
                    V_UI8(&vtOut) = static_cast<ULONGLONG>(std::stoull(rawValue));
                    return true;
                case CIM_REAL32:
                    V_VT(&vtOut) = VT_R4;
                    V_R4(&vtOut) = static_cast<FLOAT>(std::stof(rawValue));
                    return true;
                case CIM_REAL64:
                    V_VT(&vtOut) = VT_R8;
                    V_R8(&vtOut) = static_cast<DOUBLE>(std::stod(rawValue));
                    return true;
                case CIM_BOOLEAN: {
                    std::wstring lowered = rawValue;
                    std::transform(lowered.begin(), lowered.end(), lowered.begin(), towlower);
                    if (lowered == L"true" || lowered == L"1") {
                        V_VT(&vtOut) = VT_BOOL;
                        V_BOOL(&vtOut) = VARIANT_TRUE;
                        return true;
                    }
                    if (lowered == L"false" || lowered == L"0") {
                        V_VT(&vtOut) = VT_BOOL;
                        V_BOOL(&vtOut) = VARIANT_FALSE;
                        return true;
                    }
                    return false;
                }
                case CIM_STRING:
                case CIM_DATETIME:
                case CIM_REFERENCE:
                case CIM_CHAR16:
                case CIM_OBJECT:
                    V_VT(&vtOut) = VT_BSTR;
                    V_BSTR(&vtOut) = SysAllocString(rawValue.c_str());
                    return V_BSTR(&vtOut) != NULL;
                default:
                    return false;
                }
            } catch (...) {
                return false;
            }
        };

        auto tryBuildArrayVariant = [&](CIMTYPE baseType, const std::wstring& rawValue, VARIANT& vtOut) -> bool {
            VARTYPE elementVt = VT_EMPTY;
            if (!mapCimToVariantType(baseType, elementVt)) {
                return false;
            }

            std::vector<std::wstring> items = SplitAndTrimCommaList(rawValue);
            if (items.empty()) {
                return false;
            }

            SAFEARRAYBOUND bound;
            bound.lLbound = 0;
            bound.cElements = static_cast<ULONG>(items.size());
            SAFEARRAY* psa = SafeArrayCreate(elementVt, 1, &bound);
            if (!psa) {
                return false;
            }

            bool ok = true;
            for (LONG i = 0; i < static_cast<LONG>(items.size()); ++i) {
                const std::wstring& item = items[i];
                HRESULT putHr = E_FAIL;

                try {
                    switch (elementVt) {
                    case VT_I1: {
                        CHAR v = static_cast<CHAR>(std::stoi(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_UI1: {
                        BYTE v = static_cast<BYTE>(std::stoul(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_I2: {
                        SHORT v = static_cast<SHORT>(std::stoi(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_UI2: {
                        USHORT v = static_cast<USHORT>(std::stoul(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_I4: {
                        LONG v = static_cast<LONG>(std::stol(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_UI4: {
                        ULONG v = static_cast<ULONG>(std::stoul(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_I8: {
                        LONGLONG v = static_cast<LONGLONG>(std::stoll(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_UI8: {
                        ULONGLONG v = static_cast<ULONGLONG>(std::stoull(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_R4: {
                        FLOAT v = static_cast<FLOAT>(std::stof(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_R8: {
                        DOUBLE v = static_cast<DOUBLE>(std::stod(item));
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_BOOL: {
                        std::wstring lowered = item;
                        std::transform(lowered.begin(), lowered.end(), lowered.begin(), towlower);
                        VARIANT_BOOL v;
                        if (lowered == L"true" || lowered == L"1") v = VARIANT_TRUE;
                        else if (lowered == L"false" || lowered == L"0") v = VARIANT_FALSE;
                        else {
                            putHr = E_INVALIDARG;
                            break;
                        }
                        putHr = SafeArrayPutElement(psa, &i, &v);
                        break;
                    }
                    case VT_BSTR: {
                        BSTR b = SysAllocString(item.c_str());
                        if (!b) {
                            putHr = E_OUTOFMEMORY;
                            break;
                        }
                        putHr = SafeArrayPutElement(psa, &i, b);
                        SysFreeString(b);
                        break;
                    }
                    default:
                        putHr = E_NOTIMPL;
                        break;
                    }
                } catch (...) {
                    putHr = E_INVALIDARG;
                }

                if (FAILED(putHr)) {
                    ok = false;
                    break;
                }
            }

            if (!ok) {
                SafeArrayDestroy(psa);
                return false;
            }

            V_VT(&vtOut) = static_cast<VARTYPE>(VT_ARRAY | elementVt);
            V_ARRAY(&vtOut) = psa;
            return true;
        };

        auto putTypedInputValue = [&](const std::wstring& name, const std::wstring& rawValue) -> bool {
            CIMTYPE cimType = 0;
            VARIANT vtSchema;
            VariantInit(&vtSchema);
            HRESULT schemaHr = pInParamsDef->Get(name.c_str(), 0, &vtSchema, &cimType, NULL);
            VariantClear(&vtSchema);

            VARIANT vtVal;
            VariantInit(&vtVal);
            bool assigned = false;
            bool hasSchemaType = SUCCEEDED(schemaHr);

            if (hasSchemaType) {
                CIMTYPE baseType = static_cast<CIMTYPE>(cimType & ~CIM_FLAG_ARRAY);
                bool isArray = (cimType & CIM_FLAG_ARRAY) != 0;
                assigned = isArray
                    ? tryBuildArrayVariant(baseType, rawValue, vtVal)
                    : tryBuildScalarVariant(baseType, rawValue, vtVal);

                if (!assigned) {
                    // Schema exists but conversion failed; avoid sending mismatched VARTYPE.
                    return false;
                }
            }

            // Fallback when schema is unavailable: best-effort integer or BSTR.
            if (!hasSchemaType && isIntegerLiteral(rawValue)) {
                try {
                    long long v = std::stoll(rawValue);
                    if (v >= static_cast<long long>(LONG_MIN) && v <= static_cast<long long>(LONG_MAX)) {
                        V_VT(&vtVal) = VT_I4;
                        V_I4(&vtVal) = static_cast<LONG>(v);
                    } else {
                        V_VT(&vtVal) = VT_I8;
                        V_I8(&vtVal) = static_cast<LONGLONG>(v);
                    }
                    assigned = true;
                } catch (...) {
                    assigned = false;
                }
            }

            if (!assigned) {
                V_VT(&vtVal) = VT_BSTR;
                V_BSTR(&vtVal) = SysAllocString(rawValue.c_str());
            }

            HRESULT putHr = pInClass->Put(name.c_str(), 0, &vtVal, 0);
            VariantClear(&vtVal);
            return SUCCEEDED(putHr);
        };

        for (const auto& kv : inputArgs) {
            if (!putTypedInputValue(kv.first, kv.second)) {
                std::wcerr << L"[!] Failed to set method input parameter: " << kv.first << std::endl;
                pInClass->Release();
                pInParamsDef->Release();
                pClass->Release();
                pSvc->Release();
                return false;
            }
        }

        pInParamsDef->Release();
    }

    IWbemClassObject* pOutParams = NULL;
    hr = pSvc->ExecMethod(_bstr_t(classNameOrPath.c_str()), _bstr_t(methodName.c_str()), 0, NULL, pInClass, &pOutParams, NULL);

    if (pInClass) pInClass->Release();
    pClass->Release();

    if (SUCCEEDED(hr) && pOutParams) {
        VARIANT vtRet;
        VariantInit(&vtRet);
        if (SUCCEEDED(pOutParams->Get(L"ReturnValue", 0, &vtRet, NULL, NULL))) {
            std::wcout << L"\nMethod Execution Successful. ReturnValue = " << VariantToString(vtRet) << L"\n" << std::endl;
        } else {
            std::wcout << L"\nMethod Executed Successfully.\n" << std::endl;
        }
        VariantClear(&vtRet);
        pOutParams->Release();
        pSvc->Release();
        return true;
    }

    std::wcerr << L"[!] Method execution failed. HRESULT: 0x" << std::hex << hr << std::dec << std::endl;
    pSvc->Release();
    return false;
}

// --- WMI Property Modification (`set`) ---

bool ExecuteWmiSetProperty(
    const WmiTargetConfig& target,
    const std::wstring& objectPath,
    const std::wstring& propName,
    const std::wstring& propValue,
    const std::wstring& wmiLocale,
    const WmiSecurityConfig& securityConfig
) {
    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, target.wmiNamespace, securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IWbemClassObject* pInst = NULL;
    HRESULT hr = pSvc->GetObject(_bstr_t(objectPath.c_str()), 0, NULL, &pInst, NULL);
    if (FAILED(hr)) {
        std::wcerr << L"[!] Instance not found for SET operation." << std::endl;
        pSvc->Release();
        return false;
    }

    VARIANT vtVal;
    VariantInit(&vtVal);
    V_VT(&vtVal) = VT_BSTR;
    V_BSTR(&vtVal) = SysAllocString(propValue.c_str());

    hr = pInst->Put(propName.c_str(), 0, &vtVal, 0);
    VariantClear(&vtVal);

    if (SUCCEEDED(hr)) {
        hr = pSvc->PutInstance(pInst, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
    }

    pInst->Release();
    pSvc->Release();

    if (SUCCEEDED(hr)) {
        std::wcout << L"\nProperty updated successfully: " << propName << L" = " << propValue << L"\n" << std::endl;
        return true;
    }

    std::wcerr << L"[!] Failed to update instance property. HRESULT: 0x" << std::hex << hr << std::dec << std::endl;
    return false;
}

// --- WMI Instance Deletion (`delete`) ---

bool ExecuteWmiDelete(
    const WmiTargetConfig& target,
    const std::wstring& objectPath,
    const std::wstring& wmiLocale,
    const WmiSecurityConfig& securityConfig
) {
    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, target.wmiNamespace, securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    HRESULT hr = pSvc->DeleteInstance(_bstr_t(objectPath.c_str()), 0, NULL, NULL);
    pSvc->Release();

    if (SUCCEEDED(hr)) {
        std::wcout << L"\nInstance deleted successfully: " << objectPath << L"\n" << std::endl;
        return true;
    }

    std::wcerr << L"[!] Failed to delete instance. HRESULT: 0x" << std::hex << hr << std::dec << std::endl;
    return false;
}

bool ExecuteRamStatusSummary(const WmiTargetConfig& target, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    IWbemServices* pSvc = NULL;
    if (!ConnectWmiServices(target, L"ROOT\\CIMV2", securityConfig, wmiLocale, &pSvc)) {
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (FAILED(hr) || uReturn == 0) {
        pEnumerator->Release();
        pSvc->Release();
        return false;
    }

    auto readProp = [&](const wchar_t* propName) -> std::wstring {
        VARIANT vtProp;
        VariantInit(&vtProp);
        std::wstring value = L"N/A";
        if (SUCCEEDED(pclsObj->Get(propName, 0, &vtProp, 0, 0))) {
            value = VariantToString(vtProp);
        }
        VariantClear(&vtProp);
        return value;
    };

    std::wstring totalKbStr = readProp(L"TotalVisibleMemorySize");
    std::wstring freeKbStr = readProp(L"FreePhysicalMemory");

    std::wstring ramLoad = L"N/A";
    std::wstring totalPhysical = L"N/A";
    std::wstring availablePhysical = L"N/A";

    try {
        unsigned long long totalKb = std::stoull(totalKbStr);
        unsigned long long freeKb = std::stoull(freeKbStr);
        unsigned long long usedKb = (totalKb > freeKb) ? (totalKb - freeKb) : 0;

        if (totalKb > 0) {
            unsigned long long loadPct = (usedKb * 100ULL) / totalKb;
            ramLoad = std::to_wstring(loadPct) + L"%";
        }

        totalPhysical = FormatBytes(totalKb * 1024ULL);
        availablePhysical = FormatBytes(freeKb * 1024ULL);
    } catch (...) {
        // Keep N/A values when numeric conversion is unavailable.
    }

    if (g_outputOptions.format == OutputFormat::Table) {
        std::wcout << L"\n--- System Memory Summary ---" << std::endl;
        std::wcout << L"RAM Load:            " << ramLoad << std::endl;
        std::wcout << L"Total Physical:      " << totalPhysical << std::endl;
        std::wcout << L"Available Physical:  " << availablePhysical << std::endl;
    } else {
        Table table;
        table.headers = { L"RAM Load", L"Total Physical", L"Available Physical" };
        table.rows.push_back({ ramLoad, totalPhysical, availablePhysical });
        table.Print();
    }

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();
    return true;
}

void PrintHelp() {
    std::wcout << L"\n" 
              << L"XMIC - Windows System Information & Monitoring Tool\n"
              << L"Version: 2.2.0\n\n"
              << L"Copyright (c) 2026, Roberto J. Dohnert\n"
              << L"Licensed under the BSD-3 Clause License\n\n"
              << L"Commands:\n"
              << L"Usage: xmic [global_options] <command|path <class>> [where \"<clause>\"] <verb> [arguments]\n\n"
              << L"Global Options:\n"
              << L"  --node, /NODE:<HOST>          Target remote machine (default: local)\n"
              << L"  --user, /USER:<USER>          Remote authentication username\n"
              << L"  --password, /PASSWORD:<PASS>  Remote authentication password\n"
              << L"  --prompt-password             Prompt for remote password without echo\n"
              << L"  --prompt-password-confirm     Prompt twice and require matching password\n"
              << L"  --domain, /DOMAIN:<DOM>       Remote domain name\n"
              << L"  --namespace, /NAMESPACE:<NS>  WMI namespace (default: ROOT\\\\CIMV2)\n"
              << L"  --transport <MODE>           Transport mode: dcom (default) or winrm\n"
              << L"  --winrm-backend <MODE>       WinRM backend: powershell (default) or native\n"
              << L"  --console-encoding <MODE>    Console encoding: utf16 or utf8\n"
              << L"  --output, /OUTPUT:<FILE>      Redirect output to text file stream\n"
              << L"  --locale <WMI_LOCALE>         Set WMI locale (example: MS_409 for en-US)\n"
              << L"  --wmi-security <LEVEL>        Set WMI COM security level (default, connect, call, pkt, pktprivacy)\n"
              << L"  --format <FMT>               Output format (table, csv, json)\n"
              << L"  --no-header                  Suppress header row in table/csv output\n\n"
              << L"Preset Information Tasks:\n"
              << L"  os        - Operating System specifications\n"
              << L"  cpu       - CPU architecture, cores, and live load percentage\n"
              << L"  ram       - Memory summary and physical slot layout\n"
              << L"  disk      - Logical storage drives, filesystem & capacity\n"
              << L"  extdisk   - External/removable storage devices (USB and removable media)\n"
              << L"  net       - Active network adapters, MAC & IP addresses\n"
              << L"  gpu       - Graphics cards and driver details\n"
              << L"  bios      - BIOS version, vendor, release date, and serial number\n"
              << L"  gswitch   - Global Windows OS/system switch states\n"
              << L"  security  - WMI COM security level capability check\n"
              << L"  context   - WMIC-style host/context summary\n"
              << L"  qfe       - Installed Windows updates (HotFix IDs)\n"
              << L"  port      - Physical and serial port information\n"
              << L"  sys       - System hardware model, BIOS & motherboard info\n"
              << L"  process   - Active running processes and memory footprint\n"
              << L"  service   - Running Windows services\n"
              << L"  ntevent   - Windows NT event log entries (System warnings/errors)\n"
              << L"  apps      - Installed applications\n"
              << L"  apps32    - Installed Win32 applications\n"
              << L"  apps64    - Installed Win64 applications\n"
              << L"  devices   - Installed Plug-and-Play devices\n"
              << L"  threads   - Total running system threads\n"
              << L"  users     - Local user accounts\n"
              << L"  help      - Show this help message\n\n"
              << L"WMI Verbs & Custom Path Mode:\n"
              << L"  path <WMI_Class> [where \"<clause>\"] get <PROP1,PROP2,...>\n"
              << L"  path <WMI_Class> call <MethodName> [Param1=Val1 Param2=Val2]\n"
              << L"  path <WMI_Path> set <PropName>=<Value>\n"
              << L"  path <WMI_Path> delete\n"
              << L"  query \"<WQL_QUERY>\" <PROP1> [PROP2 ...]\n\n"
              << L"Deterministic Exit Codes:\n"
              << L"  0 = success\n"
              << L"  2 = invalid arguments/options\n"
              << L"  3 = unknown command\n"
              << L"  4 = WMI/runtime failure\n"
              << L"  5 = no data returned\n";
}

int wmain(int argc, wchar_t* argv[]) {
    ConsoleEncoding consoleEncoding = ConsoleEncoding::Utf16;
    if (!ConfigureConsoleOutputMode(consoleEncoding)) {
        std::wcerr << L"[!] Failed to configure default console output mode." << std::endl;
        return EXIT_BAD_ARGS;
    }

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return EXIT_WMI_FAILURE;
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    // If COM security was already initialized by another component (host/injected DLL),
    // RPC_E_TOO_LATE is expected and should not be treated as fatal.
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wcerr << L"[!] CoInitializeSecurity failed: " << HResultToHex(hr) << std::endl;
        CoUninitialize();
        return EXIT_WMI_FAILURE;
    }

    EnableCommonPrivileges();

    if (argc < 2) {
        PrintHelp();
        CoUninitialize();
        return EXIT_OK;
    }

    int argIndex = 1;
    std::wstring wmiLocale;
    WmiSecurityConfig securityConfig;
    WmiTargetConfig targetConfig;
    StdoutRedirector redirector;
    bool noHeader = false;
    OutputFormat outputFormat = OutputFormat::Table;
    bool forcePasswordPrompt = false;
    bool forcePasswordPromptConfirm = false;

    while (argIndex < argc) {
        std::wstring option = argv[argIndex];

        if (option == L"--locale") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --locale." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            wmiLocale = argv[argIndex + 1];
            argIndex += 2;
            continue;
        }

        if (option == L"--console-encoding") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --console-encoding." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }

            if (!TryParseConsoleEncoding(argv[argIndex + 1], consoleEncoding)) {
                std::wcerr << L"[!] Invalid --console-encoding value. Use utf16 or utf8." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }

            if (!ConfigureConsoleOutputMode(consoleEncoding)) {
                std::wcerr << L"[!] Failed to configure requested console output mode." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }

            argIndex += 2;
            continue;
        }

        if (option == L"--wmi-security") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --wmi-security." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            if (!TryParseWmiSecurity(argv[argIndex + 1], securityConfig)) {
                std::wcerr << L"[!] Invalid --wmi-security value." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            argIndex += 2;
            continue;
        }

        if (option == L"--transport") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --transport." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            if (!TryParseTransportMode(argv[argIndex + 1], targetConfig.transport)) {
                std::wcerr << L"[!] Invalid --transport value. Use dcom or winrm." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            argIndex += 2;
            continue;
        }

        if (option == L"--winrm-backend") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --winrm-backend." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            if (!TryParseWinRmBackendMode(argv[argIndex + 1], targetConfig.winrmBackend)) {
                std::wcerr << L"[!] Invalid --winrm-backend value. Use powershell or native." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            argIndex += 2;
            continue;
        }

        if (option == L"--format") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --format." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            if (!TryParseOutputFormat(argv[argIndex + 1], outputFormat)) {
                std::wcerr << L"[!] Invalid --format value." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            argIndex += 2;
            continue;
        }

        if (option == L"--no-header") {
            noHeader = true;
            argIndex += 1;
            continue;
        }

        if (option == L"--namespace" || _wcsnicmp(option.c_str(), L"/NAMESPACE:", 11) == 0) {
            if (option == L"--namespace") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --namespace." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                targetConfig.wmiNamespace = argv[argIndex + 1];
                argIndex += 2;
            } else {
                targetConfig.wmiNamespace = option.substr(11);
                argIndex += 1;
            }
            continue;
        }

        if (option == L"--output" || _wcsnicmp(option.c_str(), L"/OUTPUT:", 8) == 0) {
            std::wstring file;
            if (option == L"--output") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --output." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                file = argv[argIndex + 1];
                argIndex += 2;
            } else {
                file = option.substr(8);
                argIndex += 1;
            }
            if (!redirector.RedirectToFile(file)) {
                std::wcerr << L"[!] Failed to open output file: " << file << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }
            continue;
        }

        if (option == L"--node" || _wcsnicmp(option.c_str(), L"/NODE:", 6) == 0) {
            if (option == L"--node") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --node." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                targetConfig.node = argv[argIndex + 1];
                argIndex += 2;
            } else {
                targetConfig.node = option.substr(6);
                argIndex += 1;
            }
            continue;
        }

        if (option == L"--user" || _wcsnicmp(option.c_str(), L"/USER:", 6) == 0) {
            if (option == L"--user") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --user." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                targetConfig.user = argv[argIndex + 1];
                argIndex += 2;
            } else {
                targetConfig.user = option.substr(6);
                argIndex += 1;
            }
            continue;
        }

        if (option == L"--password" || _wcsnicmp(option.c_str(), L"/PASSWORD:", 10) == 0) {
            if (option == L"--password") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --password." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                targetConfig.password = argv[argIndex + 1];
                argIndex += 2;
            } else {
                targetConfig.password = option.substr(10);
                argIndex += 1;
            }
            continue;
        }

        if (option == L"--prompt-password") {
            forcePasswordPrompt = true;
            argIndex += 1;
            continue;
        }

        if (option == L"--prompt-password-confirm") {
            forcePasswordPromptConfirm = true;
            argIndex += 1;
            continue;
        }

        if (option == L"--domain" || _wcsnicmp(option.c_str(), L"/DOMAIN:", 8) == 0) {
            if (option == L"--domain") {
                if (argIndex + 1 >= argc) {
                    std::wcerr << L"[!] Missing value for --domain." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                targetConfig.domain = argv[argIndex + 1];
                argIndex += 2;
            } else {
                targetConfig.domain = option.substr(8);
                argIndex += 1;
            }
            continue;
        }

        break;
    }

    g_outputOptions.format = outputFormat;
    g_outputOptions.noHeader = noHeader;

    if (forcePasswordPromptConfirm && !targetConfig.password.empty()) {
        std::wcerr << L"[!] --prompt-password-confirm cannot be used with --password." << std::endl;
        CoUninitialize();
        return EXIT_BAD_ARGS;
    }

    bool isRemoteTarget = !(targetConfig.node.empty() || targetConfig.node == L".");
    bool shouldPromptForPassword =
        forcePasswordPromptConfirm ||
        forcePasswordPrompt ||
        (isRemoteTarget && !targetConfig.user.empty() && targetConfig.password.empty());

    if (shouldPromptForPassword) {
        if (targetConfig.user.empty()) {
            std::wcerr << L"[!] Password prompt mode requires --user for remote authentication." << std::endl;
            CoUninitialize();
            return EXIT_BAD_ARGS;
        }

        std::wstring prompt = L"Enter remote password";
        if (!targetConfig.user.empty()) {
            prompt += L" for " + targetConfig.user;
        }
        if (isRemoteTarget) {
            prompt += L"@" + targetConfig.node;
        }
        prompt += L": ";

        std::wstring firstEntry;
        std::wstring promptError;
        if (!ReadHiddenConsoleLine(prompt, firstEntry, promptError)) {
            std::wcerr << L"[!] " << promptError << std::endl;
            CoUninitialize();
            return EXIT_BAD_ARGS;
        }

        if (firstEntry.empty()) {
            std::wcerr << L"[!] Password entry cannot be empty." << std::endl;
            CoUninitialize();
            return EXIT_BAD_ARGS;
        }

        if (forcePasswordPromptConfirm) {
            std::wstring secondEntry;
            if (!ReadHiddenConsoleLine(L"Confirm remote password: ", secondEntry, promptError)) {
                SecureZeroMemory(&firstEntry[0], firstEntry.size() * sizeof(wchar_t));
                std::wcerr << L"[!] " << promptError << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }

            if (firstEntry != secondEntry) {
                if (!firstEntry.empty()) {
                    SecureZeroMemory(&firstEntry[0], firstEntry.size() * sizeof(wchar_t));
                }
                if (!secondEntry.empty()) {
                    SecureZeroMemory(&secondEntry[0], secondEntry.size() * sizeof(wchar_t));
                }
                std::wcerr << L"[!] Password confirmation does not match." << std::endl;
                CoUninitialize();
                return EXIT_BAD_ARGS;
            }

            if (!secondEntry.empty()) {
                SecureZeroMemory(&secondEntry[0], secondEntry.size() * sizeof(wchar_t));
            }
        }

        targetConfig.password = firstEntry;
        if (!firstEntry.empty()) {
            SecureZeroMemory(&firstEntry[0], firstEntry.size() * sizeof(wchar_t));
        }
    }

    if (argIndex >= argc) {
        PrintHelp();
        CoUninitialize();
        return EXIT_BAD_ARGS;
    }

    std::wstring cmd = argv[argIndex];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), towlower);

    if (cmd == L"help" || cmd == L"--help" || cmd == L"-h") {
        PrintHelp();
        CoUninitialize();
        return EXIT_OK;
    }

    bool success = true;

    if (targetConfig.transport == TransportMode::WinRm) {
        bool unsupported =
            (cmd == L"os") ||
            (cmd == L"cpu") ||
            (cmd == L"net") ||
            (cmd == L"sys") ||
            (cmd == L"devices") ||
            (cmd == L"threads") ||
            (cmd == L"security") || (cmd == L"wmisecurity") ||
            (cmd == L"gswitch") || (cmd == L"globalswitch") ||
            (cmd == L"apps32") || (cmd == L"win32apps") ||
            (cmd == L"apps64") || (cmd == L"win64apps");

        if (unsupported) {
            std::wcerr << L"[!] Command '" << cmd << L"' is currently supported only with dcom transport." << std::endl;
            CoUninitialize();
            return EXIT_BAD_ARGS;
        }
    }

    if (cmd == L"os") {
        success = ExecuteOSInfoQuery(targetConfig, wmiLocale, securityConfig);
    } 
    else if (cmd == L"cpu") {
        success = ExecuteCpuInfoQuery(targetConfig, wmiLocale, securityConfig);
    } 
    else if (cmd == L"ram") {
        success = ExecuteRamStatusSummary(targetConfig, wmiLocale, securityConfig);
        if (!success) {
            g_lastNoData = true;
            if (g_outputOptions.format == OutputFormat::Table) {
                std::wcout << L"  No data available.\n" << std::endl;
            }
        }
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nHardware Slots:" << std::endl;
        }
        bool slotsSuccess = ExecuteWMIQuery(
            targetConfig,
            L"SELECT DeviceLocator, Capacity, Speed, Manufacturer FROM Win32_PhysicalMemory",
            { L"DeviceLocator", L"Capacity", L"Speed", L"Manufacturer" },
            true, wmiLocale, {}, securityConfig
        );
        success = success && slotsSuccess;
    } 
    else if (cmd == L"disk") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3",
            { L"DeviceID", L"VolumeName", L"FileSystem", L"Size", L"FreeSpace" },
            true, wmiLocale, {}, securityConfig
        );
    } 
    else if (cmd == L"extdisk" || cmd == L"external") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace, DriveType FROM Win32_LogicalDisk WHERE DriveType=2",
            { L"DeviceID", L"VolumeName", L"FileSystem", L"Size", L"FreeSpace", L"DriveType" },
            true, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"net") {
        success = ExecuteNetInfoQuery(targetConfig, wmiLocale, securityConfig);
    } 
    else if (cmd == L"gpu") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController",
            { L"Name", L"DriverVersion", L"AdapterRAM" },
            true, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"bios" || cmd == L"firmware") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS",
            { L"Manufacturer", L"SMBIOSBIOSVersion", L"ReleaseDate", L"SerialNumber" },
            true, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"gswitch" || cmd == L"globalswitch") {
        success = ExecuteWMISwitchStateQuery(
            targetConfig,
            L"Operating System Global Switches",
            L"SELECT DataExecutionPrevention_Available, DataExecutionPrevention_32BitApplications, DataExecutionPrevention_Drivers, PAEEnabled, Debug, Distributed, PortableOperatingSystem FROM Win32_OperatingSystem",
            {
                { L"DataExecutionPrevention_Available", L"DEP Available" },
                { L"DataExecutionPrevention_32BitApplications", L"DEP for 32-bit Apps" },
                { L"DataExecutionPrevention_Drivers", L"DEP for Drivers" },
                { L"PAEEnabled", L"PAE Enabled" },
                { L"Debug", L"Kernel Debug" },
                { L"Distributed", L"Distributed Build" },
                { L"PortableOperatingSystem", L"Portable OS" }
            },
            wmiLocale, securityConfig
        );

        success = ExecuteWMISwitchStateQuery(
            targetConfig,
            L"System Global Switches",
            L"SELECT AutomaticManagedPagefile, AutomaticResetBootOption, AutomaticResetCapability, HypervisorPresent FROM Win32_ComputerSystem",
            {
                { L"AutomaticManagedPagefile", L"Auto Managed Pagefile" },
                { L"AutomaticResetBootOption", L"Auto Reset Boot Option" },
                { L"AutomaticResetCapability", L"Auto Reset Capability" },
                { L"HypervisorPresent", L"Hypervisor Present" }
            },
            wmiLocale, securityConfig
        );
    }
    else if (cmd == L"security" || cmd == L"wmisecurity") {
        PrintWmiSecurityAvailability(targetConfig, wmiLocale);
        success = true;
    }
    else if (cmd == L"context" || cmd == L"wmiccontext" || cmd == L"wmic") {
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nWMIC Context Summary:" << std::endl;
        }
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT CSName, Caption, Version, OSArchitecture, LocalDateTime, LastBootUpTime FROM Win32_OperatingSystem",
            { L"CSName", L"Caption", L"Version", L"OSArchitecture", L"LocalDateTime", L"LastBootUpTime" },
            false, wmiLocale, {}, securityConfig
        );

        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Domain, PartOfDomain, UserName FROM Win32_ComputerSystem",
            { L"Domain", L"PartOfDomain", L"UserName" },
            false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"qfe") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering",
            { L"HotFixID", L"Description", L"InstalledOn", L"InstalledBy" },
            false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"port" || cmd == L"ports") {
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nSerial and Logical Ports:" << std::endl;
        }
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT DeviceID, Name, Description, Status, MaxBaudRate FROM Win32_SerialPort",
            { L"DeviceID", L"Name", L"Description", L"Status", L"MaxBaudRate" },
            false, wmiLocale, { L"Port", L"Name", L"Description", L"Status", L"Max Baud" }, securityConfig
        );

        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"Physical Port Connectors:" << std::endl;
        }
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Tag, PortType, ExternalReferenceDesignator, InternalReferenceDesignator FROM Win32_PortConnector",
            { L"Tag", L"PortType", L"ExternalReferenceDesignator", L"InternalReferenceDesignator" },
            false, wmiLocale, { L"Tag", L"Port Type", L"External Ref", L"Internal Ref" }, securityConfig
        );
    }
    else if (cmd == L"sys") {
        success = ExecuteSystemInfoQuery(targetConfig, wmiLocale, securityConfig);
    }
    else if (cmd == L"process") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT ProcessId, Name, WorkingSetSize FROM Win32_Process",
            { L"ProcessId", L"Name", L"WorkingSetSize" },
            true, wmiLocale, {}, securityConfig
        );
    } 
    else if (cmd == L"service") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Name, DisplayName, State, StartMode FROM Win32_Service WHERE State='Running'",
            { L"Name", L"DisplayName", L"State", L"StartMode" },
            true, wmiLocale, {}, securityConfig
        );
    } 
    else if (cmd == L"ntevent" || cmd == L"event") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Logfile, EventCode, Type, SourceName, TimeGenerated FROM Win32_NTLogEvent WHERE Logfile='System' AND (Type='Error' OR Type='Warning')",
            { L"Logfile", L"EventCode", L"Type", L"SourceName", L"TimeGenerated" },
            false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"apps") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Name, Version, Vendor, InstallDate FROM Win32_Product",
            { L"Name", L"Version", L"Vendor", L"InstallDate" },
            false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"apps32" || cmd == L"win32apps") {
        success = PrintInstalledAppsByArchitecture(targetConfig, true, wmiLocale, securityConfig);
    }
    else if (cmd == L"apps64" || cmd == L"win64apps") {
        success = PrintInstalledAppsByArchitecture(targetConfig, false, wmiLocale, securityConfig);
    }
    else if (cmd == L"devices" || cmd == L"device") {
        success = ExecuteDevicesInfoQuery(targetConfig, wmiLocale, securityConfig);
    }
    else if (cmd == L"threads" || cmd == L"thread") {
        success = ExecuteThreadsInfoQuery(targetConfig, wmiLocale, securityConfig);
    }
    else if (cmd == L"users") {
        success = ExecuteWMIQuery(
            targetConfig,
            L"SELECT Name, FullName, Disabled, LocalAccount, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=TRUE",
            { L"Name", L"FullName", L"Disabled", L"LocalAccount", L"PasswordRequired" },
            false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"path" && argIndex + 1 < argc) {
        std::wstring targetClass = argv[argIndex + 1];
        std::wstring whereClause = L"";
        int nextIndex = argIndex + 2;

        if (nextIndex < argc && _wcsicmp(argv[nextIndex], L"where") == 0 && nextIndex + 1 < argc) {
            whereClause = argv[nextIndex + 1];
            nextIndex += 2;
        }

        if (nextIndex < argc) {
            std::wstring verb = argv[nextIndex];
            std::transform(verb.begin(), verb.end(), verb.begin(), towlower);

            if (verb == L"get" && nextIndex + 1 < argc) {
                std::vector<std::wstring> props;
                std::wstringstream ss(argv[nextIndex + 1]);
                std::wstring prop;
                while (std::getline(ss, prop, L',')) props.push_back(prop);

                std::wstring wql = L"SELECT " + (std::wstring)argv[nextIndex + 1] + L" FROM " + targetClass;
                if (!whereClause.empty()) wql += L" WHERE " + whereClause;
                success = ExecuteWMIQuery(targetConfig, wql, props, false, wmiLocale, {}, securityConfig);
            } else if (verb == L"call" && nextIndex + 1 < argc) {
                std::wstring methodName = argv[nextIndex + 1];
                std::map<std::wstring, std::wstring> args;
                std::wstring parseError;
                if (!ParseNamedCallArguments(nextIndex + 2, argc, argv, args, parseError)) {
                    std::wcerr << L"[!] " << parseError << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                success = ExecuteWmiMethodCall(targetConfig, targetClass, methodName, args, wmiLocale, securityConfig);
            } else if (verb == L"delete") {
                if (targetConfig.transport == TransportMode::WinRm) {
                    std::wcerr << L"[!] path delete is currently supported only with dcom transport." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                success = ExecuteWmiDelete(targetConfig, targetClass, wmiLocale, securityConfig);
            } else if (verb == L"set" && nextIndex + 1 < argc) {
                if (targetConfig.transport == TransportMode::WinRm) {
                    std::wcerr << L"[!] path set is currently supported only with dcom transport." << std::endl;
                    CoUninitialize();
                    return EXIT_BAD_ARGS;
                }
                std::wstring pair = argv[nextIndex + 1];
                size_t eqPos = pair.find(L'=');
                if (eqPos != std::wstring::npos) {
                    success = ExecuteWmiSetProperty(targetConfig, targetClass, pair.substr(0, eqPos), pair.substr(eqPos + 1), wmiLocale, securityConfig);
                }
            }
        }
    }
    else if (cmd == L"query" && argc >= argIndex + 3) {
        std::wstring query = argv[argIndex + 1];
        std::vector<std::wstring> props;
        for (int i = argIndex + 2; i < argc; ++i) {
            props.push_back(argv[i]);
        }
        success = ExecuteWMIQuery(targetConfig, query, props, false, wmiLocale, {}, securityConfig);
    } 
    else if (cmd == L"query") {
        std::wcerr << L"[!] Missing query text or property list for query command." << std::endl;
        CoUninitialize();
        return EXIT_BAD_ARGS;
    }
    else {
        std::wcerr << L"[!] Unknown command: " << cmd << std::endl;
        CoUninitialize();
        return EXIT_UNKNOWN_COMMAND;
    }

    CoUninitialize();

    if (!success) {
        if (g_lastNoData) return EXIT_NO_DATA;
        return EXIT_WMI_FAILURE;
    }
    if (g_lastNoData) return EXIT_NO_DATA;
    return EXIT_OK;
}