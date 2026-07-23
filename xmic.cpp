#define _WIN32_DCOM
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <utility>
#include <set>
#include <cwctype>
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// --- Helper Functions ---

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
            for (long i = lBound; i <= uBound; ++i) {
                if (i > lBound) result += L", ";
                result += bstrData[i];
            }
            SafeArrayUnaccessData(psa);
            return result;
        }
    }

    // Generic conversion attempt
    VARIANT dest;
    VariantInit(&dest);
    if (SUCCEEDED(VariantChangeType(&dest, &vtProp, 0, VT_BSTR))) {
        std::wstring str(V_BSTR(&dest));
        VariantClear(&dest);
        return str;
    }
    return L"<Data>";
}

std::wstring FormatWmiDateTime(const std::wstring& wmiDateTime) {
    // WMI CIM_DATETIME format: yyyymmddHHMMSS.mmmmmmsUUU
    if (wmiDateTime.length() < 14) return wmiDateTime;

    std::wstring year = wmiDateTime.substr(0, 4);
    std::wstring month = wmiDateTime.substr(4, 2);
    std::wstring day = wmiDateTime.substr(6, 2);
    std::wstring hour = wmiDateTime.substr(8, 2);
    std::wstring minute = wmiDateTime.substr(10, 2);
    std::wstring second = wmiDateTime.substr(12, 2);

    return year + L"-" + month + L"-" + day + L" " + hour + L":" + minute + L":" + second;
}

// Table renderer for clean aligned CLI output
enum class OutputFormat {
    Table,
    Csv,
    Json
};

struct OutputOptions {
    OutputFormat format = OutputFormat::Table;
    bool noHeader = false;
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

std::wstring EscapeJson(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size());

    for (wchar_t ch : input) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'\"': out += L"\\\""; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default: out += ch; break;
        }
    }

    return out;
}

std::wstring EscapeCsv(const std::wstring& input) {
    bool needsQuotes = input.find_first_of(L",\"\n\r") != std::wstring::npos;
    if (!needsQuotes) return input;

    std::wstring out = L"\"";
    for (wchar_t ch : input) {
        if (ch == L'\"') out += L"\"\"";
        else out += ch;
    }
    out += L"\"";
    return out;
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

struct WmiSecurityConfig {
    LONG authnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    LONG impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
};

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

    if (value == L"default") {
        config.authnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
        config.impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        return true;
    }

    if (value == L"connect") {
        config.authnLevel = RPC_C_AUTHN_LEVEL_CONNECT;
        config.impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        return true;
    }

    if (value == L"call") {
        config.authnLevel = RPC_C_AUTHN_LEVEL_CALL;
        config.impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        return true;
    }

    if (value == L"pkt") {
        config.authnLevel = RPC_C_AUTHN_LEVEL_PKT;
        config.impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        return true;
    }

    if (value == L"pktprivacy") {
        config.authnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        config.impLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        return true;
    }

    return false;
}

bool TryParseOutputFormat(const std::wstring& input, OutputFormat& format) {
    std::wstring value = input;
    std::transform(value.begin(), value.end(), value.begin(), towlower);

    if (value == L"table") {
        format = OutputFormat::Table;
        return true;
    }
    if (value == L"csv") {
        format = OutputFormat::Csv;
        return true;
    }
    if (value == L"json") {
        format = OutputFormat::Json;
        return true;
    }

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

std::wstring GetWindowsActivationStatus(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return L"N/A";
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return L"N/A";
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return L"N/A";
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return L"N/A";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (FAILED(hr) || uReturn == 0) {
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
    pLoc->Release();
    CoUninitialize();

    return status;
}

bool ExecuteOSInfoQuery(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Caption, Version, OSArchitecture, NumberOfUsers, InstallDate FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
        pLoc->Release();
        CoUninitialize();
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
    std::wstring activationStatus = GetWindowsActivationStatus(wmiLocale, securityConfig);

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
            L"Caption",
            L"Version",
            L"OS Architecture",
            L"Number of Users",
            L"Install Date",
            L"Activation Status"
        };
        table.rows.push_back({
            caption,
            version,
            architecture,
            numberOfUsers,
            installDate,
            activationStatus
        });
    }

    table.Print();

    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return true;
}

bool ExecuteSystemInfoQuery(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    auto querySingleRow = [&](const std::wstring& wqlQuery, const std::vector<std::wstring>& props, std::vector<std::wstring>& outValues) -> bool {
        IEnumWbemClassObject* pEnumerator = NULL;
        HRESULT qhr = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(wqlQuery.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(qhr)) {
            return false;
        }

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
    pLoc->Release();
    CoUninitialize();

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

bool ExecuteCpuInfoQuery(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, LoadPercentage FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
    pLoc->Release();
    CoUninitialize();

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
                cpuLabel,
                records[i].name,
                records[i].numberOfCores,
                records[i].logicalProcessors,
                records[i].maxClockMhz,
                records[i].loadPercentage
            });
        }
    }

    table.Print();
    return true;
}

bool ExecuteNetInfoQuery(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
    pLoc->Release();
    CoUninitialize();

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

bool ExecuteDevicesInfoQuery(const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Name, PNPClass, Manufacturer, Status FROM Win32_PnPEntity"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
    pLoc->Release();
    CoUninitialize();

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

std::wstring HResultToHex(HRESULT hr) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << static_cast<unsigned long>(hr);
    return ss.str();
}

bool ProbeWmiSecurityLevel(const WmiSecurityConfig& securityConfig, const std::wstring& wmiLocale, std::wstring& details) {
    HRESULT hrInit = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
        details = L"COM init failed (" + HResultToHex(hrInit) + L")";
        return false;
    }
    bool comInitialized = SUCCEEDED(hrInit);

    HRESULT hrSec = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    if (FAILED(hrSec) && hrSec != RPC_E_TOO_LATE) {
        details = L"CoInitializeSecurity failed (" + HResultToHex(hrSec) + L")";
        if (comInitialized) CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        details = L"WMI locator failed (" + HResultToHex(hr) + L")";
        if (comInitialized) CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }

    if (FAILED(hr)) {
        details = L"ConnectServer failed (" + HResultToHex(hr) + L")";
        pLoc->Release();
        if (comInitialized) CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        details = L"CoSetProxyBlanket failed (" + HResultToHex(hr) + L")";
        pSvc->Release();
        pLoc->Release();
        if (comInitialized) CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(L"SELECT Caption FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        details = L"WMI probe query failed (" + HResultToHex(hr) + L")";
        pSvc->Release();
        pLoc->Release();
        if (comInitialized) CoUninitialize();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    bool available = SUCCEEDED(hr) && uReturn > 0;

    if (available) {
        details = (hrSec == RPC_E_TOO_LATE) ? L"Available (process security already initialized)" : L"Available";
        pclsObj->Release();
    } else {
        details = L"Probe returned no data (" + HResultToHex(hr) + L")";
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    if (comInitialized) CoUninitialize();

    return available;
}

void PrintWmiSecurityAvailability(const std::wstring& wmiLocale) {
    std::vector<std::wstring> levels = { L"default", L"connect", L"call", L"pkt", L"pktprivacy" };

    Table table;
    table.headers = { L"Security Level", L"Status", L"Details" };

    for (const auto& level : levels) {
        WmiSecurityConfig cfg;
        TryParseWmiSecurity(level, cfg);

        std::wstring details;
        bool ok = ProbeWmiSecurityLevel(cfg, wmiLocale, details);
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
    if (FAILED(hr) || pInDef == NULL) {
        return L"";
    }

    IWbemClassObject* pInParams = NULL;
    hr = pInDef->SpawnInstance(0, &pInParams);
    pInDef->Release();
    if (FAILED(hr) || pInParams == NULL) {
        return L"";
    }

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
    if (FAILED(hr) || pOutParams == NULL) {
        return L"";
    }

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

bool PrintInstalledAppsByArchitecture(bool showWin32Apps, const std::wstring& wmiLocale, const WmiSecurityConfig& securityConfig) {
    g_lastNoData = false;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pRegClass = NULL;
    hr = pSvc->GetObject(_bstr_t(L"StdRegProv"), 0, NULL, &pRegClass, NULL);
    if (FAILED(hr) || pRegClass == NULL) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pInDef = NULL;
    hr = pRegClass->GetMethod(L"EnumKey", 0, &pInDef, NULL);
    if (FAILED(hr) || pInDef == NULL) {
        pRegClass->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pInParams = NULL;
    hr = pInDef->SpawnInstance(0, &pInParams);
    pInDef->Release();
    if (FAILED(hr) || pInParams == NULL) {
        pRegClass->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
        pLoc->Release();
        CoUninitialize();
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
        pLoc->Release();
        CoUninitialize();
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
    pLoc->Release();
    CoUninitialize();

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
    const std::wstring& sectionTitle,
    const std::wstring& wqlQuery,
    const std::vector<std::pair<std::wstring, std::wstring>>& switches,
    const std::wstring& wmiLocale = L"",
    const WmiSecurityConfig& securityConfig = WmiSecurityConfig()
) {
    g_lastNoData = false;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IWbemContext* pCtx = NULL;
    if (!wmiLocale.empty()) {
        hr = CoCreateInstance(CLSID_WbemContext, 0, CLSCTX_INPROC_SERVER, IID_IWbemContext, (LPVOID*)&pCtx);
        if (SUCCEEDED(hr) && pCtx != NULL) {
            VARIANT vtLocale;
            VariantInit(&vtLocale);
            V_VT(&vtLocale) = VT_BSTR;
            V_BSTR(&vtLocale) = SysAllocString(wmiLocale.c_str());
            if (V_BSTR(&vtLocale) != NULL) {
                pCtx->SetValue(L"__Locale", 0, &vtLocale);
            }
            VariantClear(&vtLocale);
        } else {
            pCtx = NULL;
        }
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wqlQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        pCtx,
        &pEnumerator
    );

    if (FAILED(hr)) {
        std::wcerr << L"[!] WMI Query execution failed." << std::endl;
        if (pCtx) pCtx->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
        if (pCtx) pCtx->Release();
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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
    if (pCtx) pCtx->Release();
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return true;
}

// Main WMI Query Execution Core
bool ExecuteWMIQuery(
    const std::wstring& wqlQuery,
    const std::vector<std::wstring>& properties,
    bool autoByteFormat = true,
    const std::wstring& wmiLocale = L"",
    const std::vector<std::wstring>& displayHeaders = {},
    const WmiSecurityConfig& securityConfig = WmiSecurityConfig()
) {
    g_lastNoData = false;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"[!] COM Initialization failed." << std::endl;
        return false;
    }

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    if (wmiLocale.empty()) {
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    } else {
        _bstr_t localeBstr(wmiLocale.c_str());
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, localeBstr, NULL, 0, 0, &pSvc);
    }
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        securityConfig.authnLevel,
        securityConfig.impLevel,
        NULL,
        EOAC_NONE
    );

    IWbemContext* pCtx = NULL;
    if (!wmiLocale.empty()) {
        hr = CoCreateInstance(CLSID_WbemContext, 0, CLSCTX_INPROC_SERVER, IID_IWbemContext, (LPVOID*)&pCtx);
        if (SUCCEEDED(hr) && pCtx != NULL) {
            VARIANT vtLocale;
            VariantInit(&vtLocale);
            V_VT(&vtLocale) = VT_BSTR;
            V_BSTR(&vtLocale) = SysAllocString(wmiLocale.c_str());
            if (V_BSTR(&vtLocale) != NULL) {
                pCtx->SetValue(L"__Locale", 0, &vtLocale);
            }
            VariantClear(&vtLocale);
        } else {
            pCtx = NULL;
        }
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(wqlQuery.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, pCtx, &pEnumerator);

    if (FAILED(hr)) {
        std::wcerr << L"[!] WMI Query execution failed." << std::endl;
        if (pCtx) pCtx->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
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

                if (prop == L"InstallDate") {
                    val = FormatWmiDateTime(val);
                }

                if (prop == L"LicenseStatus") {
                    val = MapLicenseStatusCode(val);
                }
                
                // Format sizes if property is capacity/memory/size related
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

    if (pCtx) pCtx->Release();
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return true;
}

// Fast API status check for RAM
void FastRamStatus() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        std::wcout << L"\n--- System Memory Summary ---" << std::endl;
        std::wcout << L"RAM Load:            " << memInfo.dwMemoryLoad << L"%" << std::endl;
        std::wcout << L"Total Physical:      " << FormatBytes(memInfo.ullTotalPhys) << std::endl;
        std::wcout << L"Available Physical:  " << FormatBytes(memInfo.ullAvailPhys) << std::endl;
    }
}

void PrintHelp() {
    std::wcout << L"\n" 
              << L"xmic - Windows System Information & Monitoring Tool using WMI\n"
              << L"Version: 1.0.0\n\n"
              << L"Copyright (c) 2026, Roberto J. Dohnert\n"
              << L"Licensed under the BSD-3 Clause License\n\n"
              << L"Commands:\n"
              << L"Usage: xmic [--locale <WMI_LOCALE>] [--wmi-security <LEVEL>] [--format <FMT>] [--no-header] <command> [arguments]\n\n"
              << L"Global options:\n"
              << L"  --locale <WMI_LOCALE>         Set WMI locale (example: MS_409 for en-US)\n"
              << L"  --wmi-security <LEVEL>        Set WMI COM security level\n"
              << L"                                Values: default, connect, call, pkt, pktprivacy\n"
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
              << L"  users     - Local user accounts\n"
              << L"  help      - Show this help message\n\n"
              << L"Help options:\n"
              << L"  help | --help | -h\n\n"
              << L"Custom WQL Query Mode:\n"
              << L"  query \"<WQL_QUERY>\" <PROP1> [PROP2 ...]\n"
              << L"  Example: xmic query \"SELECT Name, State FROM Win32_Service WHERE State='Running'\" Name State\n"
              << L"  Example with locale: xmic --locale MS_409 query \"SELECT Caption FROM Win32_OperatingSystem\" Caption\n"
              << L"  Example with WMI security: xmic --wmi-security pktprivacy os\n"
              << L"  Example in JSON: xmic --format json os\n"
              << L"  Example CSV no headers: xmic --format csv --no-header process\n\n"
              << L"Deterministic Exit Codes:\n"
              << L"  0 = success\n"
              << L"  2 = invalid arguments/options\n"
              << L"  3 = unknown command\n"
              << L"  4 = WMI/runtime failure\n"
              << L"  5 = no data returned\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    int argIndex = 1;
    std::wstring wmiLocale;
    WmiSecurityConfig securityConfig;
    bool noHeader = false;
    OutputFormat outputFormat = OutputFormat::Table;

    while (argIndex < argc) {
        std::wstring option = argv[argIndex];

        if (option == L"--locale") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --locale." << std::endl;
                PrintHelp();
                return 1;
            }
            wmiLocale = argv[argIndex + 1];
            argIndex += 2;
            continue;
        }

        if (option == L"--wmi-security") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --wmi-security." << std::endl;
                PrintHelp();
                return 1;
            }

            if (!TryParseWmiSecurity(argv[argIndex + 1], securityConfig)) {
                std::wcerr << L"[!] Invalid --wmi-security value. Use: default, connect, call, pkt, pktprivacy." << std::endl;
                return 1;
            }

            argIndex += 2;
            continue;
        }

        if (option == L"--format") {
            if (argIndex + 1 >= argc) {
                std::wcerr << L"[!] Missing value for --format." << std::endl;
                PrintHelp();
                return EXIT_BAD_ARGS;
            }

            if (!TryParseOutputFormat(argv[argIndex + 1], outputFormat)) {
                std::wcerr << L"[!] Invalid --format value. Use: table, csv, json." << std::endl;
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

        break;
    }

    g_outputOptions.format = outputFormat;
    g_outputOptions.noHeader = noHeader;

    if (argIndex >= argc) {
        PrintHelp();
        return EXIT_BAD_ARGS;
    }

    std::wstring cmd = argv[argIndex];

    if (cmd == L"help" || cmd == L"--help" || cmd == L"-h") {
        PrintHelp();
        return EXIT_OK;
    }

    bool success = true;

    if (cmd == L"os") {
        success = ExecuteOSInfoQuery(wmiLocale, securityConfig);
    } 
    else if (cmd == L"cpu") {
        success = ExecuteCpuInfoQuery(wmiLocale, securityConfig);
    } 
    else if (cmd == L"ram") {
        FastRamStatus();
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nHardware Slots:" << std::endl;
        }
        success = ExecuteWMIQuery(
            L"SELECT DeviceLocator, Capacity, Speed, Manufacturer FROM Win32_PhysicalMemory",
            { L"DeviceLocator", L"Capacity", L"Speed", L"Manufacturer" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    } 
    else if (cmd == L"disk") {
        success = ExecuteWMIQuery(
            L"SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3",
            { L"DeviceID", L"VolumeName", L"FileSystem", L"Size", L"FreeSpace" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    } 
    else if (cmd == L"extdisk" || cmd == L"external") {
        success = ExecuteWMIQuery(
            L"SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace, DriveType FROM Win32_LogicalDisk WHERE DriveType=2",
            { L"DeviceID", L"VolumeName", L"FileSystem", L"Size", L"FreeSpace", L"DriveType" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"net") {
        success = ExecuteNetInfoQuery(wmiLocale, securityConfig);
    } 
    else if (cmd == L"gpu") {
        success = ExecuteWMIQuery(
            L"SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController",
            { L"Name", L"DriverVersion", L"AdapterRAM" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"bios" || cmd == L"firmware") {
        success = ExecuteWMIQuery(
            L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS",
            { L"Manufacturer", L"SMBIOSBIOSVersion", L"ReleaseDate", L"SerialNumber" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"gswitch" || cmd == L"globalswitch") {
        success = ExecuteWMISwitchStateQuery(
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
            wmiLocale,
            securityConfig
        );

        success = ExecuteWMISwitchStateQuery(
            L"System Global Switches",
            L"SELECT AutomaticManagedPagefile, AutomaticResetBootOption, AutomaticResetCapability, HypervisorPresent FROM Win32_ComputerSystem",
            {
                { L"AutomaticManagedPagefile", L"Auto Managed Pagefile" },
                { L"AutomaticResetBootOption", L"Auto Reset Boot Option" },
                { L"AutomaticResetCapability", L"Auto Reset Capability" },
                { L"HypervisorPresent", L"Hypervisor Present" }
            },
            wmiLocale,
            securityConfig
        );
    }
    else if (cmd == L"security" || cmd == L"wmisecurity") {
        PrintWmiSecurityAvailability(wmiLocale);
        success = true;
    }
    else if (cmd == L"context" || cmd == L"wmiccontext" || cmd == L"wmic") {
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nWMIC Context Summary:" << std::endl;
        }
        success = ExecuteWMIQuery(
            L"SELECT CSName, Caption, Version, OSArchitecture, LocalDateTime, LastBootUpTime FROM Win32_OperatingSystem",
            { L"CSName", L"Caption", L"Version", L"OSArchitecture", L"LocalDateTime", L"LastBootUpTime" },
            false,
            wmiLocale,
            {},
            securityConfig
        );

        success = ExecuteWMIQuery(
            L"SELECT Domain, PartOfDomain, UserName FROM Win32_ComputerSystem",
            { L"Domain", L"PartOfDomain", L"UserName" },
            false,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"qfe") {
        success = ExecuteWMIQuery(
            L"SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering",
            { L"HotFixID", L"Description", L"InstalledOn", L"InstalledBy" },
            false,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"port" || cmd == L"ports") {
        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"\nSerial and Logical Ports:" << std::endl;
        }
        success = ExecuteWMIQuery(
            L"SELECT DeviceID, Name, Description, Status, MaxBaudRate FROM Win32_SerialPort",
            { L"DeviceID", L"Name", L"Description", L"Status", L"MaxBaudRate" },
            false,
            wmiLocale,
            { L"Port", L"Name", L"Description", L"Status", L"Max Baud" },
            securityConfig
        );

        if (g_outputOptions.format == OutputFormat::Table) {
            std::wcout << L"Physical Port Connectors:" << std::endl;
        }
        success = ExecuteWMIQuery(
            L"SELECT Tag, PortType, ExternalReferenceDesignator, InternalReferenceDesignator FROM Win32_PortConnector",
            { L"Tag", L"PortType", L"ExternalReferenceDesignator", L"InternalReferenceDesignator" },
            false,
            wmiLocale,
            { L"Tag", L"Port Type", L"External Ref", L"Internal Ref" },
            securityConfig
        );
    }
    else if (cmd == L"sys") {
        success = ExecuteSystemInfoQuery(wmiLocale, securityConfig);
    }
    else if (cmd == L"process") {
        success = ExecuteWMIQuery(
            L"SELECT ProcessId, Name, WorkingSetSize FROM Win32_Process",
            { L"ProcessId", L"Name", L"WorkingSetSize" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    } 
    else if (cmd == L"service") {
        success = ExecuteWMIQuery(
            L"SELECT Name, DisplayName, State, StartMode FROM Win32_Service WHERE State='Running'",
            { L"Name", L"DisplayName", L"State", L"StartMode" },
            true,
            wmiLocale,
            {},
            securityConfig
        );
    } 
    else if (cmd == L"ntevent" || cmd == L"event") {
        success = ExecuteWMIQuery(
            L"SELECT Logfile, EventCode, Type, SourceName, TimeGenerated FROM Win32_NTLogEvent WHERE Logfile='System' AND (Type='Error' OR Type='Warning')",
            { L"Logfile", L"EventCode", L"Type", L"SourceName", L"TimeGenerated" },
            false,
            wmiLocale,
            {},
            securityConfig
        );
    }
    else if (cmd == L"apps") {
        success = ExecuteWMIQuery(
            L"SELECT Name, Version, Vendor, InstallDate FROM Win32_Product",
            { L"Name", L"Version", L"Vendor", L"InstallDate" }, false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"apps32" || cmd == L"win32apps") {
        success = PrintInstalledAppsByArchitecture(true, wmiLocale, securityConfig);
    }
    else if (cmd == L"apps64" || cmd == L"win64apps") {
        success = PrintInstalledAppsByArchitecture(false, wmiLocale, securityConfig);
    }
    else if (cmd == L"devices" || cmd == L"device") {
        success = ExecuteDevicesInfoQuery(wmiLocale, securityConfig);
    }
    else if (cmd == L"users") {
        success = ExecuteWMIQuery(
            L"SELECT Name, FullName, Disabled, LocalAccount, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=TRUE",
            { L"Name", L"FullName", L"Disabled", L"LocalAccount", L"PasswordRequired" }, false, wmiLocale, {}, securityConfig
        );
    }
    else if (cmd == L"query" && argc >= argIndex + 3) {
        std::wstring query = argv[argIndex + 1];
        std::vector<std::wstring> props;
        for (int i = argIndex + 2; i < argc; ++i) {
            props.push_back(argv[i]);
        }
        success = ExecuteWMIQuery(query, props, false, wmiLocale, {}, securityConfig);
    } 
    else if (cmd == L"query") {
        std::wcerr << L"[!] Missing query text or property list for query command." << std::endl;
        return EXIT_BAD_ARGS;
    }
    else {
        std::wcerr << L"[!] Unknown command: " << cmd << std::endl;
        return EXIT_UNKNOWN_COMMAND;
    }

    if (!success) {
        if (g_lastNoData) return EXIT_NO_DATA;
        return EXIT_WMI_FAILURE;
    }
    if (g_lastNoData) return EXIT_NO_DATA;
    return EXIT_OK;
}