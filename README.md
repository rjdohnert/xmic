<img width="198" height="197" alt="xmic" src="https://github.com/user-attachments/assets/bbef0631-578b-4786-b3e7-3818d40d4404" />

# XMIC v2.2.0

XMIC is a Windows Management Instrumentation (WMI) command-line tool designed as a modern replacement for `wmic`.

It provides quick system diagnostics, hardware inventory, process/service insights, update information, and custom WQL query support.

`XMIC` can be used as an installable application or as a portable binary.

## Features

- Native Windows COM/WMI implementation
- Preset system information commands (`os`, `cpu`, `ram`, `disk`, `net`, etc.)
- WMI security capability check (`security`)
- Installed app views:
  - `apps` (Win32_Product)
  - `apps32` (32-bit uninstall registry branch via WMI `StdRegProv`)
  - `apps64` (64-bit uninstall registry branch via WMI `StdRegProv`)
- Script mode output:
  - `--format table|csv|json`
  - `--no-header`
- Deterministic exit codes for automation

## Requirements

- Windows Server 2025/2022 Windows 11 Pro/Home/Enterprise
- WMI service available

## Build

From the project directory:

```powershell
cl.exe /Zi /EHsc /nologo /Fe:xmic.exe xmic.cpp
```
`Visual Studio Code` with the `Visual Studio Build Tools 2026`

You can use the Microsoft C++ extension which activates the compiler
Or use the default VS Code build task (`Build xmic.cpp`) from Developer Command Prompt.

## Usage

```text
xmic [--node <HOST>] [--user <USER>] [--password <PASS> | --prompt-password | --prompt-password-confirm] [--domain <DOMAIN>] [--namespace <WMI_NAMESPACE>] [--console-encoding <MODE>] [--locale <WMI_LOCALE>] [--wmi-security <LEVEL>] [--format <FMT>] [--no-header] <command> [arguments]
```
More information is available in the manual.md file which explains the program in more detail

## History

I loved WMIC.  I hated to see it go.  I wrote my own implementation as best as I could.

## Install

- You can run this from any directory using Windows Terminal or Console Host
- You can install system wide for any user by copying the .exe to the system32\ folder
C:\windows\system32 you will be prompted for admin privileges (Installer coming soon)

### Global Options

- `--locale <WMI_LOCALE>`: Set WMI locale (example: `MS_409`)
- `--wmi-security <LEVEL>`: WMI COM security level (`default`, `connect`, `call`, `pkt`, `pktprivacy`)
- `--format <FMT>`: Output format (`table`, `csv`, `json`)
- `--no-header`: Hide header row in table/csv output
- `--node <HOST>`: Execute command against a remote target host
- `--user <USER>`: Remote authentication username
- `--password <PASS>`: Remote authentication password
- `--prompt-password`: Prompt for remote password with hidden input (avoids command-line leakage)
- `--prompt-password-confirm`: Prompt for password twice and require match before remote authentication
- `--domain <DOMAIN>`: Remote domain for authentication context
- `--namespace <WMI_NAMESPACE>`: Namespace override for `query` and `path` command operations
- `--console-encoding <MODE>`: Console output mode (`utf16` or `utf8`)

### Examples

```powershell
xmic os
xmic --format json cpu
xmic --format csv --no-header process
xmic --wmi-security pktprivacy security
xmic --node SRV-01 process
xmic --node SRV-01 --user Administrator --prompt-password process
xmic --node SRV-01 --user Administrator --prompt-password-confirm process
xmic --namespace ROOT\CIMV2 path Win32_Process where "Name='notepad.exe'" get Name,ProcessId
xmic query "SELECT Name, State FROM Win32_Service" Name State
```

## Exit Codes

- `0` = Success
- `2` = Invalid arguments/options
- `3` = Unknown command
- `4` = WMI/runtime failure
- `5` = No data returned

## License

BSD 3-Clause. See [license.txt](license.txt).
