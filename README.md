# xmic

xmic is a Windows Management Instrumentation (WMI) command-line tool designed as a modern replacement for `wmic`.

It provides quick system diagnostics, hardware inventory, process/service insights, update information, and custom WQL query support.

It will be made part of the CrossShellBSD kit but will also be a standalone option

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
xmic [--locale <WMI_LOCALE>] [--wmi-security <LEVEL>] [--format <FMT>] [--no-header] <command> [arguments]
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

### Examples

```powershell
xmic os
xmic --format json cpu
xmic --format csv --no-header process
xmic --wmi-security pktprivacy security
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
