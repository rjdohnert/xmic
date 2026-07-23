
`XMIC DOCUMENTATION & MANUAL` Windows Management Instrumentation Command-Line Tool 
- Copyright (C) 2026, Roberto J Dohnert 
- Licensed under the terms of the BSD-3 Clause License

------------------------------------------------------------------------------
1. OVERVIEW
-------------------------------------------------------------------------------
`xmic` is a high-performance WMI query utility designed to replace the 
deprecated Microsoft WMIC utility. Built natively on Windows COM/WMI APIs, 
it gathers system diagnostics, hardware info, and runtime metrics without 
heavy dependencies or framework overhead.

Key Features:
 - Dynamic auto-aligned table layout for all console outputs.
 - Automatic size formatting (Converts raw bytes into KB, MB, GB).
 - Native SafeArray parsing (Handles multi-value properties like IP addresses).
 - Sub-second startup time and tiny memory footprint.
 - Generic WQL query engine for custom WMI database queries.

Command Alias Quick List:

| Command | Alias(es)     | Purpose (Short)                         |
|---------|---------------|------------------------------------------|
| extdisk | external      | External/removable storage devices       |
| ntevent | event         | NT System event log warnings/errors      |
| bios    | firmware      | BIOS details (vendor/version/date/serial)|
| gswitch | globalswitch  | Global Windows switch states             |
| security | wmisecurity  | WMI COM security capability check        |
| context | wmic, context | WMIC-style host/context summary       |
| qfe     | (none)        | Installed update HotFix IDs              |
| port    | ports         | Physical and serial port information      |
| apps32  | win32apps     | Installed Win32 applications              |
| apps64  | win64apps     | Installed Win64 applications              |
| devices | device        | Installed Plug-and-Play devices           |
| help    | --help, -h    | Show command usage and options           |


2. COMPILATION & SETUP
-------------------------------------------------------------------------------
1. Created using `Visual Studio Code` and the `Visual Studio Build Tools 2026`.
2. Will be included as a module in `CrossShellBSD` as well as standalone.
3. `xmic.exe` can be setup with the installer in the system32\ folder or run as
a portable application.


3. HOW TO EXECUTE
-------------------------------------------------------------------------------
Open Command Prompt (cmd.exe) or Windows Termina;, navigate to the folder containing 
xmic.exe, and run:

    xmic [--locale <WMI_LOCALE>] [--wmi-security <LEVEL>] [--format <FMT>] [--no-header] <command> [arguments]

Optional global locale override:

    --locale <WMI_LOCALE>

Optional WMI COM security level override:

    --wmi-security <LEVEL>

Allowed LEVEL values:

    default
    connect
    call
    pkt
    pktprivacy

Optional output format override (script mode):

    --format <FMT>

Allowed FMT values:

    table
    csv
    json

Optional header suppression:

    --no-header

Example locale values:

    MS_409   (English - United States)
    MS_40C   (French - France)

Quick example:

    xmic gswitch

Quick example using explicit WMI security:

    xmic --wmi-security pktprivacy os

Quick script mode examples:

    xmic --format json os
    xmic --format csv --no-header process

To view quick inline help inside the command line, run:

    xmic
  OR
    xmic help
    OR
        xmic --help
    OR
        xmic -h


4. BUILT-IN COMMAND REFERENCE & EXAMPLES
-------------------------------------------------------------------------------

[ COMMAND ]     [ PURPOSE & EXAMPLE ]
-------------------------------------------------------------------------------

os              Displays Operating System details (Edition, Version,
                Architecture, Registered Users, Install Date, and
                Activation Status).
                
                Example:
                    xmic os

-------------------------------------------------------------------------------

cpu             Displays CPU processor specifications, physical core count,
                logical thread count, clock speed, and current utilization %.
                
                Example:
                    xmic cpu

-------------------------------------------------------------------------------

ram             Displays real-time system memory usage summary (RAM load, total, 
                and free capacity) followed by a physical RAM stick hardware report.
                
                Example:
                    xmic ram

-------------------------------------------------------------------------------

disk            Displays physical/logical storage drive letters, volume labels,
                file system type, total capacity, and available free space.
                
                Example:
                    xmic disk

-------------------------------------------------------------------------------

extdisk         Displays external/removable storage devices (for example USB
                removable drives), including drive letter, file system, total
                size, and free space.
                Alias: external

                Example:
                    xmic extdisk

-------------------------------------------------------------------------------

net             Displays enabled network interface adapters, physical MAC 
                addresses, and active IPv4/IPv6 addresses.
                
                Example:
                    xmic net

-------------------------------------------------------------------------------

gpu             Displays active graphics card controllers, installed driver 
                versions, and onboard VRAM size.
                
                Example:
                    xmic gpu

-------------------------------------------------------------------------------

bios            Displays BIOS manufacturer, SMBIOS version, release date,
                and system serial number.
                Alias: firmware

                Example:
                    xmic bios

-------------------------------------------------------------------------------

gswitch         Displays the state of global Windows switch-style settings
                (DEP, PAE, debug/distributed/portable flags, and selected
                system-wide auto-switches).
                Alias: globalswitch

                Example:
                    xmic gswitch

-------------------------------------------------------------------------------

security        Probes WMI COM security authentication levels and reports
                which levels are available for command execution on
                this system.
                Alias: wmisecurity

                Example:
                    xmic security

                Example with locale:
                    xmic --locale MS_409 security

-------------------------------------------------------------------------------

context         Displays a WMIC-style context summary including computer name,
                OS version/architecture, local time, last boot time, domain,
                and current user context.
                Aliases: wmic, context

                Example:
                    xmic context

-------------------------------------------------------------------------------

qfe             Lists installed Windows updates (Quick Fix Engineering),
                including HotFixID, description, install date, and installer.

                Example:
                    xmic qfe

-------------------------------------------------------------------------------

port            Displays serial/logical ports and physical port connector
                information discovered by WMI.
                Alias: ports

                Example:
                    xmic port

-------------------------------------------------------------------------------

sys             Displays system hardware model, motherboard manufacturer, 
                architecture type, BIOS version, and motherboard serial number.
                
                Example:
                    xmic sys

-------------------------------------------------------------------------------

process         Lists all active running processes, Process IDs (PID), and 
                their RAM memory working set footprint.
                
                Example:
                    xmic process

-------------------------------------------------------------------------------

service         Lists active running Windows Services, display names, and 
                their startup configurations.
                
                Example:
                    xmic service

---------------------------------------------------------------------------------

ntevent         Lists Windows NT System event log warnings and errors using
                WMI (log name, event code, type, source, and generated time).
                Alias: event

                Example:
                    xmic ntevent

---------------------------------------------------------------------------------

users           Lists active system user accounts, display names, and 
                password status.
                
                Example:
                    xmic users

---------------------------------------------------------------------------------

apps           Lists all installed applications, display vendors, and 
               version numbers.
               Note:  Query may take longer depending on number of apps 
               installed
                
                Example:
                    xmic apps

---------------------------------------------------------------------------------

apps32         Lists installed Win32 applications from the 32-bit
               uninstall registry branch through the WMI StdRegProv object.
               Alias: win32apps

               Example:
                   xmic apps32

---------------------------------------------------------------------------------

apps64         Lists installed Win64 applications from the 64-bit
               uninstall registry branch through the WMI StdRegProv object.
               Alias: win64apps

               Example:
                   xmic apps64

---------------------------------------------------------------------------------

devices        Lists installed Plug-and-Play devices discovered by WMI,
               including device name, class, manufacturer, and status.
               Alias: device

               Example:
                   xmic devices

---------------------------------------------------------------------------------

help           Displays command usage and available options.
               Aliases: --help, -h

               Example:
                   xmic help

5. CUSTOM WQL QUERY MODE
-------------------------------------------------------------------------------
`xmic` includes a general-purpose WQL engine that lets you run custom queries 
against any WMI class in `ROOT\CIMV2`.

SYNTAX:
    xmic [--locale <WMI_LOCALE>] [--wmi-security <LEVEL>] [--format <FMT>] [--no-header] query "<WQL_STATEMENT>" <PROP_NAME_1> [PROP_NAME_2 ...]

EXAMPLES:

1. Query specific stopped services:
   xmic query "SELECT Name, DisplayName FROM Win32_Service WHERE State='Stopped'" Name DisplayName

2. Query system motherboard manufacturer and BIOS details:
   xmic query "SELECT Manufacturer, Name, Version FROM Win32_BIOS" Manufacturer Name Version

3. Query startup programs registered on Windows:
   xmic query "SELECT Name, Command, User FROM Win32_StartupCommand" Name Command User

4. Query audio/sound device details:
   xmic query "SELECT Name, Status, Manufacturer FROM Win32_SoundDevice" Name Status Manufacturer

5. Query Windows Environment Variables:
   xmic query "SELECT Name, VariableValue FROM Win32_Environment WHERE SystemVariable=TRUE" Name VariableValue

6. Force query execution with a specific WMI locale:
    xmic --locale MS_409 query "SELECT Caption FROM Win32_OperatingSystem" Caption

7. Force query execution with strict packet privacy security:
    xmic --wmi-security pktprivacy query "SELECT Caption FROM Win32_OperatingSystem" Caption

8. Export query output as JSON:
    xmic --format json query "SELECT Name, ProcessId FROM Win32_Process" Name ProcessId

9. Export query output as CSV without headers:
    xmic --format csv --no-header query "SELECT Name, State FROM Win32_Service" Name State


6. TIPS FOR SCRIPTING & INTEGRATION
-------------------------------------------------------------------------------

1. EXPORT OUTPUT TO A FILE:
   Save hardware or process reports to text or log files using output redirection:
       xmic os > system_report.txt
       xmic process >> system_report.txt

2. FILTER OUTPUT USING FINDSTR:
   Search for specific processes, services, or drives:
       xmic process | findstr /I "chrome"
       xmic service | findstr /I "Running"

3. BATCH SCRIPT INTEGRATION:
   Include xmic directly in your automated maintenance scripts or diagnostics:
       @echo off
       echo --- RUNNING DIAGNOSTICS ---
       xmic os
       xmic ram
       xmic disk
       pause

4. DETERMINISTIC EXIT CODES:
   xmic returns stable numeric exit codes for script handling:
       0 = success
       2 = invalid arguments/options
       3 = unknown command
       4 = WMI/runtime failure
       5 = no data returned

===============================================================================
