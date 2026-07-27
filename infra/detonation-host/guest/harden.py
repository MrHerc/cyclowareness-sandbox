"""Silence the guest's own network chatter.

A detonation sandbox's network capture is only evidence if the baseline is
near-empty. Windows 10 idle contacts Azure AD, MSA sign-in, NCSI, Edge update,
Delivery Optimization and telemetry - and it does so from rotating CDN and
anycast pools, so subtracting observed IPs afterwards does not work: the same
service reappears on a neighbouring address every run. The fix is upstream -
stop the traffic being generated.
"""
import subprocess

def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, shell=False)
    return p.returncode

SERVICES = [
    "DiagTrack",          # Connected User Experiences and Telemetry
    "dmwappushservice",   # WAP push message routing (telemetry transport)
    "DoSvc",              # Delivery Optimization - peer/CDN content
    "WerSvc",             # Windows Error Reporting
    "wlidsvc",            # Microsoft Account sign-in -> login.live.com / MSA pools
    "MapsBroker",         # Downloaded maps manager
    "WSearch",            # Indexer: disk noise, no analytic value
    "edgeupdate", "edgeupdatem",
    "OneSyncSvc", "CDPUserSvc", "CDPSvc",
    "RetailDemo",
    "PcaSvc",             # Program Compatibility Assistant telemetry
]
for svc in SERVICES:
    run("sc", "stop", svc)
    run("sc", "config", svc, "start=", "disabled")

REG = [
    # Stop the active connectivity probe (www.msftconnecttest.com) outright.
    (r"HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet",
     "EnableActiveProbing", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
     "DoNotShowFeedbackNotifications", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
     "DisableWindowsConsumerFeatures", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
     "DisableSoftLanding", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore", "AutoDownload", "2"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
     "DODownloadMode", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
     "Disabled", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Update", "UpdateDefault", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", "0"),
    # No automatic time sync chatter; the clock CAPE sets is what we want anyway.
    (r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type", "NoSync"),
]
for key, name, val in REG:
    t = "REG_SZ" if not val.isdigit() else "REG_DWORD"
    run("reg", "add", key, "/v", name, "/t", t, "/d", val, "/f")

TASKS = [
    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    r"\Microsoft\Windows\Feedback\Siuf\DmClient",
    r"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
    r"\Microsoft\Windows\Maps\MapsUpdateTask",
    r"\Microsoft\Windows\Maps\MapsToastTask",
    r"\MicrosoftEdgeUpdateTaskMachineCore",
    r"\MicrosoftEdgeUpdateTaskMachineUA",
]
for t in TASKS:
    run("schtasks", "/change", "/tn", t, "/disable")

# OneDrive's per-user autostart.
run("reg", "delete", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "/v", "OneDriveSetup", "/f")
run("reg", "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    "/v", "DisableFileSyncNGSC", "/t", "REG_DWORD", "/d", "1", "/f")

with open(r"C:\hardened.txt", "w") as fh:
    fh.write("network hardening applied\n")
print("hardening complete")
