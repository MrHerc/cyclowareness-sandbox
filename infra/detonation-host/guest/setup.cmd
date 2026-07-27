@echo off
set SRC=%~dp0
set LOG=C:\cape-provision.log
echo [%date% %time%] provisioning started from %SRC% > %LOG%

echo [*] installing Python >> %LOG%
"%SRC%python-amd64.exe" /quiet InstallAllUsers=1 TargetDir=C:\Python312 PrependPath=1 Include_test=0 Include_launcher=1 >> %LOG% 2>&1

echo [*] staging the CAPE agent >> %LOG%
mkdir C:\cape 2>nul
copy /Y "%SRC%agent.py" C:\cape\agent.py >> %LOG% 2>&1

echo [*] agent autostart at logon, elevated >> %LOG%
schtasks /create /tn "CAPEAgent" /tr "C:\Python312\python.exe C:\cape\agent.py" /sc onlogon /ru analyst /rl highest /f >> %LOG% 2>&1

echo [*] no UAC prompts - the agent must be able to elevate silently >> %LOG%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >> %LOG% 2>&1

echo [*] firewall off - it interferes with the result server callback >> %LOG%
netsh advfirewall set allprofiles state off >> %LOG% 2>&1

echo [*] Windows Update off - updates change the baseline between analyses >> %LOG%
sc config wuauserv start= disabled >> %LOG% 2>&1
sc stop wuauserv >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f >> %LOG% 2>&1

echo [*] Defender policy - best effort; tamper protection is handled offline >> %LOG%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f >> %LOG% 2>&1

echo [*] no sleep, no hibernate - the guest must stay reachable >> %LOG%
powercfg /hibernate off >> %LOG% 2>&1
powercfg /change standby-timeout-ac 0 >> %LOG% 2>&1
powercfg /change monitor-timeout-ac 0 >> %LOG% 2>&1

echo [*] show file extensions and hidden files - analysts read this screen >> %LOG%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >> %LOG% 2>&1

echo [*] starting the agent now >> %LOG%
start "" C:\Python312\python.exe C:\cape\agent.py

echo [%date% %time%] provisioning finished >> %LOG%
echo done > C:\cape\provisioned.txt
