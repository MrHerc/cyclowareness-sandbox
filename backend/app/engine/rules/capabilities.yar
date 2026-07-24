/*
 * Cyclowareness Sandbox rule pack: capabilities.yar
 * Behaviour-shaped rules that cut across file types: embedded executables,
 * living-off-the-land binary invocations, and suspicious PE import
 * combinations. Each requires a combination of primitives, never a single
 * common API name, so a normal program that imports one Win32 call is untouched.
 */

rule Embedded_PE_In_NonPE
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "A file that is not itself a PE carries an embedded Windows executable"
        severity = "high"
        reference = "MITRE ATT&CK T1027.009 Embedded Payloads; T1204"
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) != 0x5A4D and $dos
}

rule LOLBin_Mshta_Remote_Script
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "mshta invoked against a remote or inline script (LOLBin execution)"
        severity = "medium"
        reference = "MITRE ATT&CK T1218.005 Mshta"
    strings:
        $m = "mshta" nocase ascii wide
        $u1 = "http" nocase ascii wide
        $u2 = "javascript:" nocase ascii wide
        $u3 = "vbscript:" nocase ascii wide
    condition:
        $m and any of ($u*)
}

rule LOLBin_Regsvr32_Scrobj
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "regsvr32 squiblydoo: registering a remote scriptlet via scrobj.dll"
        severity = "high"
        reference = "MITRE ATT&CK T1218.010 Regsvr32"
    strings:
        $r = "regsvr32" nocase ascii wide
        $i = "/i:" nocase ascii wide
        $s = "scrobj.dll" nocase ascii wide
        $u = "http" nocase ascii wide
    condition:
        $r and ($s or ($i and $u))
}

rule LOLBin_Certutil_Download_Or_Decode
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "certutil abused to download (-urlcache) or decode (-decode) a payload"
        severity = "high"
        reference = "MITRE ATT&CK T1105; T1140 via certutil"
    strings:
        $c  = "certutil" nocase ascii wide
        $a1 = "-urlcache" nocase ascii wide
        $a2 = "-decode" nocase ascii wide
        $a3 = "-decodehex" nocase ascii wide
        $a4 = "/urlcache" nocase ascii wide
    condition:
        $c and any of ($a*)
}

rule Bitsadmin_Transfer_Download
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "bitsadmin used to transfer a remote file (background download LOLBin)"
        severity = "medium"
        reference = "MITRE ATT&CK T1197 BITS Jobs"
    strings:
        $b = "bitsadmin" nocase ascii wide
        $t = "/transfer" nocase ascii wide
        $u = "http" nocase ascii wide
    condition:
        $b and $t and $u
}

rule PE_Process_Injection_Import_Combo
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE imports the classic allocate/write/execute-in-remote-process trio"
        severity = "medium"
        reference = "MITRE ATT&CK T1055 Process Injection"
    strings:
        $alloc = "VirtualAllocEx" ascii
        $alloc2 = "VirtualAlloc" ascii
        $write = "WriteProcessMemory" ascii
        $thread = "CreateRemoteThread" ascii
        $thread2 = "NtCreateThreadEx" ascii
        $resolve1 = "LoadLibraryA" ascii
        $resolve2 = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D
        and ($alloc or $alloc2)
        and $write
        and ($thread or $thread2)
        and any of ($resolve*)
}

rule PE_Keylogger_Api_Combo
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE imports the keyboard-hook + async-key-state pair used by keyloggers"
        severity = "medium"
        reference = "MITRE ATT&CK T1056.001 Keylogging"
    strings:
        $hook = "SetWindowsHookExA" ascii
        $hookw = "SetWindowsHookExW" ascii
        $key = "GetAsyncKeyState" ascii
        $key2 = "GetKeyboardState" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($hook*)) and (any of ($key*))
}
