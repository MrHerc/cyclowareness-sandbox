/*
 * Cyclowareness Sandbox rule pack: capabilities.yar
 * Behaviour-shaped rules that cut across file types: embedded executables,
 * living-off-the-land binary invocations, and suspicious PE import
 * combinations. Each requires a combination of primitives, never a single
 * common API name, so a normal program that imports one Win32 call is untouched.
 *
 * "A combination of primitives" has to mean a combination in ONE PLACE. Two
 * common strings megabytes apart in a large binary are two coincidences, not a
 * combination, and that is how Process Explorer and Autoruns came to be accused
 * of LOLBin execution. The LOLBin rules below therefore require their parts
 * within 400 bytes of each other — one command line.
 */
import "pe"

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
    /*
     * A LOLBin finding is about ONE COMMAND LINE, not one file.
     *
     * "mshta anywhere and http anywhere" fired on Process Explorer and on all
     * three Autoruns builds: `MSHTA.EXE` is an entry in Autoruns' own table of
     * autostart host programs, and the `http` was `https://www.sysinternals.com`
     * FIFTY-EIGHT THOUSAND bytes away. Measured across the 88-sample detonation
     * fixture, the old form caught 0 of them and accused 6 Sysinternals tools.
     *
     * NEAR_BYTES is generous for a command line, and still three orders of
     * magnitude tighter than "somewhere in the same file". Both directions,
     * written as two comparisons rather than `@ - 400` because YARA offsets are
     * unsigned and would wrap.
     */
    strings:
        $m = "mshta" nocase ascii wide
        $u1 = "http" nocase ascii wide
        $u2 = "javascript:" nocase ascii wide
        $u3 = "vbscript:" nocase ascii wide
    condition:
        for any i in (1..#m) : (
            for any of ($u*) : (
                (@ > @m[i] and @ - @m[i] < 400) or (@ < @m[i] and @m[i] - @ < 400)
            )
        )
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
    /* Same shape as the mshta rule above, so the same one-command-line rule. */
    condition:
        for any i in (1..#b) : (
            for any j in (1..#t) : (
                ((@t[j] > @b[i] and @t[j] - @b[i] < 400) or
                 (@t[j] < @b[i] and @b[i] - @t[j] < 400))
                and
                for any k in (1..#u) : (
                    (@u[k] > @b[i] and @u[k] - @b[i] < 400) or
                    (@u[k] < @b[i] and @b[i] - @u[k] < 400)
                )
            )
        )
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
    /*
     * The description says "PE imports". It did not check imports — it searched
     * the whole file for the API NAMES, which also matches a string in a
     * resource, a debug blob, or an embedded copy of another program. Asking the
     * import table is what the rule always claimed to do.
     *
     * This does NOT clear Process Monitor, which genuinely imports both: it
     * hooks windows and reads keyboard state, and so does every screen recorder,
     * IME, accessibility tool and debugger. That is a capability the report
     * should carry — it is left at `medium` and named honestly rather than
     * tuned away.
     */
    condition:
        pe.is_pe
        and (pe.imports("user32.dll", "SetWindowsHookExA")
             or pe.imports("user32.dll", "SetWindowsHookExW"))
        and (pe.imports("user32.dll", "GetAsyncKeyState")
             or pe.imports("user32.dll", "GetKeyboardState"))
}
