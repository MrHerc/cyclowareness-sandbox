/*
 * Cyclowareness Sandbox rule pack: scripts.yar
 * PowerShell, JScript/VBScript and shell one-liners. Script droppers are text,
 * so these rules key on the specific verb combinations a dropper needs, not on
 * any single common word. A rule that fired on every script that says "http"
 * would be noise; each rule below requires an execution or download primitive.
 */

rule PowerShell_EncodedCommand
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PowerShell invoked with a base64 -EncodedCommand payload"
        severity = "high"
        reference = "MITRE ATT&CK T1059.001; T1027 Obfuscated Files"
    strings:
        $ps    = "powershell" nocase ascii wide
        $enc1  = "-EncodedCommand" nocase ascii wide
        $enc2  = /-e(nc?)?\s+[A-Za-z0-9+\/]{40,}/ nocase ascii wide
    condition:
        $ps and ($enc1 or $enc2)
}

rule PowerShell_Download_Cradle
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PowerShell download-and-execute cradle (WebClient / IWR + IEX)"
        severity = "high"
        reference = "MITRE ATT&CK T1059.001; T1105 Ingress Tool Transfer"
    strings:
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadFile" nocase ascii wide
        $dl3 = "Net.WebClient" nocase ascii wide
        $dl4 = "Invoke-WebRequest" nocase ascii wide
        $dl5 = "Invoke-RestMethod" nocase ascii wide
        $ex1 = "IEX" ascii wide
        $ex2 = "Invoke-Expression" nocase ascii wide
    condition:
        any of ($dl*) and any of ($ex*)
}

rule PowerShell_Stealth_Flags
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PowerShell launched hidden and unrestricted (dropper launcher pattern)"
        severity = "medium"
        reference = "MITRE ATT&CK T1059.001; T1564 Hide Artifacts"
    strings:
        $ps  = "powershell" nocase ascii wide
        $f1  = "-nop" nocase ascii wide
        $f2  = "-noprofile" nocase ascii wide
        $f3  = "-w hidden" nocase ascii wide
        $f4  = "-windowstyle hidden" nocase ascii wide
        $f5  = "-ep bypass" nocase ascii wide
        $f6  = "-executionpolicy bypass" nocase ascii wide
    condition:
        $ps and 2 of ($f*)
}

rule JS_Obfuscation_Eval_Decode
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "JScript/JS runtime string assembly fed to eval (obfuscated dropper)"
        severity = "medium"
        reference = "MITRE ATT&CK T1059.007; T1140 Deobfuscate/Decode"
    /*
     * Two deliberate tightenings, both paid for by false positives:
     *
     * `eval` as a bare substring matched jQuery's own `_evalUrl`, and matched
     * "retrieval" inside curl.exe. It must be a CALL, so the regex refuses a
     * preceding word character, `.` or `$`.
     *
     * "somewhere in the file" is not a relationship. jQuery has one `eval` and
     * a `String.fromCharCode` forty kilobytes away in its CSS escape handling;
     * that is two ordinary things, not one obfuscated dropper. The decoder now
     * has to sit within 300 bytes of the eval, in either direction, which is
     * what `eval(atob(x))` and `var s=unescape(...); eval(s)` both look like.
     *
     * Every pattern accepts bracket notation as well as dot notation, because
     * `String['fromCharCode'](` is what the obfuscators in this corpus actually
     * emit and `String.fromCharCode(` is what a person writes.
     */
    strings:
        $eval = /(^|[^\w.$])eval\s*\(|['"]eval['"]\s*\]\s*\(/ ascii wide
        $d1   = /unescape['"\]\s]*\(/ nocase ascii wide
        $d2   = /fromCharCode['"\]\s]*\(/ nocase ascii wide
        $d3   = /atob['"\]\s]*\(/ nocase ascii wide
        $d4   = /document\s*[.\[]\s*['"]?write['"\]\s]*\(/ nocase ascii wide
    condition:
        for any i in (1..#eval) : (
            for any of ($d*) : (
                (@ > @eval[i] and @ - @eval[i] < 300) or
                (@ < @eval[i] and @eval[i] - @ < 300)
            )
        )
}

rule WScript_Shell_Command_Execution
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "VBScript/JScript spawning a process via WScript.Shell.Run/Exec"
        severity = "medium"
        reference = "MITRE ATT&CK T1059.005; T1059.007"
    strings:
        $obj  = "WScript.Shell" nocase ascii wide
        $run1 = ".Run" ascii wide
        $run2 = ".Exec" ascii wide
    condition:
        $obj and ($run1 or $run2)
}

rule Reverse_Shell_OneLiner
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "Classic *nix reverse-shell one-liner (bash tcp, nc -e, python socket)"
        severity = "high"
        reference = "MITRE ATT&CK T1059.004; T1219 Remote Access"
    strings:
        $bash    = "/dev/tcp/" ascii
        $nce     = /nc(\.traditional)?\s+(-[a-z]*e|-e)\b/ nocase ascii
        $pysock  = "socket.socket" ascii
        $pydup   = "os.dup2" ascii
        $mkfifo  = "mkfifo" ascii
        $shflag  = /-i\s+>&|\bsh\s+-i\b/ ascii
    condition:
        $bash or $nce or ($pysock and $pydup) or ($mkfifo and $shflag)
}
