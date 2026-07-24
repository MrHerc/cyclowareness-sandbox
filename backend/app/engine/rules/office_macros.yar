/*
 * Cyclowareness Sandbox rule pack: office_macros.yar
 * VBA in legacy OLE2 documents. A macro-bearing document is not by itself
 * malicious, so the graded rules here require an auto-execution trigger paired
 * with a process-spawn or download primitive. The plain "has a VBA project"
 * rule is deliberately low severity: it is context, not a verdict.
 */

rule VBA_AutoExec_And_Shell
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "VBA macro that auto-runs on open and shells out to a process"
        severity = "high"
        reference = "MITRE ATT&CK T1204.002; T1059.005 Visual Basic"
    strings:
        $a1 = "AutoOpen" nocase ascii wide
        $a2 = "Document_Open" nocase ascii wide
        $a3 = "Workbook_Open" nocase ascii wide
        $a4 = "AutoClose" nocase ascii wide
        $a5 = "Auto_Open" nocase ascii wide
        $s1 = "Shell" nocase ascii wide
        $s2 = "WScript.Shell" nocase ascii wide
        $s3 = "Shell.Application" nocase ascii wide
        $s4 = "CreateObject" nocase ascii wide
    condition:
        any of ($a*) and any of ($s*)
}

rule VBA_Download_And_Execute
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "VBA macro that fetches a remote payload and runs it"
        severity = "high"
        reference = "MITRE ATT&CK T1105 Ingress Tool Transfer; T1204.002"
    strings:
        $net1 = "URLDownloadToFile" nocase ascii wide
        $net2 = "MSXML2.XMLHTTP" nocase ascii wide
        $net3 = "MSXML2.ServerXMLHTTP" nocase ascii wide
        $net4 = "WinHttp.WinHttpRequest" nocase ascii wide
        $run1 = "Shell" nocase ascii wide
        $run2 = "WScript.Shell" nocase ascii wide
        $run3 = "Shell.Application" nocase ascii wide
        $run4 = "ShellExecute" nocase ascii wide
    condition:
        any of ($net*) and any of ($run*)
}

rule Office_OLE_Contains_VBA_Project
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "Legacy OLE2 Office document carries an embedded VBA project"
        severity = "low"
        reference = "MITRE ATT&CK T1059.005; olevba"
    strings:
        $vba1 = "VBAProject" ascii wide
        $vba2 = "_VBA_PROJECT" ascii wide
        $vba3 = "Attribute VB_Name" ascii
    condition:
        uint32(0) == 0xE011CFD0 and any of them
}

rule VBA_Suspicious_AutoExec_Keywords
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "VBA auto-exec trigger alongside evasion / persistence keywords"
        severity = "medium"
        reference = "MITRE ATT&CK T1204.002; T1547 Autostart"
    strings:
        $a1 = "AutoOpen" nocase ascii wide
        $a2 = "Document_Open" nocase ascii wide
        $a3 = "Workbook_Open" nocase ascii wide
        $k1 = "Environ" nocase ascii wide
        $k2 = "GetObject" nocase ascii wide
        $k3 = "CallByName" nocase ascii wide
        $k4 = "powershell" nocase ascii wide
        $k5 = "cmd.exe" nocase ascii wide
    condition:
        any of ($a*) and any of ($k*)
}
