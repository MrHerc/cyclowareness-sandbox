/*
 * Cyclowareness Sandbox rule pack: packers.yar
 * Runtime packers and protectors. These are not malicious by themselves, but a
 * PE whose real code only exists after unpacking is deliberately hiding from
 * static parsing, and that is a graded observation. Every rule anchors on the
 * MZ magic so it can never fire on a document that merely mentions the string.
 */

rule UPX_Packed_Executable
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE packed with UPX (UPX0/UPX1 sections or the UPX! marker)"
        severity = "high"
        reference = "MITRE ATT&CK T1027.002 Software Packing; upx.github.io"
    strings:
        $upx0   = "UPX0" ascii
        $upx1   = "UPX1" ascii
        $marker = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and (($upx0 and $upx1) or $marker)
}

rule ASPack_Packed_Executable
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE packed with ASPack (.aspack / .adata section names)"
        severity = "medium"
        reference = "MITRE ATT&CK T1027.002 Software Packing"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule MPRESS_Packed_Executable
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE packed with MPRESS (.MPRESS1 / .MPRESS2 section names)"
        severity = "medium"
        reference = "MITRE ATT&CK T1027.002 Software Packing"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Petite_or_FSG_Packed_Executable
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE packed with Petite or FSG (small dropper packers)"
        severity = "medium"
        reference = "MITRE ATT&CK T1027.002 Software Packing"
    strings:
        $petite = ".petite" ascii
        $fsg    = "FSG!" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Themida_WinLicense_Protected
{
    meta:
        author = "Cyclowareness Sandbox"
        description = "PE protected by Themida / WinLicense (anti-analysis armouring)"
        severity = "medium"
        reference = "MITRE ATT&CK T1027.002; T1622 Debugger Evasion"
    strings:
        $t1 = ".themida" ascii
        $t2 = "Themida" ascii
        $t3 = "WinLicense" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
