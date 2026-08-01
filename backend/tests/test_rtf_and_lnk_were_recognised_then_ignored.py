r"""Nine real samples produced nothing at all, because nothing ran.

The type-diverse corpus scored `rtf 0/5` and `lnk 0/4`. That was not weak
detection: both came out `family=unknown`, no analyzer, no signals, no
detonation, `clean` at 1.7. Identification already knew what they were --
libmagic returned `application/rtf` and "Windows shortcut file" -- and
`_family_for` had no case for either MIME, so the answer was thrown away.

RTF and LNK are the two formats attackers moved to when Microsoft blocked
macros, and the samples show why. Two RTFs (DBatLoader, Smoke Loader) carry
`\object`, `\objdata` and `\objupdate` -- an embedded OLE object plus the control
word that renders it WITHOUT a click. Two LNKs (NetSupport) put the whole attack
in the command line, which Explorer does not show: the properties dialog
truncates the arguments field.

Measured after wiring both analyzers, on the same nine files:

    rtf   Mimikatz        1.7      (a macOS TextEdit document, no object)
    rtf   DBatLoader     17.3      rtf.object_auto_executes
    rtf   Smoke Loader   17.3
    rtf   Loki           17.3   x2
    lnk   Kimsuky        30.9      oversized + icon disguise
    lnk   NetSupport     50.3   x2  lnk.command_line_attack (critical)
    lnk   Sliver         17.3      oversized
    flagged: 8 of 9, from 0 of 9

And the other half, which matters more: seven benign controls, all correct. A
WordPad document, an RTF embedding a legitimate Excel chart, a shortcut to
notepad, a Start Menu shortcut with an icon, an admin shortcut to cmd, and a
PowerShell profile shortcut all score 1.7.

The admin shortcuts are why `lnk.runs_an_interpreter` is `info`. At `medium` they
scored 8.3 on structure alone -- and a developer machine is full of them. Same
rule the PE analyzer states about imports: a fact about capability is not a
detection on its own.
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from app.engine import identify, scoring
from app.engine.analyzers import lnk as lnk_mod
from app.engine.analyzers import rtf as rtf_mod
from app.engine.analyzers import run_all
from app.engine.contracts import Sample

# --- builders ----------------------------------------------------------------

LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def shortcut(target: str, args: str = "", icon: str = "", pad: int = 0) -> bytes:
    """A structurally valid .lnk: header, then StringData in its fixed order."""
    HAS_REL, HAS_ARGS, HAS_ICON, UNICODE = 1 << 3, 1 << 5, 1 << 6, 1 << 7
    flags = HAS_REL | UNICODE
    if args:
        flags |= HAS_ARGS
    if icon:
        flags |= HAS_ICON
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = LINK_CLSID
    struct.pack_into("<I", header, 20, flags)

    def s(text: str) -> bytes:
        return struct.pack("<H", len(text)) + text.encode("utf-16-le")

    body = s(target) + (s(args) if args else b"") + (s(icon) if icon else b"")
    return bytes(header) + body + b"\x00" * pad


def _analyse(tmp_path, blob: bytes, suffix: str):
    path = tmp_path / ("sample" + suffix)
    path.write_bytes(blob)
    ident = identify.identify(str(path), "sample" + suffix)
    sample = Sample(
        path=str(path), size_bytes=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(), md5=hashlib.md5(blob).hexdigest(),
        mime=ident.mime, magic=ident.magic, claimed_extension=ident.claimed_extension,
        original_name="sample" + suffix, extension_mismatch=ident.extension_mismatch,
        family=ident.family,
    )
    results = run_all(sample, sample.family)
    ids = {s.id: s for r in results for s in r.signals}
    return sample, ids, scoring.assess(results, ioc_total=0).final_score


# --- the gap itself ----------------------------------------------------------

def test_rtf_is_identified_as_rtf(tmp_path) -> None:
    """It was `unknown`, which selects no analyzer at all."""
    sample, _, _ = _analyse(tmp_path, rb"{\rtf1\ansi hello}", ".rtf")
    assert sample.family == "rtf"


def test_a_shortcut_is_identified_as_a_shortcut(tmp_path) -> None:
    sample, _, _ = _analyse(tmp_path, shortcut(r"..\..\Windows\notepad.exe"), ".lnk")
    assert sample.family == "lnk"


def test_both_are_supported_and_detonated() -> None:
    """Accepted but unsupported, and never offered to the worker."""
    from app.api.dynamic import _DYNAMIC_FAMILIES
    from app.api.meta import SUPPORTED_EXTENSIONS

    assert ".rtf" in SUPPORTED_EXTENSIONS
    assert ".lnk" in SUPPORTED_EXTENSIONS
    assert "rtf" in _DYNAMIC_FAMILIES
    assert "lnk" in _DYNAMIC_FAMILIES


# --- RTF ---------------------------------------------------------------------

def test_objupdate_is_the_finding(tmp_path) -> None:
    """The control word that renders the object without a click."""
    blob = rb"{\rtf1\ansi{\object\objemb\objupdate{\*\objdata 0102030405060708}}}"
    _, ids, score = _analyse(tmp_path, blob, ".rtf")
    assert "rtf.object_auto_executes" in ids
    assert ids["rtf.object_auto_executes"].severity == "high"
    assert score > 10


def test_an_embedded_object_alone_is_not_a_finding(tmp_path) -> None:
    """A document may legitimately embed a chart. Saying otherwise is the trap."""
    blob = (rb"{\rtf1\ansi\pard A chart follows.\par"
            rb"{\object\objemb{\*\objclass Excel.Sheet.12}{\*\objdata 01020304}}}")
    _, ids, score = _analyse(tmp_path, blob, ".rtf")
    assert "rtf.object_auto_executes" not in ids
    assert score < 5


def test_an_embedded_executable_is_critical(tmp_path) -> None:
    payload = b"MZ" + b"\x90" * 64
    blob = (rb"{\rtf1\ansi{\object\objemb{\*\objdata "
            + payload.hex().encode() + rb"}}}")
    _, ids, _ = _analyse(tmp_path, blob, ".rtf")
    assert ids["rtf.embedded_executable"].severity == "critical"


def test_the_equation_editor_clsid_is_critical(tmp_path) -> None:
    """CVE-2017-11882 / CVE-2018-0802, still the common RTF chain."""
    payload = bytes.fromhex("02ce020000000000c000000000000046") + b"\x00" * 32
    blob = (rb"{\rtf1\ansi{\object\objemb{\*\objdata "
            + payload.hex().encode() + rb"}}}")
    _, ids, _ = _analyse(tmp_path, blob, ".rtf")
    assert ids["rtf.equation_editor_object"].severity == "critical"


def test_a_plain_document_says_nothing(tmp_path) -> None:
    blob = (rb"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fnil Calibri;}}"
            rb"\viewkind4\uc1\pard\f0\fs22 Quarterly report.\par}")
    _, ids, score = _analyse(tmp_path, blob, ".rtf")
    assert not [i for i in ids if i.startswith("rtf.")], sorted(ids)
    assert score < 5


# --- LNK ---------------------------------------------------------------------

def test_the_command_line_is_the_attack(tmp_path) -> None:
    blob = shortcut(
        r"..\..\Windows\System32\cmd.exe",
        args="/c powershell -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA==",
    )
    _, ids, score = _analyse(tmp_path, blob, ".lnk")
    assert ids["lnk.command_line_attack"].severity == "critical"
    assert score > 30


def test_an_ordinary_shortcut_says_nothing(tmp_path) -> None:
    _, ids, score = _analyse(tmp_path, shortcut(r"..\..\Windows\notepad.exe"), ".lnk")
    assert not [i for i in ids if i.startswith("lnk.")], sorted(ids)
    assert score < 5


@pytest.mark.parametrize("target,args", [
    (r"..\..\Windows\System32\cmd.exe", "/k cd /d C:\\work"),
    (r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "-NoExit -Command Set-Location C:\\src"),
])
def test_an_admin_shortcut_is_recorded_not_accused(tmp_path, target, args) -> None:
    """A developer machine is full of these. At `medium` they scored 8.3."""
    _, ids, score = _analyse(tmp_path, shortcut(target, args=args), ".lnk")
    assert ids["lnk.runs_an_interpreter"].severity == "info"
    assert score < 5


def test_a_shortcut_carrying_a_payload_is_flagged(tmp_path) -> None:
    """Kimsuky's was 68 kB. A shortcut is a pointer."""
    blob = shortcut(r"..\..\Windows\notepad.exe", pad=40 * 1024)
    _, ids, _ = _analyse(tmp_path, blob, ".lnk")
    assert ids["lnk.oversized_for_a_shortcut"].severity == "high"


def test_the_icon_disguise(tmp_path) -> None:
    blob = shortcut(r"..\..\Windows\System32\cmd.exe", args="/c whoami",
                    icon=r"%SystemRoot%\system32\imageres.dll")
    _, ids, _ = _analyse(tmp_path, blob, ".lnk")
    assert ids["lnk.icon_disguise"].severity == "high"


def test_a_truncated_shortcut_does_not_crash(tmp_path) -> None:
    """A malformed shortcut is something to report, not something to raise on."""
    for blob in (b"L\x00\x00\x00", b"L\x00\x00\x00" + b"\x00" * 60,
                 bytes(0x4C), b"\x00" * 8):
        path = tmp_path / "broken.lnk"
        path.write_bytes(blob)
        result = lnk_mod.analyze(Sample(
            path=str(path), size_bytes=len(blob), sha256="a" * 64, md5="b" * 32,
            mime="application/x-ms-shortcut", magic="Windows shortcut",
            claimed_extension=".lnk", original_name="broken.lnk",
            extension_mismatch=False, family="lnk"))
        assert result is not None


def test_a_truncated_rtf_does_not_crash(tmp_path) -> None:
    for blob in (rb"{\rtf1", rb"{\rtf1\objdata zzzz", rb"{\rtf1\objdata 0", b"{"):
        path = tmp_path / "broken.rtf"
        path.write_bytes(blob)
        result = rtf_mod.analyze(Sample(
            path=str(path), size_bytes=len(blob), sha256="a" * 64, md5="b" * 32,
            mime="application/rtf", magic="RTF", claimed_extension=".rtf",
            original_name="broken.rtf", extension_mismatch=False, family="rtf"))
        assert result is not None
