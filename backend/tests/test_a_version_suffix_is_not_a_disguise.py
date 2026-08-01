"""`convert-im6.q16` was called a disguise, and `docker` was called packed.

Measured over 75 real Linux malware samples (Mirai, Gafgyt, XorDDoS and the
general ELF feed) and 220 stock ELF binaries taken from this host's own
`/usr/bin`, `/bin`, `/usr/sbin` and `/usr/lib`:

    signal                        malicious   benign   sole reason for the flag
    generic.extension_mismatch          0%       8%    0 malicious / 19 benign
    elf.packed                         25%       4%   19 malicious /  8 benign

`generic.extension_mismatch` is the engine's strongest deception signal, at
HIGH, and on this population it accused nineteen ordinary programs and caught
nothing. Every one was a build or version suffix that names no format:

    convert-im6.q16, display-im6.q16     ImageMagick's quantum depth
    db5.3_dump, db5.3_log_verify         Berkeley DB: version, then tool name
    python3.10                           splitext() reads this as `.10`

`elf.packed` fired on `docker` (malicious, 33.6), `bsondump`, `curl` and six
`btrfs-*` tools. Their high-entropy data is in a NAMED SECTION — `.debug_info`
holding compressed DWARF, `.rodata` holding compressed tables — inside binaries
with seven to sixteen sections. Every one of the nineteen genuinely packed
malware samples had its high-entropy region in the `<PT_LOAD>` fallback, which
only runs when there is no section table at all, and twelve carried a UPX
marker besides.

Together: benign false positives 28 of 220 -> **0 of 220**, with malicious
detection unchanged at 20 of 75.
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from app.engine import identify
from app.engine.analyzers import elf as elf_analyzer
from app.engine.contracts import Sample

# --- a minimal but real ELF --------------------------------------------------
#
# Hand-built rather than fixture-loaded so the section table can be removed
# without also changing anything else about the file.

_EI = b"\x7fELF\x02\x01\x01" + bytes(9)


def _elf(*, sections: bool, body: bytes = b"\x00" * 8192,
         machine: int = 62) -> bytes:
    """A 64-bit little-endian ELF with one PT_LOAD and optionally a section."""
    ehsize, phentsize, shentsize = 64, 56, 64
    phoff = ehsize
    load_off = phoff + phentsize
    shoff = load_off + len(body) if sections else 0
    shnum = 3 if sections else 0

    header = _EI + struct.pack(
        "<HHIQQQIHHHHHH",
        2, machine, 1, 0x400000, phoff, shoff, 0,
        ehsize, phentsize, 1, shentsize, shnum, 2 if sections else 0,
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, load_off, 0x400000, 0x400000,
                       len(body), len(body), 0x1000)
    out = bytearray(header + phdr + body)
    if sections:
        names = b"\x00.rodata\x00.shstrtab\x00"
        name_off = len(out)
        out += names
        shoff = len(out)
        out[40:48] = struct.pack("<Q", shoff)
        # null, .rodata (covering the body), .shstrtab
        out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        out += struct.pack("<IIQQQQIIQQ", 1, 1, 2, 0x400000, load_off,
                           len(body), 0, 0, 1, 0)
        out += struct.pack("<IIQQQQIIQQ", 9, 3, 0, 0, name_off,
                           len(names), 0, 0, 1, 0)
    return bytes(out)


def _sample(tmp_path, data: bytes, name: str) -> Sample:
    path = tmp_path / name
    path.write_bytes(data)
    ident = identify.identify(str(path), name)
    return Sample(
        path=str(path), size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(), md5=hashlib.md5(data).hexdigest(),
        mime=ident.mime, magic=ident.magic, claimed_extension=ident.claimed_extension,
        original_name=name, extension_mismatch=ident.extension_mismatch,
        family=ident.family,
    )


# --- the name ----------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "convert-im6.q16",      # ImageMagick's quantum depth
    "db5.3_dump",           # Berkeley DB: version, then the tool's name
    "db5.3_log_verify",
    "python3.10",           # splitext() reads `.10`
    "libcrypto.so.3",       # every versioned shared object on a Linux system
])
def test_a_suffix_that_names_no_format_is_not_a_disguise(tmp_path, name) -> None:
    ident = identify.identify(str(_write(tmp_path, name)), name)
    assert ident.family == "elf", ident.mime
    assert not ident.extension_mismatch, (
        f"{name} claimed={ident.claimed_extension!r} — a build or version suffix "
        "is not a claim about a format, so it cannot be a lie about one"
    )


def _write(tmp_path, name: str):
    path = tmp_path / name
    path.write_bytes(_elf(sections=True))
    return path


@pytest.mark.parametrize("name", ["photo.jpg", "invoice.pdf", "report.docx", "notes.zip"])
def test_a_real_format_under_a_binary_body_still_is(tmp_path, name) -> None:
    """The direction that must not be lost. `.jpg` and `.pdf` ARE formats: a
    name that promises a picture over a body that is a program is the whole
    reason this signal exists."""
    ident = identify.identify(str(_write(tmp_path, name)), name)
    assert ident.extension_mismatch, f"{name} over an ELF body must still be a mismatch"


def test_the_known_format_set_is_derived_not_hand_written() -> None:
    """A hand-maintained duplicate of a list drifts from it silently — that is
    exactly how the corpus builder came to have no `pdf` in it."""
    known = identify._KNOWN_FORMAT_EXTENSIONS
    for row in identify._MAGIC:
        for ext in row[3]:
            assert ext in known, ext
    for ext in identify.WINDOWS_RUNS_THESE:
        assert ext in known, ext
    for ext in identify._BINARY_FORMAT_EXTENSIONS:
        assert ext in known, ext
    # And the suffixes that caused this are NOT in it.
    for ext in (".q16", ".3_dump", ".10", ".3"):
        assert ext not in known, ext


# --- the packing claim -------------------------------------------------------


def _analyze(tmp_path, data: bytes, name: str = "s.elf"):
    return {s.id: s for s in elf_analyzer.analyze(_sample(tmp_path, data, name)).signals}


def test_entropy_in_a_named_section_is_not_packing(tmp_path) -> None:
    """`.debug_info` in a Go binary reaches 8.00 — the same as a UPX stub. The
    difference is not the number, it is that the binary has a section table."""
    import os

    signals = _analyze(tmp_path, _elf(sections=True, body=os.urandom(16384)))
    assert "elf.packed" not in signals, (
        "high-entropy data in a named section of a normally-sectioned binary is "
        "compressed data the compiler emitted"
    )


def test_entropy_with_no_section_table_is_packing(tmp_path) -> None:
    """And the direction that must be kept: all nineteen genuinely packed
    samples had their high-entropy region in the PT_LOAD fallback."""
    import os

    signals = _analyze(tmp_path, _elf(sections=False, body=os.urandom(16384)))
    assert "elf.packed" in signals, signals.keys()
    assert signals["elf.packed"].severity == "high"
    reasons = (signals["elf.packed"].evidence or {}).get("reasons") or []
    assert any("no section table" in r for r in reasons), reasons


def test_a_upx_marker_is_packing_wherever_it_sits(tmp_path) -> None:
    """Twelve of the nineteen say so in plain bytes; that route is untouched."""
    body = b"\x00" * 4096 + b"UPX!" + b"\x00" * 4096
    signals = _analyze(tmp_path, _elf(sections=True, body=body))
    assert "elf.packed" in signals, signals.keys()


def test_the_high_entropy_fact_is_still_recorded(tmp_path) -> None:
    """Demoting a claim must not hide the observation behind it."""
    import os

    sample = _sample(tmp_path, _elf(sections=True, body=os.urandom(16384)), "s.elf")
    facts = elf_analyzer.analyze(sample).facts or {}
    assert facts.get("entropy"), "the measurement itself must survive"
    assert max(e["entropy"] for e in facts["entropy"]) > 7.0


# --- what was deliberately NOT done -----------------------------------------


def test_static_linking_is_a_build_choice_not_a_capability() -> None:
    """`elf.statically_linked` fires on 90% of the malware set and 0% of the
    220 stock binaries, which looks like the best discriminator in the file.

    It is not, and the reason is the control group: this host has no statically
    linked binaries at all, so 0% measures where the samples were collected
    rather than what static linking means. Fetched as a proper control —
    busybox-static, caddy, hugo, syncthing, and musl builds of ripgrep and fd —
    all six are statically linked and all six are ordinary software. They
    already score 16.6 to 19.1; one severity step would flag every Go and Rust
    program ever submitted.

    Kept at `low` on purpose. This test exists so the next person who notices
    that 90%/0% finds the measurement before acting on it.
    """
    from app.engine.analyzers.elf import _SUSPICIOUS  # noqa: F401  (import guard)

    import pathlib

    source = pathlib.Path(elf_analyzer.__file__).read_text(encoding="utf-8")
    block = source[source.index('id="elf.statically_linked"'):]
    severity = block[: block.index("detail=")]
    assert '"low"' in severity, (
        "elf.statically_linked must stay `low` — see this test's docstring for "
        "the six-binary control group that decides it"
    )


def test_architecture_is_not_evidence_of_intent() -> None:
    """55 of the 75 malware samples are non-x86 — ARM 19, MIPS 13, PowerPC 5,
    SPARC 4, SuperH 4, m68k 4 — against 0 of 226 benign, which is the Mirai and
    Gafgyt shape: one botnet client cross-compiled for every embedded CPU.

    It is still not a signal, and for the same reason as above: the benign set
    came off an x86-64 server, so every legitimate ARM or MIPS binary in the
    world is missing from it. A Raspberry Pi program is not malware for being
    ARM. If this is ever revisited, the control group has to include real
    non-x86 software first.
    """
    import pathlib

    source = pathlib.Path(elf_analyzer.__file__).read_text(encoding="utf-8")
    for wrong in ("non_native_architecture", "foreign_architecture", "cross_compiled"):
        assert f'id="elf.{wrong}"' not in source, (
            f"elf.{wrong} would be measuring where the benign corpus was collected"
        )
