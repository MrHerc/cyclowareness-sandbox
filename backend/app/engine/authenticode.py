"""Authenticode: did this program come from who it says, unaltered?

`pe.py` has always reported `pe.signature_present` at `info`, and said plainly
in its own docstring that it "never validates a signature chain". Presence is
worth nothing — a self-signed certificate produces the same byte. This module is
the part that was missing.

WHY IT EXISTS
-------------
Measured on the detonation host, an Authenticode signature is the single
strongest discriminator available, and the only one an attacker cannot
manufacture by editing bytes:

    benign PEs   13 of 14 signed  (93%)
    real malware 10 of 85 signed  (12%)

Everything else that separates ordinary software from a loader — entropy, an
overlay, TLS callbacks, a packer section, a writable+executable section — is a
fact about how the binary was BUILT, and an unsigned lookalike produces every
one of them. That is why Process Explorer, WinMerge, Audacity, Greenshot, the
Python distribution and a dozen release archives read as `suspicious`.

THREE LAYERS, NOT THREE OPTIONS
-------------------------------
1. **Integrity** needs no trust at all: recompute the Authenticode PE hash and
   check it equals the digest the signature commits to, then check the signer's
   own key verifies the signed attributes. This proves the file has not changed
   since it was signed, and names the publisher. It is always reported.
2. **Anchoring** asks whether the chain reaches an issuer this deployment has
   decided to trust. That list is DATA — `trust_anchors.py`, auditable, and
   replaceable by the operator — not a policy baked into the engine. For a
   sovereign product, *which certificate authorities we trust* has to be
   something the operator can read and change.
3. **What it buys** is narrow on purpose: a verified, anchored signature stops
   STRUCTURAL signals from accusing. It never waives behaviour. Ten of the
   malware samples on this host are signed, and buying a waiver is the entire
   reason a certificate gets stolen.

DEFENCE
-------
Every byte parsed here is attacker-controlled. The DER reader below is
deliberately tiny, iterative, bounds-checked on every field, and bounded in
total work; it never allocates from a length it has not validated against the
buffer, and it is not recursive, so a nested structure cannot exhaust the stack.
Nothing here executes, decompresses or resolves anything, and there is no
network access: revocation is therefore NOT checked, and this module says so
rather than implying a freshness it does not have.
"""
from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - exercised by the import guard test
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    _CRYPTO_AVAILABLE = True
    _CRYPTO_ERROR = ""
except Exception as exc:  # pragma: no cover
    _CRYPTO_AVAILABLE = False
    _CRYPTO_ERROR = f"{type(exc).__name__}: {exc}"

# --- bounds -------------------------------------------------------------------
#: Largest certificate table examined. Real ones are tens of kilobytes.
MAX_CERT_TABLE = 4 * 1024 * 1024
#: Largest file hashed. A signature over more than this is not worth the read.
MAX_HASH_BYTES = 512 * 1024 * 1024
#: Ceiling on DER elements walked, so a pathological structure cannot spin.
MAX_DER_STEPS = 200_000
#: Ceiling on certificates loaded out of one signature.
MAX_CERTS = 64

# --- object identifiers -------------------------------------------------------
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
#: RFC 3161 timestamp token, carried as an unsigned attribute. The value is a
#: complete CMS ContentInfo, not a bare time -- the timestamp is itself signed by
#: a timestamping authority, which is why a TSA must never be a code-signing
#: anchor (see `trust_anchors`).
OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
#: The older Authenticode countersignature: a SignerInfo whose signed attributes
#: carry `signingTime`. Still present on binaries signed before RFC 3161 became
#: the norm, and on plenty signed since.
OID_COUNTERSIGNATURE = "1.2.840.113549.1.9.6"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"

_DIGESTS: dict[str, str] = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

#: Digests that are broken for signatures. A file signed only under one of these
#: is reported as signed and NOT treated as verified — SHA-1 collisions are
#: practical, and Authenticode is exactly the setting where that matters.
WEAK_DIGESTS = frozenset({"md5", "sha1"})


# --- a minimal, bounded DER reader --------------------------------------------


class DerError(ValueError):
    """The bytes are not the DER this module needs. Never a crash, always this."""


@dataclass(frozen=True)
class _Node:
    tag: int
    start: int          # offset of the identifier octet
    header: int         # identifier + length octets
    length: int         # content length
    value: int          # offset of the first content octet

    @property
    def end(self) -> int:
        return self.value + self.length


def _read(buf: bytes, off: int, limit: int) -> _Node:
    """One TLV at `off`, validated against `limit`."""
    if off + 2 > limit:
        raise DerError("truncated element")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags are not used by PKCS#7")
    first = buf[off + 1]
    if first < 0x80:
        header, length = 2, first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DerError("indefinite or oversized length")
        if off + 2 + count > limit:
            raise DerError("truncated length")
        length = int.from_bytes(buf[off + 2:off + 2 + count], "big")
        header = 2 + count
    value = off + header
    if length < 0 or value + length > limit:
        raise DerError("element overruns its container")
    return _Node(tag=tag, start=off, header=header, length=length, value=value)


def _children(buf: bytes, node: _Node, budget: list[int]) -> list[_Node]:
    out: list[_Node] = []
    off = node.value
    while off < node.end:
        budget[0] -= 1
        if budget[0] <= 0:
            raise DerError("DER walk budget exhausted")
        child = _read(buf, off, node.end)
        out.append(child)
        off = child.end
        if len(out) > 4096:
            raise DerError("too many children")
    return out


def _oid(buf: bytes, node: _Node) -> str:
    """Dotted form of an OBJECT IDENTIFIER."""
    if node.tag != 0x06 or node.length == 0:
        raise DerError("not an OID")
    raw = buf[node.value:node.end]
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for i, byte in enumerate(raw[1:]):
        value = (value << 7) | (byte & 0x7F)
        if value > (1 << 64):
            raise DerError("OID arc too large")
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
        elif i == len(raw) - 2:
            raise DerError("OID ends mid-arc")
    return ".".join(parts)


def _find(buf: bytes, node: _Node, budget: list[int], depth: int = 0):
    """Iterative pre-order walk. Yields every element under `node`.

    Iterative rather than recursive: the input is hostile and a deeply nested
    structure must not be able to reach the interpreter's stack limit.
    """
    stack = [(node, 0)]
    while stack:
        current, level = stack.pop()
        budget[0] -= 1
        if budget[0] <= 0:
            raise DerError("DER walk budget exhausted")
        yield current, level
        if level > 40:
            continue
        if current.tag & 0x20:  # constructed
            try:
                kids = _children(buf, current, budget)
            except DerError:
                continue
            for kid in reversed(kids):
                stack.append((kid, level + 1))


# --- the PE side --------------------------------------------------------------


@dataclass(frozen=True)
class _CertTable:
    offset: int
    size: int
    optional_header: int
    magic: int


def _locate(data: bytes) -> _CertTable | None:
    """Where the certificate table and the two excluded fields live.

    Parsed by hand rather than through pefile: this needs exact FILE offsets of
    three header fields, it must work on a file pefile refuses, and it must not
    be affected by any repair pefile does while loading.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    optional_header = e_lfanew + 24
    if optional_header + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, optional_header)[0]
    if magic == 0x10B:
        dd = optional_header + 96
    elif magic == 0x20B:
        dd = optional_header + 112
    else:
        return None
    entry = dd + 4 * 8              # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4
    if entry + 8 > len(data):
        return None
    offset, size = struct.unpack_from("<II", data, entry)
    return _CertTable(offset=offset, size=size, optional_header=optional_header, magic=magic)


def authenticode_digest(data: bytes, algorithm: str) -> bytes | None:
    """The hash Authenticode actually signs.

    Three regions are excluded because signing changes them: the OptionalHeader
    CheckSum, the security data directory entry that points at the signature,
    and the certificate table itself. Anything appended AFTER the certificate
    table is included — otherwise a payload could be stapled to a signed file
    and inherit its signature.
    """
    table = _locate(data)
    if table is None:
        return None
    try:
        digest = hashlib.new(algorithm)
    except ValueError:
        return None

    checksum = table.optional_header + 64
    entry = table.optional_header + (96 if table.magic == 0x10B else 112) + 4 * 8
    if checksum + 4 > len(data) or entry + 8 > len(data):
        return None

    end = table.offset if table.offset else len(data)
    if end > len(data):
        end = len(data)
    if end < entry + 8:
        return None

    digest.update(data[:checksum])
    digest.update(data[checksum + 4:entry])
    digest.update(data[entry + 8:end])
    trailing = table.offset + table.size
    if table.offset and trailing < len(data):
        digest.update(data[trailing:])
    return digest.digest()


def _certificate_blob(data: bytes) -> bytes | None:
    """The DER PKCS#7 inside the WIN_CERTIFICATE wrapper."""
    table = _locate(data)
    if table is None or not table.offset or not table.size:
        return None
    if table.size > MAX_CERT_TABLE:
        return None
    end = min(table.offset + table.size, len(data))
    blob = data[table.offset:end]
    if len(blob) < 8:
        return None
    length, _revision, cert_type = struct.unpack_from("<IHH", blob, 0)
    if cert_type != 0x0002:          # WIN_CERT_TYPE_PKCS_SIGNED_DATA
        return None
    length = min(max(length, 8), len(blob))
    return blob[8:length]


# --- results ------------------------------------------------------------------


@dataclass(frozen=True)
class Publisher:
    common_name: str = ""
    organisation: str = ""
    country: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    sha256: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass(frozen=True)
class SignatureResult:
    #: A certificate table is present at all.
    present: bool = False
    #: The PKCS#7 parsed far enough to find a signer and a committed digest.
    parsed: bool = False
    #: The signature's digest equals the Authenticode hash of THESE bytes.
    covers_file: bool = False
    #: The signer's own public key verifies the signed attributes.
    signature_valid: bool = False
    #: "anchored" | "unanchored" | "self-signed" | "unknown"
    chain: str = "unknown"
    #: The pinned issuer reached, when chain == "anchored".
    anchor: str = ""
    publisher: Publisher | None = None
    digest_algorithm: str = ""
    #: Certificate subjects from leaf upward, for the report.
    chain_subjects: tuple[str, ...] = ()
    #: When a countersigner attested this signature existed, ISO-8601, or "" if
    #: this engine could not read one. Absence is NOT evidence of recency, and
    #: nothing may treat it as "signed now".
    signed_at: str = ""
    reason: str = ""

    @property
    def verified(self) -> bool:
        """Cryptographically sound AND from a publisher this deployment trusts.

        All four, because any three of them prove nothing on their own: a
        signature that does not cover the file is decoration, one whose key does
        not verify is forged, a weak digest is forgeable, and an unanchored
        chain is whoever wanted to sign it.
        """
        return (
            self.parsed
            and self.covers_file
            and self.signature_valid
            and self.chain == "anchored"
            and self.digest_algorithm not in WEAK_DIGESTS
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "present": self.present,
            "parsed": self.parsed,
            "covers_file": self.covers_file,
            "signature_valid": self.signature_valid,
            "chain": self.chain,
            "verified": self.verified,
            "digest_algorithm": self.digest_algorithm,
            # When a countersigner attested the signature existed. "" means no
            # readable timestamp, which is not the same as "signed now".
            "signed_at": self.signed_at,
            # Said out loud, every time: there is no network in this engine, so
            # a revoked certificate still verifies here.
            "revocation_checked": False,
        }
        if self.anchor:
            out["anchor"] = self.anchor
        if self.publisher:
            out["publisher"] = self.publisher.to_dict()
        if self.chain_subjects:
            out["chain"] = list(self.chain_subjects)
            out["chain_status"] = self.chain
        if self.reason:
            out["reason"] = self.reason
        return out


_ABSENT = SignatureResult(reason="no certificate table")


# --- verification -------------------------------------------------------------


def _name_part(name, oid) -> str:
    try:
        found = name.get_attributes_for_oid(oid)
    except Exception:
        return ""
    if not found:
        return ""
    value = found[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _publisher_of(cert) -> Publisher:
    from cryptography.x509.oid import NameOID

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fingerprint = ""
    return Publisher(
        common_name=_name_part(cert.subject, NameOID.COMMON_NAME)[:200],
        organisation=_name_part(cert.subject, NameOID.ORGANIZATION_NAME)[:200],
        country=_name_part(cert.subject, NameOID.COUNTRY_NAME)[:8],
        serial=format(cert.serial_number, "x")[:64],
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        sha256=fingerprint,
    )


def _load_certificates(blob: bytes, budget: list[int]) -> list:
    """Every X.509 certificate in the bag, parsed one at a time.

    `pkcs7.load_der_pkcs7_certificates` refuses some real Authenticode
    signatures outright (it raises `UnknownDefinedBy` on the SpcIndirectData
    content type). Certificates are self-delimiting DER, so they are lifted out
    of the walk directly instead — and one unparseable certificate then costs
    that certificate, not the whole signature.
    """
    root = _read(blob, 0, len(blob))
    certs = []
    for node, _level in _find(blob, root, budget):
        if node.tag != 0x30 or node.length < 64:
            continue
        try:
            cert = x509.load_der_x509_certificate(blob[node.start:node.end])
        except Exception:
            continue
        certs.append(cert)
        if len(certs) >= MAX_CERTS:
            break
    return certs


def _committed_digest(econtent: bytes, budget: list[int]) -> tuple[str, bytes]:
    """(algorithm, digest) that SpcIndirectDataContent commits the file to.

    READ ONLY FROM eContent. THIS IS THE WHOLE SECURITY PROPERTY.

    This used to pre-order walk the ENTIRE PKCS#7 blob and return the first
    DigestInfo-shaped SEQUENCE after any OID equal to SPC_INDIRECT_DATA — the
    exact "scan for likely-looking bytes" mistake `_parse_signed_data` was
    rewritten to avoid, left behind in the one function where it is fatal.

    The attack, confirmed by running the module: take a genuinely
    Microsoft-signed EXE, patch its code, and splice two elements into the
    SignedData `digestAlgorithms` SET — the SPC OID, then a DigestInfo carrying
    SHA-256 of the PATCHED file. `digestAlgorithms` is element 1 and
    `encapContentInfo` is element 2, so the walk reached the forgery first and
    `covers_file` came back True. The signature covers only `signedAttrs`, so
    `signature_valid` stayed True against the real SignerInfo, the real
    Microsoft chain still anchored, and `verified` was True. The report then
    said "Signed by Microsoft Corporation — the Authenticode signature covers
    these exact bytes" over a modified binary, and handed it the
    `STRUCTURAL_SIGNALS` waiver. Growing the certificate table cannot disturb
    the hash being forged, because `authenticode_digest` excludes that table by
    construction — so there is not even a chicken-and-egg to solve.

    `econtent` is the SpcIndirectDataContent CONTENT octets, located by
    `_parse_signed_data` walking the grammar, and it is the same buffer the
    `messageDigest` signed attribute is taken over. Reading the digest from
    anywhere else means the thing checked and the thing signed are different
    objects.

        SpcIndirectDataContent ::= SEQUENCE {
            data          SpcAttributeTypeAndOptionalValue,
            messageDigest DigestInfo }
        DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    """
    if not econtent:
        return "", b""
    try:
        fields = _children(
            econtent,
            _Node(tag=0x30, start=0, header=0, length=len(econtent), value=0),
            budget,
        )
    except DerError:
        return "", b""
    # Exactly two, in order, and the DigestInfo is the SECOND. Not "the first
    # one that parses": position is what makes this unambiguous.
    if len(fields) != 2 or fields[1].tag != 0x30:
        return "", b""
    try:
        kids = _children(econtent, fields[1], budget)
    except DerError:
        return "", b""
    if len(kids) != 2 or kids[0].tag != 0x30 or kids[1].tag != 0x04:
        return "", b""
    try:
        alg = _children(econtent, kids[0], budget)
    except DerError:
        return "", b""
    if not alg or alg[0].tag != 0x06:
        return "", b""
    try:
        name = _DIGESTS.get(_oid(econtent, alg[0]), "")
    except DerError:
        return "", b""
    if not name:
        return "", b""
    return name, econtent[kids[1].value:kids[1].end]


@dataclass(frozen=True)
class _SignedData:
    """The three things a PKCS#7 SignedData has to give up to be checked."""
    #: DER of SpcIndirectDataContent — what messageDigest is taken over.
    econtent: bytes = b""
    #: signedAttrs re-encoded as a SET; this is the byte string that is signed.
    signed_attributes: bytes = b""
    #: The messageDigest attribute's value.
    message_digest: bytes = b""
    #: SignerInfo's own digest algorithm.
    digest_algorithm: str = ""
    #: The signature itself.
    signature: bytes = b""

    #: When a countersigner attested the signature existed, if it said so.
    #: None means no readable timestamp, which is NOT the same as "signed
    #: now" and must never be treated as one.
    signed_at: Any = None


def _der_time(buf: bytes, node: "_Node") -> "datetime | None":
    """UTCTime (0x17) or GeneralizedTime (0x18) as an aware UTC datetime.

    Returns None rather than raising on anything unexpected. A timestamp this
    parser cannot read must leave the existing verdict alone -- refusing to trust
    a binary because our own parser is limited would be a false positive
    introduced to fix a theoretical one.
    """
    if node.tag not in (0x17, 0x18):
        return None
    text = buf[node.value:node.end].decode("ascii", "ignore").strip()
    if not text.endswith("Z"):
        # Local-time and offset forms are legal DER and vanishingly rare here.
        # Reading them wrong is worse than not reading them.
        return None
    text = text[:-1]
    try:
        if node.tag == 0x17:            # YYMMDDHHMM[SS]
            if len(text) == 10:
                text += "00"
            if len(text) != 12:
                return None
            year = int(text[:2])
            # RFC 5280: 00-49 is 2000-2049, 50-99 is 1950-1999.
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        else:                            # YYYYMMDDHHMMSS[.fff]
            text = text.split(".", 1)[0]
            if len(text) != 14:
                return None
            year = int(text[:4])
            rest = text[4:]
        return datetime(
            year, int(rest[0:2]), int(rest[2:4]),
            int(rest[4:6]), int(rest[6:8]), int(rest[8:10]),
            tzinfo=timezone.utc,
        )
    except (ValueError, IndexError):
        return None


def _timestamp_from_rfc3161(buf: bytes, value: "_Node", budget: list[int]):
    """`genTime` out of the TSTInfo inside a timestamp token.

        ContentInfo ::= SEQUENCE { contentType OID, [0] SignedData }
        SignedData  ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
        encapContentInfo ::= SEQUENCE { eContentType OID, [0] OCTET STRING }
        TSTInfo ::= SEQUENCE { version, policy OID, messageImprint,
                               serialNumber, genTime GeneralizedTime, ... }
    """
    try:
        top = _children(buf, value, budget)
        if len(top) < 2 or top[1].tag != 0xA0:
            return None
        explicit = _children(buf, top[1], budget)
        if not explicit or explicit[0].tag != 0x30:
            return None
        signed = _children(buf, explicit[0], budget)
        if len(signed) < 3:
            return None
        encap = _children(buf, signed[2], budget)
        if len(encap) < 2 or encap[1].tag != 0xA0:
            return None
        wrapped = _children(buf, encap[1], budget)
        if not wrapped or wrapped[0].tag != 0x04:
            return None
        inner = buf[wrapped[0].value:wrapped[0].end]
        tst = _children(inner, _read(inner, 0, len(inner)), budget)
        for node in tst:
            if node.tag == 0x18:
                return _der_time(inner, node)
    except DerError:
        return None
    return None


def _timestamp_from_countersignature(buf: bytes, value: "_Node", budget: list[int]):
    """`signingTime` out of a legacy countersignature's signed attributes."""
    try:
        signer = _children(buf, value, budget)
        for field in signer:
            if field.tag != 0xA0:
                continue
            for attr in _children(buf, field, budget):
                if attr.tag != 0x30:
                    continue
                pair = _children(buf, attr, budget)
                if len(pair) != 2 or pair[0].tag != 0x06 or pair[1].tag != 0x31:
                    continue
                if _oid(buf, pair[0]) != OID_SIGNING_TIME:
                    continue
                for item in _children(buf, pair[1], budget):
                    parsed = _der_time(buf, item)
                    if parsed is not None:
                        return parsed
    except DerError:
        return None
    return None


def _signing_time(buf: bytes, unsigned: "_Node", budget: list[int]):
    """When the signature was countersigned, from whichever form is present."""
    try:
        attributes = _children(buf, unsigned, budget)
    except DerError:
        return None
    for attr in attributes:
        if attr.tag != 0x30:
            continue
        try:
            pair = _children(buf, attr, budget)
            if len(pair) != 2 or pair[0].tag != 0x06 or pair[1].tag != 0x31:
                continue
            oid = _oid(buf, pair[0])
            values = _children(buf, pair[1], budget)
        except DerError:
            continue
        if not values:
            continue
        if oid == OID_TIMESTAMP_TOKEN:
            found = _timestamp_from_rfc3161(buf, values[0], budget)
            if found is not None:
                return found
        elif oid == OID_COUNTERSIGNATURE:
            found = _timestamp_from_countersignature(buf, values[0], budget)
            if found is not None:
                return found
    return None


def _parse_signed_data(blob: bytes, budget: list[int]) -> _SignedData:
    """Navigate the structure rather than scanning for likely-looking bytes.

    A first attempt searched the whole blob for "an OCTET STRING of plausible
    length" and for "a [0] whose children look like attributes". It verified 3
    signatures out of 104: certificates contain `[0]` elements too, and a
    countersignature carries a second OCTET STRING that is not the signature
    being checked. Walk the grammar:

        ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
        SignedData  ::= SEQUENCE { version, digestAlgorithms SET,
                                   encapContentInfo, [0] certificates,
                                   [1] crls OPTIONAL, signerInfos SET }
        SignerInfo  ::= SEQUENCE { version, sid, digestAlgorithm,
                                   [0] signedAttrs IMPLICIT, signatureAlgorithm,
                                   signature OCTET STRING, [1] unsignedAttrs }
    """
    outer = _read(blob, 0, len(blob))
    top = _children(blob, outer, budget)
    if len(top) < 2 or top[0].tag != 0x06 or top[1].tag != 0xA0:
        return _SignedData()
    explicit = _children(blob, top[1], budget)
    if not explicit or explicit[0].tag != 0x30:
        return _SignedData()
    signed = _children(blob, explicit[0], budget)
    if len(signed) < 4:
        return _SignedData()

    # encapContentInfo is the third element; SpcIndirectDataContent sits inside
    # its [0], NOT wrapped in an OCTET STRING — Authenticode differs from CMS
    # here, and hashing the wrapper instead of the content is the classic way to
    # get a messageDigest that never matches.
    econtent = b""
    encap = signed[2]
    if encap.tag == 0x30:
        parts = _children(blob, encap, budget)
        if len(parts) >= 2 and parts[1].tag == 0xA0:
            inner = _children(blob, parts[1], budget)
            if inner:
                # The CMS rule: `messageDigest` covers the eContent OCTETS, not
                # the DER element that carries them — so the SEQUENCE header is
                # excluded. Determined by construction against Microsoft-,
                # GlobalSign- and DigiCert-signed binaries, all three of which
                # agree; hashing the element instead is off by exactly the two
                # header bytes and matches nothing.
                node = inner[0]
                econtent = blob[node.value:node.end]

    # signerInfos is the last element, a SET of at least one SignerInfo.
    signer_set = signed[-1]
    if signer_set.tag != 0x31:
        return _SignedData(econtent=econtent)
    signers = _children(blob, signer_set, budget)
    if not signers or signers[0].tag != 0x30:
        return _SignedData(econtent=econtent)
    fields = _children(blob, signers[0], budget)
    if len(fields) < 5:
        return _SignedData(econtent=econtent)

    algorithm = ""
    signed_at = None
    attributes = b""
    message_digest = b""
    signature = b""
    for index, field_node in enumerate(fields):
        if field_node.tag == 0x30 and index == 2:
            alg = _children(blob, field_node, budget)
            if alg and alg[0].tag == 0x06:
                try:
                    algorithm = _DIGESTS.get(_oid(blob, alg[0]), "")
                except DerError:
                    algorithm = ""
        elif field_node.tag == 0xA1:
            # unsignedAttrs. The countersignature timestamp lives here, and
            # it is the difference between "expired" meaning what Windows
            # means and meaning nothing.
            signed_at = _signing_time(blob, field_node, budget)
        elif field_node.tag == 0xA0:
            # The signature is over these attributes re-encoded as a SET, not
            # over the [0] IMPLICIT form they appear in.
            attributes = _encode(0x31, blob[field_node.value:field_node.end])
            for attr in _children(blob, field_node, budget):
                if attr.tag != 0x30:
                    continue
                pair = _children(blob, attr, budget)
                if len(pair) != 2 or pair[0].tag != 0x06 or pair[1].tag != 0x31:
                    continue
                try:
                    oid = _oid(blob, pair[0])
                except DerError:
                    continue
                if oid != OID_MESSAGE_DIGEST:
                    continue
                values = _children(blob, pair[1], budget)
                if values and values[0].tag == 0x04:
                    message_digest = blob[values[0].value:values[0].end]
        elif field_node.tag == 0x04 and index >= 4:
            signature = blob[field_node.value:field_node.end]

    return _SignedData(
        econtent=econtent,
        signed_at=signed_at,
        signed_attributes=attributes,
        message_digest=message_digest,
        digest_algorithm=algorithm,
        signature=signature,
    )


def _encode(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(raw)]) + raw
    return header + body


def _verify_signature(cert, signed: bytes, signature: bytes, algorithm: str) -> bool:
    try:
        digest = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
                  "sha384": hashes.SHA384(), "sha512": hashes.SHA512(),
                  "md5": hashes.MD5()}[algorithm]
    except KeyError:
        return False
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), digest)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(digest))
        else:
            return False
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False
    return True


def _order_chain(certs: list) -> list:
    """Leaf first, then each issuer that is present, longest path wins."""
    if not certs:
        return []
    by_subject: dict[bytes, Any] = {}
    for cert in certs:
        by_subject.setdefault(cert.subject.public_bytes(), cert)
    issuers = {cert.issuer.public_bytes() for cert in certs}
    leaves = [c for c in certs if c.subject.public_bytes() not in issuers]
    # A signing leaf is an end-entity: no CA basic constraint.
    def _is_ca(cert) -> bool:
        try:
            return bool(cert.extensions.get_extension_for_class(
                x509.BasicConstraints).value.ca)
        except Exception:
            return False

    def _signs_code(cert) -> bool:
        """Has the code-signing extended key usage."""
        try:
            usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except Exception:
            return False
        return any(getattr(u, "dotted_string", "") == "1.3.6.1.5.5.7.3.3" for u in usages)

    # An Authenticode bag carries the timestamp authority's certificates too, so
    # "not a CA and not anyone's issuer" is not enough to find the publisher: it
    # named COMODO CA Limited as the publisher of BlueScreenView. The signer is
    # the end-entity certificate issued FOR SIGNING CODE.
    ends = [c for c in certs if not _is_ca(c)]
    candidates = (
        [c for c in ends if _signs_code(c)]
        or [c for c in leaves if not _is_ca(c)]
        or leaves
        or certs
    )
    leaf = candidates[0]
    chain = [leaf]
    seen = {leaf.subject.public_bytes()}
    while True:
        issuer_name = chain[-1].issuer.public_bytes()
        if issuer_name in seen:
            break
        parent = by_subject.get(issuer_name)
        if parent is None:
            break
        chain.append(parent)
        seen.add(issuer_name)
        if len(chain) > 16:
            break
    return chain


def _anchor_expiry(chain, anchor_name: str):
    """When the certificate this chain anchored to stops being valid.

    Returns None whenever it cannot say, and the caller treats None as "do not
    gate". That direction is deliberate: guessing "expired" would take a waiver
    from a file that earned one, and the entire reason expired anchors are still
    trusted is that removing them cost thirty-two genuine Microsoft binaries.

    Everything is inside the try for the same reason. An earlier version compared
    `anchor_name in cert.subject` -- `subject` is an x509 `Name`, not a string,
    which the rest of this module knows -- and raised TypeError on audacity.exe,
    handbrake.exe, putty.exe and winmerge.exe. Four correctly-signed benign
    binaries, turned from "verified" into an exception. A helper that only
    tightens a verdict must never be able to break one.
    """
    if not anchor_name:
        return None
    try:
        for cert in reversed(chain):
            subject = getattr(cert, "subject", None)
            if subject is None:
                continue
            text = subject if isinstance(subject, str) else subject.rfc4514_string()
            if anchor_name not in text and text not in anchor_name:
                continue

            raw_value = getattr(cert, "not_valid_after_utc", None)
            if raw_value is None:
                raw_value = getattr(cert, "not_after", None)
            if raw_value is None:
                return None
            if isinstance(raw_value, datetime):
                parsed_value = raw_value
            else:
                parsed_value = datetime.fromisoformat(str(raw_value))
            if parsed_value.tzinfo is None:
                parsed_value = parsed_value.replace(tzinfo=timezone.utc)
            return parsed_value
    except Exception:  # noqa: BLE001 — see the docstring: never break a verdict
        return None
    return None


def _links_verified(chain: list) -> int:
    """How many certificates from the leaf up are cryptographically linked.

    THIS IS NOT OPTIONAL. `_order_chain` matches issuer NAMES, and a name is
    free to write. Without this, an attacker embeds their own self-issued leaf
    that merely CLAIMS `issuer = Microsoft Code Signing PCA 2024`, staples the
    genuine Microsoft intermediate beside it — a public certificate anyone can
    download — and the chain "reaches" an anchored fingerprint without Microsoft
    having signed anything.

    Returns the index of the highest certificate reachable by verified
    signatures, so the anchor has to be found at or below it.
    """
    reach = 0
    for i in range(len(chain) - 1):
        child, parent = chain[i], chain[i + 1]
        try:
            key = parent.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            else:
                break
        except Exception:  # noqa: BLE001 - a broken link ends the chain, quietly
            break
        reach = i + 1
    return reach


def verify(data: bytes) -> SignatureResult:
    """Everything that can be established about a PE's signature, offline."""
    if not _CRYPTO_AVAILABLE:
        return SignatureResult(reason=f"cryptography unavailable ({_CRYPTO_ERROR})")
    if len(data) > MAX_HASH_BYTES:
        return SignatureResult(reason="file too large to hash")

    blob = _certificate_blob(data)
    if not blob:
        return _ABSENT
    budget = [MAX_DER_STEPS]

    # ORDER MATTERS. The structure is navigated FIRST, and the file digest is
    # then read only out of the eContent that walk located — never scavenged from
    # the blob at large. See `_committed_digest`.
    try:
        certs = _load_certificates(blob, budget)
        parsed = _parse_signed_data(blob, budget)
        algorithm, committed = _committed_digest(parsed.econtent, budget)
    except DerError as exc:
        return SignatureResult(present=True, reason=f"malformed signature: {exc}")
    except Exception as exc:  # noqa: BLE001 - hostile input, never a crash
        return SignatureResult(present=True, reason=f"{type(exc).__name__}: {exc}"[:160])

    if not certs or not algorithm or not committed:
        return SignatureResult(present=True, reason="no signer or no committed digest")

    chain = _order_chain(certs)
    leaf = chain[0]
    subjects = tuple(c.subject.rfc4514_string()[:200] for c in chain)

    try:
        actual = authenticode_digest(data, algorithm)
    except Exception:
        actual = None
    covers = bool(actual and actual == committed)

    valid = False
    try:
        signer_algorithm = parsed.digest_algorithm or algorithm
        if parsed.signed_attributes and parsed.signature:
            valid = _verify_signature(
                leaf, parsed.signed_attributes, parsed.signature, signer_algorithm
            )
            # BOTH halves, or the check is decoration. The signature proves the
            # attributes are the signer's; `messageDigest` inside them proves
            # those attributes are about THIS content; `covers_file` above
            # proves that content is about THESE bytes. Break any link and a
            # valid attribute set can be lifted from another file.
            if valid and parsed.message_digest and parsed.econtent:
                actual_content = hashlib.new(signer_algorithm)
                actual_content.update(parsed.econtent)
                if actual_content.digest() != parsed.message_digest:
                    valid = False
            elif valid:
                valid = False
    except DerError:
        valid = False
    except Exception:  # noqa: BLE001
        valid = False

    from .trust_anchors import anchor_for

    # Only the part of the chain that is cryptographically linked to the leaf
    # may be searched for an anchor. See `_links_verified`.
    reach = _links_verified(chain)
    anchor = anchor_for(chain[: reach + 1])
    if anchor:
        status = "anchored"
    elif chain and chain[-1].issuer == chain[-1].subject:
        status = "self-signed"
    else:
        status = "unanchored"

    # The countersignature timestamp, and the single decision it is allowed to
    # make. `trust_anchors` keeps expired authorities anchored on purpose --
    # dropping them cost 32 genuine Microsoft binaries their waiver for no real
    # security gain -- and names this as what would properly gate them: "was
    # this signed while the authority was valid", which is what Windows checks.
    #
    # So: a signature timestamped AFTER the anchoring authority expired is not
    # verified. A signature with no readable timestamp is left exactly as it
    # was, because refusing to trust a binary because OUR parser is limited
    # would be a false positive invented to fix a theoretical one.
    signed_at = parsed.signed_at
    stamped = signed_at.isoformat() if signed_at is not None else ""
    late = ""
    if status == "anchored" and signed_at is not None:
        expiry = _anchor_expiry(chain[: reach + 1], anchor)
        if expiry is not None and signed_at > expiry:
            status = "unanchored"
            late = (
                f"countersigned {signed_at.date()}, after the anchoring authority "
                f"expired on {expiry.date()}"
            )

    return SignatureResult(
        present=True,
        parsed=True,
        covers_file=covers,
        signature_valid=valid,
        chain=status,
        anchor="" if late else anchor,
        publisher=_publisher_of(leaf),
        digest_algorithm=algorithm,
        chain_subjects=subjects,
        signed_at=stamped,
        reason=late or ("" if covers else "the signature does not cover these bytes"),
    )
