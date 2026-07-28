"""Deep static analysis for APK, JAR and disk images.

These types are ZIP or filesystem containers; the point of the test is that the
engine reaches inside them and reasons about what they carry — Android
permissions and DEX APIs, Java class behaviour, files bundled on a disk image —
rather than treating them as opaque blobs. Samples are crafted in-memory to
genuinely exercise each parser (a real AXML string pool, a real Java constant
pool, a real ISO9660 volume descriptor and directory).
"""
from __future__ import annotations

import io
import struct
import zipfile

from app.engine import pipeline, storage


def _run(db, name: str, data: bytes):
    stored = storage.store_bytes(data)
    job = pipeline.new_job(db, stored, original_name=name, submitted_by="test", tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    fired = {
        s["id"]
        for payload in (job.analysis or {}).values()
        if payload.get("ran")
        for s in payload.get("signals", [])
    }
    return job, fired


def test_apk_permissions_and_apis(db):
    manifest = b"\x03\x00\x08\x00" + b"\x00" * 16 + (
        b"android.permission.SEND_SMS\x00"
        b"android.permission.BIND_ACCESSIBILITY_SERVICE\x00"
        b"android.permission.RECEIVE_BOOT_COMPLETED\x00"
        b"android.permission.SYSTEM_ALERT_WINDOW\x00"
        b"com.evil.bank\x00"
    )
    dex = b"dex\n035\x00" + b"\x00" * 16 + (
        b"Ljava/lang/Runtime;\x00exec\x00Landroid/telephony/SmsManager;\x00"
        b"sendTextMessage\x00Ldalvik/system/DexClassLoader;\x00http://evil.test/c2\x00"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 32)
        z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)

    job, fired = _run(db, "bank_update.apk", buf.getvalue())

    assert job.family == "apk"
    assert job.status == "completed"
    assert "apk.accessibility_abuse" in fired  # the critical one
    assert "apk.dangerous_permission" in fired
    assert "apk.suspicious_api" in fired
    assert "apk.multiple_dex" in fired
    assert job.final_score >= 60  # this combination is high-risk
    assert "evil.test" in job.iocs.get("domains", []) or "http://evil.test/c2" in job.iocs.get("urls", [])


def _java_class(strings: list[str]) -> bytes:
    pool = b"".join(struct.pack(">BH", 1, len(s.encode())) + s.encode() for s in strings)
    body = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + struct.pack(">H", len(strings) + 1) + pool
    body += struct.pack(">HHHHHHH", 0x21, 0, 0, 0, 0, 0, 0)
    return body


def test_jar_class_behaviour(db):
    main = _java_class([
        "java/lang/Runtime", "exec", "java/net/URLClassLoader", "loadClass",
        "java/lang/reflect/Method", "setAccessible", "java/lang/System", "loadLibrary",
        "http://evil.test/payload.bin", "45.77.88.99",
    ])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nMain-Class: com.evil.Main\n")
        z.writestr("com/evil/Main.class", main)
        z.writestr("native/libcore.so", b"\x7fELF" + b"\x00" * 40)

    job, fired = _run(db, "tool.jar", buf.getvalue())

    assert job.family == "jar"
    assert "jar.runtime_exec" in fired
    assert "jar.classloader" in fired
    assert "45.77.88.99" in job.iocs.get("ips", [])


def _both32(v: int) -> bytes:
    return struct.pack("<I", v) + struct.pack(">I", v)


def _both16(v: int) -> bytes:
    return struct.pack("<H", v) + struct.pack(">H", v)


def _iso_record(lba: int, size: int, flags: int, name: str) -> bytes:
    name_b = name.encode()
    base = 33 + len(name_b)
    length = base + (base % 2)
    r = bytearray(length)
    r[0] = length
    r[2:10] = _both32(lba)
    r[10:18] = _both32(size)
    r[18:25] = bytes([80, 1, 1, 0, 0, 0, 0])
    r[25] = flags
    r[32] = len(name_b)
    r[33:33 + len(name_b)] = name_b
    return bytes(r)


def test_iso_lists_files_and_finds_executable(db):
    SEC = 2048
    readme = b"MZ" + b"\x90" * 80
    autorun = b"[autorun]\r\nopen=setup.exe\r\nicon=http://evil.test/x.ico\r\n"
    root = bytearray()
    root += _iso_record(18, SEC, 0x02, "\x00")
    root += _iso_record(18, SEC, 0x02, "\x01")
    root += _iso_record(19, len(readme), 0x00, "README.EXE;1")
    root += _iso_record(20, len(autorun), 0x00, "AUTORUN.INF;1")

    pvd = bytearray(SEC)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[128:132] = _both16(SEC)
    pvd[156:190] = _iso_record(18, SEC, 0x02, "\x00")
    term = bytearray(SEC)
    term[0] = 255
    term[1:6] = b"CD001"

    img = bytearray(SEC * 21)
    img[SEC * 16:SEC * 16 + SEC] = pvd
    img[SEC * 17:SEC * 17 + SEC] = term
    img[SEC * 18:SEC * 18 + len(root)] = root
    img[SEC * 19:SEC * 19 + len(readme)] = readme
    img[SEC * 20:SEC * 20 + len(autorun)] = autorun

    job, fired = _run(db, "distribution.iso", bytes(img))

    assert job.family == "diskimage"
    assert "diskimage.embedded_executable" in fired
    assert "diskimage.autorun" in fired


def test_raw_img_scanned_for_embedded_executable(db):
    raw = bytearray(2048 * 12)
    raw[1000:1004] = b"\x7fELF"
    raw[4000:4040] = b"connect http://evil.test/payload 8.8.8.8 done"

    job, fired = _run(db, "usb_dump.img", bytes(raw))

    # A raw image with no filesystem still routes to the disk-image analyzer.
    assert job.family == "diskimage"
    assert "diskimage.embedded_executable" in fired
