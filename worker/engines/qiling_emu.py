"""Safe emulation path: Qiling — an OPTIONAL adapter the operator opts into.

LICENCE, first, because it governs how this file exists at all: Qiling is
GPL-2.0 and is **not** a dependency of this product. It is absent from
``requirements.txt`` and from the worker Dockerfile, because importing a GPL-2.0
library in-process inside an image we distribute would make that image a
derivative work of it, which is incompatible with the BUSL-1.1 licence on
Cyclowareness Sandbox. What ships is this adapter — our own code, calling a
public API. An operator who wants emulation installs ``qiling`` on their own
worker; that is their licence decision about their own deployment, and we take
no position on it beyond stating the obligation. Until they install it,
``available()`` is False and the agent skips this engine entirely.

Qiling is a binary emulation framework — it runs the sample's instructions in an
emulated CPU (via Unicorn) against an emulated OS, hooking every syscall / API
call. Crucially, the sample's code never touches the real kernel: a ``connect``
or ``CreateFileW`` is intercepted by Qiling, not executed by the host. That is
why this engine is the demonstrable native-behaviour path when no isolation VM
is available — emulation is safe even on a workstation, because nothing is
actually detonated.

The trade-off is fidelity: emulation covers common Windows/Linux API surface but
not every packer or kernel trick, so the native Firejail engine is preferred
when it is available and the Qiling engine is the fallback. Both emit the same
Report shape, so the backend cannot tell — and does not need to — which one ran.

``available()`` is False unless the ``qiling`` package imports. The import is
guarded so this module loads (and py_compiles) on a host without Qiling — which
is every host we ship — and just reports itself unavailable. Emulation also
needs a "rootfs" (the emulated OS files Qiling ships / the operator provides);
without one, individual samples are reported ``ran=False`` with a clear reason
rather than crashing the loop.
"""
from __future__ import annotations

import os
import time

from .base import Engine, Report

# Guarded import: never make package import depend on an optional heavy library.
try:  # pragma: no cover - depends on optional dependency
    import qiling  # type: ignore
    from qiling import Qiling  # type: ignore
    from qiling.const import QL_VERBOSE  # type: ignore

    _QILING_IMPORT_ERROR: str | None = None
except Exception as exc:  # ImportError, or a broken partial install
    qiling = None  # type: ignore
    Qiling = None  # type: ignore
    QL_VERBOSE = None  # type: ignore
    _QILING_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


_SUPPORTED = {"pe", "elf"}

# One sentence, said once, wherever the operator meets this engine switched off:
# the absence is a licence decision we made for our distribution, and installing
# it is a licence decision they make for theirs.
_NOT_INSTALLED_REASON = (
    "qiling is not installed on this worker, and Cyclowareness Sandbox does not "
    "ship it: qiling is GPL-2.0, and importing it in-process in an image we "
    "distribute would make that image a derivative work of a GPL-2.0 library. "
    "This module is an optional adapter, not a dependency. To enable emulation, "
    "install it yourself on your own worker (pip install qiling, plus a rootfs "
    "under QILING_ROOTFS). Accepting Qiling's GPL-2.0 terms for your deployment "
    "is your decision, not ours"
)

# Where the emulated OS filesystems live. Qiling needs a rootfs per target OS;
# operators drop them under this tree (or set QILING_ROOTFS to point elsewhere).
_DEFAULT_ROOTFS = os.environ.get("QILING_ROOTFS", "/opt/qiling/rootfs")


class QilingEngine(Engine):
    name = "qiling"

    def __init__(self, config) -> None:
        self.config = config
        self.rootfs_base = os.environ.get("QILING_ROOTFS", _DEFAULT_ROOTFS)

    def available(self) -> bool:
        return qiling is not None

    @property
    def unavailable_reason(self) -> str | None:
        """Why this engine is off, in the operator's terms. The agent logs it at
        startup so "engine qiling -> unavailable" is never mistaken for a bug."""
        if qiling is not None:
            return None
        return f"{_NOT_INSTALLED_REASON} ({_QILING_IMPORT_ERROR})."

    def supports(self, family: str) -> bool:
        return family in _SUPPORTED

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        if qiling is None:
            return Report.unavailable(
                self.name,
                self.config.worker_name,
                self.unavailable_reason or _NOT_INSTALLED_REASON,
            )

        rootfs = self._rootfs_for(family, sample_path)
        if not rootfs or not os.path.isdir(rootfs):
            return Report.unavailable(
                self.name,
                self.config.worker_name,
                f"no Qiling rootfs available for family '{family}' "
                f"(looked under {self.rootfs_base}); emulation needs an emulated "
                "OS filesystem to run against.",
            )

        report = self._report(self.config.worker_name)
        report.facts["rootfs"] = rootfs
        report.facts["emulated"] = True
        started = time.monotonic()

        # Collected behaviour, populated by the hooks below.
        events: dict[str, list] = {"exec": [], "net": [], "files": [], "regs": []}

        try:
            ql = Qiling(
                [sample_path],
                rootfs,
                verbose=QL_VERBOSE.OFF if QL_VERBOSE is not None else None,
                console=False,
            )
        except Exception as exc:  # emulator refused to load the binary
            report.duration_ms = int((time.monotonic() - started) * 1000)
            return Report.unavailable(
                self.name,
                self.config.worker_name,
                f"Qiling could not load the sample ({type(exc).__name__}: {exc}).",
            )

        self._install_hooks(ql, events, report)

        try:
            ql.run(timeout=self.config.engine_timeout_seconds * 1_000_000)  # microseconds
            report.facts["completed"] = True
        except Exception as exc:  # emulation faulted — still report what we saw
            report.facts["emulation_error"] = f"{type(exc).__name__}: {exc}"

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.ran = True
        self._derive_signals(events, report)
        return report

    # -- internals -----------------------------------------------------------
    def _rootfs_for(self, family: str, sample_path: str) -> str | None:
        """Pick the emulated-OS filesystem. Layout under the rootfs base:

            <base>/x8664_linux, <base>/x86_windows, <base>/x8664_windows ...

        We keep the mapping coarse (arch detection would inspect the header);
        operators typically symlink the arch they analyse to a stable name.
        """
        candidates = []
        if family == "elf":
            candidates = ["x8664_linux", "x86_linux", "arm_linux", "linux"]
        elif family == "pe":
            candidates = ["x8664_windows", "x86_windows", "windows"]
        for name in candidates:
            path = os.path.join(self.rootfs_base, name)
            if os.path.isdir(path):
                return path
        # A bare rootfs base is also acceptable if the operator laid it out flat.
        return self.rootfs_base if os.path.isdir(self.rootfs_base) else None

    def _install_hooks(self, ql, events: dict, report: Report) -> None:
        """Hook the syscall / API surface we turn into signals.

        Hook registration differs across Qiling versions; each is wrapped so a
        missing hook point degrades to "we saw less" rather than crashing.
        """

        def on_exec(ql_, *a, **k):
            try:
                path = ql_.os.utils.read_cstring(a[0]) if a else "?"
            except Exception:
                path = "?"
            events["exec"].append(str(path))
            report.add_event(len(events["exec"]), "process", f"exec {path}")
            return 0

        def on_connect(ql_, *a, **k):
            events["net"].append(tuple(a))
            report.add_event(len(events["net"]), "network", "connect()")
            return 0

        def on_open(ql_, *a, **k):
            try:
                path = ql_.os.utils.read_cstring(a[0]) if a else "?"
            except Exception:
                path = "?"
            events["files"].append(str(path))
            return 0

        # Linux syscalls.
        for sysname, cb in (
            ("execve", on_exec),
            ("connect", on_connect),
            ("open", on_open),
            ("openat", on_open),
        ):
            try:
                ql.os.set_syscall(sysname, cb)
            except Exception:
                pass

        # Windows API (best-effort; only relevant with a windows rootfs).
        for apiname, cb in (
            ("CreateProcessW", on_exec),
            ("CreateProcessA", on_exec),
            ("connect", on_connect),
            ("InternetConnectW", on_connect),
            ("CreateFileW", on_open),
            ("CreateFileA", on_open),
        ):
            try:
                ql.os.set_api(apiname, cb)
            except Exception:
                pass

    def _derive_signals(self, events: dict, report: Report) -> None:
        if events["net"]:
            report.add_signal(
                "qiling.network_call",
                "Emulated sample attempted network connections",
                "high",
                detail=f"{len(events['net'])} connect/network API call(s) intercepted "
                "during emulation (not executed against a real network).",
            )
        if events["exec"]:
            report.add_signal(
                "qiling.process_create",
                "Emulated sample created processes",
                "medium",
                detail="Process-creation calls: " + ", ".join(events["exec"][:8]),
                evidence={"targets": events["exec"][:20]},
            )
            for target in events["exec"]:
                if any(sh in target for sh in ("sh", "cmd", "powershell", "bash")):
                    report.add_signal(
                        "qiling.spawns_shell",
                        "Emulated sample spawned a shell/interpreter",
                        "high",
                        detail=target,
                    )
                    break
        if events["files"]:
            uniq = sorted(set(events["files"]))
            for path in uniq:
                report.add_ioc("file_paths", path)
            report.add_signal(
                "qiling.file_access",
                f"Emulated sample touched {len(uniq)} file path(s)",
                "low",
                detail="Opened/created: " + ", ".join(uniq[:8]),
                evidence={"paths": uniq[:50]},
            )
        if not report.signals:
            report.add_signal(
                "qiling.benign_emulation",
                "No notable behaviour during emulation",
                "info",
                detail="Emulation completed without network, process, or file "
                "activity on the hooked API surface.",
            )
