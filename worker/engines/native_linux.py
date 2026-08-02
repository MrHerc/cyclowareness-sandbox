"""The team's own native engine: real execution under a Firejail + seccomp jail.

This is the only engine in the worker that actually runs the sample's own code
on the host CPU. Everything about it is built around one non-negotiable rule:

    If the sample cannot be confined, it does not run.

Concretely, ``available()`` returns False unless BOTH ``firejail`` and
``strace`` are present. There is no "unconfined fallback" — a native engine that
would execute a malware sample outside its jail is worse than no native engine,
so the absence of Firejail disables native detonation entirely and the agent
moves to the emulation path (Qiling) or an external sandbox instead.

The jail we ask Firejail for:
  * ``--net=none``        no network at all (or a sinkhole route if configured)
  * ``--seccomp``         kernel-level syscall filtering
  * ``--private=<dir>``   a throwaway root; the real filesystem is not visible
  * ``--noroot``          drop to an unprivileged user namespace
  * ``--rlimit-*``        cap CPU, file size, and process count

Inside that jail we run the sample under ``strace -f`` and read the syscall
trace back. The trace is the evidence: we turn the sequence of syscalls into
behaviour Signals (spawns a shell, opens a socket, writes files, calls
``ptrace`` to defeat debuggers, installs cron/systemd persistence, maps
writable+executable memory) and lift IOCs (connect() addresses, opened paths)
out of the arguments.

Operational reality (see resources_needed in the delivery notes): this file is
correct but it can only *run* on a Linux host that has firejail + strace and on
which the operator accepts detonating live malware — a disposable, network-
isolated VM. On any other host ``available()`` is False and the engine is
skipped, which is the intended behaviour, not a stub.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

from .base import Engine, Report

#: Families this engine may claim. ELF only — deliberately not `script`.
#:
#: The agent picks the FIRST available engine that supports a family, and this
#: engine is first in priority. So claiming `script` means that the moment
#: firejail is installed, every PowerShell, VBScript and JScript sample stops
#: going to the Windows sandbox and is executed on a Linux host instead, where it
#: cannot run. It would not error: the jail would report a process that did
#: nothing, and a Windows script downloader would come back with no signals at
#: all while a perfectly good Windows guest sat idle.
#:
#: That is this project's oldest failure mode — evidence quietly getting thinner
#: with nothing failing — and it was one `apt install firejail` away. The corpus
#: has five Windows script samples (two .vbs, three .js) that detonate correctly
#: on CAPE today.
#:
#: A genuine POSIX shell script has no engine either way: CAPE refuses it
#: (`File.LINUX_TYPES` covers "POSIX shell script" and "Bourne-Again"), and
#: routing it here would need the submitted suffix, which `supports` does not
#: receive. Worth doing; not worth pretending is done.
_SUPPORTED = {"elf"}

# --- strace line grammar -----------------------------------------------------
# Typical line (with -f):  "1234  openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3"
# We tolerate the leading PID (from -f), unfinished/resumed lines, and signals.
_CALL_RE = re.compile(
    r"""^
        (?:\[[^\]]*\]\s*)?          # optional [pid 1234] style prefix
        (?:\d+\s+)?                 # optional bare pid from -f
        (?P<name>[A-Za-z_][A-Za-z0-9_]*)   # syscall name
        \((?P<args>.*?)\)           # argument list (non-greedy)
        \s*=\s*(?P<ret>-?\d+|\?|0x[0-9a-fA-F]+)  # return value
    """,
    re.VERBOSE,
)

# Extract a quoted string argument (execve path, open path, connect sun_path).
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
# sockaddr_in in a connect() line: sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")
_INET_RE = re.compile(r'inet_addr\("([0-9.]+)"\)')
_INET6_RE = re.compile(r'inet_pton\([^,]+,\s*"([0-9A-Fa-f:]+)"')
_PORT_RE = re.compile(r'sin6?_port=htons\((\d+)\)')

_SHELLS = ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "sh", "bash")
_PERSIST_HINTS = (
    "/etc/cron",
    "/var/spool/cron",
    "crontab",
    "/etc/systemd/system",
    "/.config/systemd",
    "/etc/init.d",
    "/etc/rc.local",
    "/.bashrc",
    "/.profile",
    "/etc/ld.so.preload",
)


class NativeLinuxEngine(Engine):
    name = "native"

    def __init__(self, config) -> None:
        self.config = config

    # -- availability: the safety gate ---------------------------------------
    def _firejail(self) -> str | None:
        return shutil.which(self.config.firejail_bin)

    def _strace(self) -> str | None:
        return shutil.which(self.config.strace_bin)

    def available(self) -> bool:
        """True only when the sample can be confined AND traced.

        Missing firejail is the hard stop: we would rather not run natively than
        run a sample unconfined. Missing strace means we could confine but not
        observe, which is useless, so that also disables the engine.
        """
        return bool(self._firejail() and self._strace())

    @property
    def unavailable_reason(self) -> str | None:
        """Which binary is missing, named.

        `agent.py` prints an engine's reason when it exposes one, "so
        'unavailable' is never read as a bug" — and this engine, the only one
        whose absence an operator can actually fix with a package install, was
        the one that said nothing. Startup read

            engine native   -> unavailable
            engine qiling   -> unavailable: qiling is GPL-2.0 and we do not ship it...

        so the licence stance explained itself at length and the missing
        `apt install firejail` did not. Measured on the reference host: `strace`
        is present, `firejail` is not, and 5,643 detonations have all gone to
        CAPE. This engine has never run a sample.
        """
        missing = [
            name for name, found in (
                (self.config.firejail_bin, self._firejail()),
                (self.config.strace_bin, self._strace()),
            ) if not found
        ]
        if not missing:
            return None
        return (
            f"not installed on this worker: {', '.join(missing)}. "
            "The native engine confines each sample with firejail and reads its "
            "behaviour from strace, and it refuses to run a sample it cannot "
            "confine, so both are required. Install them on the worker host to "
            "enable native Linux detonation."
        )

    def supports(self, family: str) -> bool:
        return family in _SUPPORTED

    # -- execution -----------------------------------------------------------
    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        report = self._report(self.config.worker_name)

        firejail = self._firejail()
        strace = self._strace()
        if not (firejail and strace):
            # Defensive: the agent only calls run() on available() engines, but
            # never execute unconfined if that ever changes.
            return Report.unavailable(
                self.name,
                self.config.worker_name,
                # The same sentence the startup line prints, so an operator who
                # reads a report and an operator who reads the log are told the
                # same thing — and both are told WHICH binary is missing.
                (self.unavailable_reason or "firejail or strace missing")
                + " Refusing to run a sample unconfined (native engine safety "
                "invariant).",
            )

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="cw-native-") as work:
            trace_path = os.path.join(work, "trace.log")
            target = self._stage_sample(sample_path, family, work)

            cmd = self._build_command(firejail, strace, trace_path, target, family, work)
            report.facts["command"] = " ".join(cmd)
            report.facts["confinement"] = "firejail+seccomp,--net=" + (
                self.config.native_sinkhole or "none"
            )

            timed_out = False
            proc_rc: int | None = None
            launcher_stderr = ""
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=work,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.config.engine_timeout_seconds,
                )
                proc_rc = proc.returncode
                launcher_stderr = (proc.stderr or b"").decode("utf-8", "replace")[-400:]
            except subprocess.TimeoutExpired:
                timed_out = True
            except OSError as exc:
                return Report.unavailable(
                    self.name,
                    self.config.worker_name,
                    f"failed to launch confined sample: {exc}",
                )

            trace_text = ""
            if os.path.isfile(trace_path):
                with open(trace_path, "r", errors="replace") as fh:
                    trace_text = fh.read()

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.facts["exit_code"] = proc_rc
        report.facts["timed_out"] = timed_out
        report.facts["syscall_lines"] = trace_text.count("\n")

        if not trace_text.strip():
            # AN EMPTY TRACE IS NOT A QUIET SAMPLE.
            #
            # strace writes the syscalls a process makes, and a process that
            # starts at all makes some -- execve at the very least. A completely
            # empty trace file means strace never attached, which means the jail
            # never ran the sample. Reporting that as "executed and did nothing"
            # is absence of evidence rendered as evidence of absence, on the one
            # engine that runs the sample's own code.
            #
            # `proc_rc` was captured for exactly this and never read.
            if proc_rc not in (0, None):
                return Report.unavailable(
                    self.name,
                    self.config.worker_name,
                    "the jail did not execute the sample: launcher exited "
                    f"{proc_rc}"
                    + (f" ({launcher_stderr.strip()})" if launcher_stderr.strip() else ""),
                )
            # A clean exit with no trace is genuinely ambiguous -- the sample may
            # have refused to run -- so it stays `ran`, but it says the exit code
            # rather than implying the jail worked.
            report.ran = True
            report.facts["note"] = "no syscall trace captured"
            report.add_signal(
                "native.no_trace",
                "Sample produced no observable syscalls",
                "info",
                detail=(
                    f"The jail exited {proc_rc} and strace captured nothing. The "
                    "sample may have exited immediately or refused to run; no "
                    "behaviour was observed either way."
                ),
            )
            return report

        self._analyse_trace(trace_text, report, timed_out)
        return report

    # -- jail construction ---------------------------------------------------
    def _stage_sample(self, sample_path: str, family: str, work: str) -> str:
        """Copy the sample into the throwaway workdir and mark it runnable.

        The original quarantine copy is never made executable; we only ever
        chmod +x the disposable copy that lives inside the jail's private root.
        """
        dest = os.path.join(work, "sample.bin")
        shutil.copyfile(sample_path, dest)
        os.chmod(dest, 0o700)
        return dest

    def _build_command(
        self,
        firejail: str,
        strace: str,
        trace_path: str,
        target: str,
        family: str,
        work: str,
    ) -> list[str]:
        net = f"--net={self.config.native_sinkhole}" if self.config.native_sinkhole else "--net=none"
        jail = [
            firejail,
            "--quiet",
            "--noprofile",
            "--noroot",
            "--seccomp",
            net,
            "--private=" + work,       # throwaway root; host FS not visible
            "--private-dev",
            "--private-tmp",
            "--rlimit-cpu=" + str(max(1, self.config.engine_timeout_seconds)),
            "--rlimit-fsize=104857600",  # 100 MB max file the sample can write
            "--rlimit-nproc=64",
            "--timeout=00:0" + "0:00",   # replaced below with a real value
        ]
        # Firejail wants HH:MM:SS; build it from the timeout budget.
        jail[-1] = "--timeout=" + _hhmmss(self.config.engine_timeout_seconds)

        trace = [
            strace,
            "-f",                       # follow forked children
            "-tt",                      # microsecond timestamps for the timeline
            "-e", "trace=all",
            "-s", "256",                # keep enough of each string arg
            "-o", trace_path,
        ]

        # Scripts run through their interpreter; ELF runs directly.
        if family == "script":
            invoke = ["/bin/sh", target]
        else:
            invoke = [target]

        return [*jail, *trace, *invoke]

    # -- trace -> signals ----------------------------------------------------
    def _analyse_trace(self, trace_text: str, report: Report, timed_out: bool) -> None:
        report.ran = True

        calls: list[tuple[str, str, str]] = []  # (name, args, ret)
        for line in trace_text.splitlines():
            m = _CALL_RE.match(line.strip())
            if m:
                calls.append((m.group("name"), m.group("args"), m.group("ret")))

        report.facts["syscalls_parsed"] = len(calls)

        # Behaviour accumulators.
        spawned: list[str] = []
        writes: list[str] = []
        connects: list[str] = []
        persistence: list[str] = []
        ptrace_seen = False
        wx_mem = False

        base_t = None
        for idx, (name, args, ret) in enumerate(calls):
            # execve / execveat -> child process; flag shells.
            if name in ("execve", "execveat"):
                path = _first_quoted(args)
                if path:
                    spawned.append(path)
                    if path in _SHELLS or os.path.basename(path) in ("sh", "bash", "dash"):
                        if not _has_signal(report, "native.spawns_shell"):
                            report.add_signal(
                                "native.spawns_shell",
                                "Sample spawned a command shell",
                                "high",
                                detail=f"execve({path})",
                                evidence={"path": path},
                            )
                            report.add_event(idx, "process", f"exec {path}")

            # network
            elif name in ("connect", "sendto", "connect4"):
                ip = _INET_RE.search(args)
                ip6 = _INET6_RE.search(args)
                port = _PORT_RE.search(args)
                addr = ip.group(1) if ip else (ip6.group(1) if ip6 else None)
                if addr and not addr.startswith("127.") and addr != "::1":
                    tag = addr + (f":{port.group(1)}" if port else "")
                    connects.append(tag)
                    report.add_ioc("ips", addr)
                    report.add_event(idx, "network", f"connect {tag}")

            elif name in ("socket",):
                report.facts.setdefault("opened_socket", True)

            # file writes: open/openat with a write flag, or plain write/creat
            elif name in ("open", "openat", "creat"):
                if _is_write_open(args):
                    path = _write_target(name, args)
                    if path:
                        writes.append(path)
                        report.add_ioc("file_paths", path)
                        if _looks_persistent(path):
                            persistence.append(path)

            elif name in ("rename", "renameat", "renameat2", "link", "symlink"):
                for q in _QUOTED_RE.findall(args):
                    if _looks_persistent(q):
                        persistence.append(q)
                        report.add_ioc("file_paths", q)

            # anti-debug / process injection
            elif name == "ptrace":
                ptrace_seen = True

            elif name in ("mprotect", "mmap"):
                if _is_wx(args):
                    wx_mem = True

        # --- derive the behaviour signals --------------------------------------
        if connects:
            report.add_signal(
                "native.network_connect",
                "Sample opened outbound network connections",
                "high",
                detail="Connected to: " + ", ".join(sorted(set(connects))[:10]),
                evidence={"endpoints": sorted(set(connects))},
            )

        if writes:
            uniq = sorted(set(writes))
            report.add_signal(
                "native.file_write",
                f"Sample wrote {len(uniq)} file path(s)",
                "medium" if not persistence else "high",
                detail="Wrote: " + ", ".join(uniq[:10]),
                evidence={"paths": uniq[:50]},
            )

        if persistence:
            uniq = sorted(set(persistence))
            report.add_signal(
                "native.persistence",
                "Sample touched a persistence location",
                "critical",
                detail="cron/systemd/init/profile write: " + ", ".join(uniq[:10]),
                evidence={"paths": uniq},
            )
            report.add_event(len(calls), "persistence", uniq[0])

        if ptrace_seen:
            report.add_signal(
                "native.anti_debug",
                "Sample called ptrace (anti-debugging or injection)",
                "high",
                detail="ptrace() indicates a debugger check or code injection into "
                "another process.",
            )
            report.add_event(len(calls), "anti-analysis", "ptrace")

        if wx_mem:
            report.add_signal(
                "native.wx_memory",
                "Sample mapped writable+executable memory",
                "high",
                detail="mmap/mprotect with PROT_WRITE|PROT_EXEC is a common "
                "unpacking / self-modifying-code pattern.",
            )
            report.add_event(len(calls), "memory", "W+X mapping")

        if len(spawned) > 1:
            report.facts["child_processes"] = sorted(set(spawned))

        if timed_out:
            report.add_signal(
                "native.timeout",
                "Sample ran until the analysis timeout",
                "low",
                detail=f"Still executing at {self.config.engine_timeout_seconds}s; "
                "long-running behaviour was cut off. Findings so far are reported.",
            )

        if not report.signals:
            report.add_signal(
                "native.benign_trace",
                "No malicious behaviour observed in the trace",
                "info",
                detail="Executed under the jail; the captured syscalls showed no "
                "network, persistence, shell, or anti-analysis behaviour.",
            )


# --- module helpers ----------------------------------------------------------
def _hhmmss(seconds: int) -> str:
    seconds = max(1, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _first_quoted(args: str) -> str | None:
    m = _QUOTED_RE.search(args)
    if not m:
        return None
    return _unescape(m.group(1))


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n").replace("\\t", "\t")


def _is_write_open(args: str) -> bool:
    return bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC", args))


def _write_target(name: str, args: str) -> str | None:
    quoted = _QUOTED_RE.findall(args)
    if not quoted:
        return None
    # openat(AT_FDCWD, "path", ...) -> the path is the first (only) quoted arg;
    # open("path", ...) -> likewise the first quoted arg.
    return _unescape(quoted[0])


def _looks_persistent(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _PERSIST_HINTS)


def _is_wx(args: str) -> bool:
    return "PROT_WRITE" in args and "PROT_EXEC" in args


def _has_signal(report: Report, signal_id: str) -> bool:
    return any(s.get("id") == signal_id for s in report.signals)
