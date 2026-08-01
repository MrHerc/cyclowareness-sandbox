"""What a sample can *do*, distilled from the signals the analyzers fired.

One shared taxonomy so the impact rating, the threat classification and the
MITRE ATT&CK mapping all reason about the same observed capabilities rather
than re-deriving them three different ways.

Two rules make this trustworthy, and both exist because violating them produced
a 90% false-positive rate on ordinary business files:

1. **Match exact signal ids, never substrings of free text.** A signal's ``id``
   is its stable machine identifier (``office.autoexec_macro``); its ``title``
   is prose written for a human. Substring-matching prose is how ``"rop"``
   matched inside *ent-rop-y* and turned every high-entropy installer into an
   "Exploit", and how ``"encrypt"`` matched ``office.encrypted`` — a
   password-protected document — and reported it as ransomware.

2. **A capability is something the sample can DO, not something it mentions.**
   A PDF containing a hyperlink has not communicated with anything; a document
   that fetches a remote template on open has. Passive string evidence still
   raises the rule score, but it must never assert a capability, because
   capabilities drive the impact vector and the threat classification.

Info-severity signals are neutral facts (``pe.signature_present`` means the
binary is *signed* — a good sign) and never assert a capability.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .contracts import SEVERITY_ORDER, IOCs, Signal

#: Below this severity a signal is a fact, not a capability.
_MIN_SEVERITY = SEVERITY_ORDER["low"]

#: capability -> the exact signal ids that demonstrate it.
#: Every id here is emitted by a real analyzer; nothing is speculative.
CAPABILITY_SIGNALS: dict[str, frozenset[str]] = {
    # The sample can cause code to run.
    "execution": frozenset({
        # `\objupdate` makes the embedded object update — that is, run —
        # when the document opens. Word does not emit it.
        "rtf.object_auto_executes",
        # A shortcut whose arguments are a hidden, encoded PowerShell.
        "lnk.command_line_attack",
        "office.autoexec_macro", "office.xlm_macro", "office.dde_field", "office.vba_present",
        "pdf.launch_action", "pdf.open_action", "pdf.javascript",
        "jar.runtime_exec",
        "apk.suspicious_api",
        "diskimage.autorun",
        "script.download_and_execute", "script.dynamic_execution",
        "script.encoded_command", "script.execution_policy_bypass",
    }),
    # The sample actively reaches out. Passive URLs in strings are NOT this.
    "network": frozenset({
        # An OLE2Link moniker fetches the object when the document opens.
        "rtf.remote_object_link",
        "office.remote_template",
        "pdf.submit_form",
        "script.download_and_execute",
    }),
    # The sample reads secrets or personal data.
    "credential": frozenset({
        "script.credential_access",
        # THE GROUPS THAT ARE ACTUALLY ABOUT PERSONAL DATA.
        #
        # `apk.dangerous_permission` used to be one id for eight groups --
        # SMS, call log and contacts, boot persistence, silent install,
        # screen overlay, microphone, camera, location -- and every one of
        # them asserted "reads secrets or personal data". Asking to start
        # at boot is not reading anything.
        "apk.dangerous_permission.sms",
        "apk.dangerous_permission.call_log_and_contacts",
        "apk.dangerous_permission.microphone",
        "apk.dangerous_permission.camera",
        "apk.dangerous_permission.location",
        # The bare id stays so rows assessed before the split keep the
        # capability they were given rather than quietly losing it.
        "apk.dangerous_permission",
    }),
    # The sample survives a reboot / re-runs itself.
    "persistence": frozenset({
        "script.persistence",
        # Where boot persistence belongs, rather than under `credential`.
        "apk.dangerous_permission.boot_persistence",
        "diskimage.autorun",
    }),
    # The sample hides from analysis or disables defences.
    "evasion": frozenset({
        "pe.packer_section_name",
        "elf.packed",
        "office.macro_obfuscation", "office.vba_stomping",
        # ONE part unreadable inside an otherwise readable archive. Not
        # `office.parse_failed`, which fires when the whole file will not open
        # and cannot tell deliberate damage from ordinary corruption; this is
        # the specific shape -- both SideWinder samples have exactly one broken
        # relationship and every other part intact.
        "office.part_unreadable",
        # `pdf.object_streams` was here. Object streams are how every PDF
        # 1.5+ writer stores its structure, and the signal that reports them
        # is `info`. It asserted T1027 through the word "obfuscation" in its
        # own former id, on documents whose verdict was clean.
        "jar.obfuscated",
        "script.obfuscation_high", "script.defense_evasion",
        "script.amsi_or_etw_tamper", "script.hidden_window", "script.decoded_layer",
    }),
    # The sample loads or runs code that is not statically visible.
    # pe.import_combination (not the individual import groups, which are facts
    # present in ordinary software) is what argues for this on a PE.
    #
    # `pe.writable_executable_section` used to be in this set and is NOT evidence
    # of injection. A section that is both writable and executable is how every
    # packer works — the stub must decompress into memory it then runs — so it is
    # a fact about how the binary was BUILT, not about what it does to other
    # processes. Measured on the corpus: it fires on 4 of 102 malware, and on
    # Rufus, a signed and widely-used disk utility that ships UPX-packed, where
    # it alone supplied the accusing capability that made it `malicious` at 64.
    #
    # The signal still exists and still raises the score. It just no longer
    # asserts a capability on its own. Real injection is something the dynamic
    # tier watches happen.
    "injection": frozenset({
        "pe.import_combination",
        "jar.classloader", "jar.reflection", "jar.script_engine",
        "apk.dynamic_code",
        "script.dynamic_execution",
    }),
    # The sample carries another executable payload SOMEWHERE IT SHOULD NOT.
    #
    # A PDF with an embedded file and a Word document with an embedded object
    # are droppers: those formats are documents, and a program inside one is
    # there to be run by someone who thought they were opening a document.
    #
    # A CONTAINER carrying a program is not. An ISO, a zip and an installer
    # package exist to carry programs — that is the format working, and calling
    # it "dropper" made an ISO of PuTTY `DiskImage.Dropper.EmbeddedExecutable`
    # while both of its members analysed clean. Containers are UNPACKED now, so
    # each member is judged on its own and the container inherits the worst of
    # them; that inheritance is the evidence, and it is a far better one than
    # the mere presence of a header.
    #
    # `generic.embedded_executable` stays: it fires on a file that is NOT a
    # recognised container (the exempt list lives in `generic.py`), which is the
    # document case above by another route.
    "dropper": frozenset({
        "generic.embedded_executable",
        # `pdf.embedded_file` was here, and it asserted `dropper` on the mere
        # presence of an /EmbeddedFile entry. Measured over 45 malicious PDFs
        # and 20 ordinary documents: 0 of the malicious carry one and 10 of the
        # ordinary ones do — every fillable IRS form on the list, because that
        # is where a form keeps its own XFA data. Ten accusations, no catches.
        # The attachment is still reported; the capability moved to the case
        # that can support one.
        "pdf.embedded_executable",
        "office.embedded_object",
        # A document whose largest part is another document. Three of the
        # five malicious .docx measured here were wrappers around a
        # multi-megabyte RTF.
        "office.carries_a_document",
        "rtf.embedded_executable", "rtf.embedded_ole_package",
        # A shortcut is a pointer. One carrying tens of kilobytes is
        # carrying a payload that its command line reassembles.
        "lnk.oversized_for_a_shortcut",
    }),
    # The sample abuses elevation / device-administration controls.
    "privilege": frozenset({
        "apk.accessibility_abuse",
    }),
    # The sample disguises what it is.
    "deception": frozenset({
        "generic.extension_mismatch",
        # A document icon on a shortcut that runs a shell.
        "lnk.icon_disguise",
        # A page whose entire surface is one link, and a page that tells the
        # reader it cannot be displayed here so they should open it in a
        # browser. Both are the document lying about what it is.
        #
        # `pdf.page_renders_no_text` is deliberately NOT here. A poster whose
        # text was flattened to outlines on export renders nothing either, and
        # the benign corpus contains no such document — so there is no evidence
        # for the stronger claim, and it stays a `medium` that contributes to
        # the score without asserting intent.
        "pdf.page_is_one_click_target",
        "pdf.reader_incompatible_lure",
        "archive.double_extension",
        "generic.double_extension",
        "diskimage.suspicious_filename",
        "generic.punycode_or_lookalike_domain",
        "archive.path_traversal",
    }),
    #: `destruction` and `discovery` stay deliberately empty: no analyzer
    #: produces static evidence of either, and claiming one from evidence we do
    #: not have is exactly the dishonesty this engine refuses. They remain as
    #: keys so the dynamic tier can populate them from a real detonation.
    "destruction": frozenset(),
    #: `exploit` is no longer empty, and the bar for adding to it is the one
    #: the note above sets: evidence we actually have.
    #:
    #: CLSID {0002CE02-0000-0000-C000-000000000046} is Microsoft Equation
    #: Editor — the component behind CVE-2017-11882 and CVE-2018-0802, retired
    #: by Microsoft in 2018. A document that embeds it in 2026 is not doing
    #: mathematics. It is also HIGH_CONSEQUENCE, so it needs corroboration
    #: before it accuses on its own, which is the right treatment for the
    #: strongest claim the RTF analyzer can make.
    "exploit": frozenset({
        "rtf.equation_editor_object",
    }),
    "discovery": frozenset(),
}

#: Behaviour reported by the off-host worker arrives as ``native.*`` /
#: ``dynamic.*`` ids. That tier observed the sample RUNNING, so its evidence is
#: authoritative; it is matched on the id's final segment against whole tokens.
#:
#: `joe.` belongs here for the same reason the others do — JoeSandboxEngine
#: emits `joe.malicious` and `joe.threat.<name>` — and its absence meant a Joe
#: report demonstrated no capability at all. Since "malicious" additionally
#: requires a nameable capability, a deployment whose only dynamic engine was
#: Joe could never reach a malicious verdict: every sample came back
#: suspicious / `Win32.Clean`.
_DYNAMIC_PREFIXES = (
    "native.", "dynamic.", "cuckoo.", "capev2.", "qiling.", "firejail.", "joe.",
)
_DYNAMIC_TOKENS: dict[str, tuple[str, ...]] = {
    "execution": ("exec", "spawns_shell", "process_create", "run"),
    "network": ("network", "beacon", "c2", "connect", "dns", "http", "exfil"),
    # "infostealer" is the same whole-token miss as the destruction set: WannaCry
    # emitted `infostealer_browser` and `infostealer_cookies`, neither of which
    # matches "steal", so the rating came back C:N — no confidentiality impact —
    # for a sample observed reading browser credential stores.
    "credential": (
        "credential",
        "infostealer",
        "keylog",
        "clipboard",
        "browser_data",
        "steal",
    ),
    "persistence": ("persistence", "autostart", "registry_run", "schtask", "cron", "service_install"),
    "evasion": ("anti_debug", "anti_vm", "sandbox_evasion", "unhook", "tamper", "disable_defender"),
    "injection": ("injection", "hollow", "shellcode", "reflective", "wx_memory"),
    # Matching is whole-token, and this set missed almost everything a real
    # ransomware detonation emits. Measured on WannaCry
    # (ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa) through
    # CAPEv2 on our own sandbox: `ransomware_file_modifications` did not match
    # "ransom", `mass_data_encryption` did not match "encrypt_files", and
    # `deletes_shadow_copies` did not match "delete_shadow". Only
    # `mass_ransom_note_drop` matched — so the most recognisable ransomware in
    # existence earned its destruction capability on a single lucky hit, and a
    # variant that skipped the ransom note would have scored none at all.
    #
    # The keys below are written against the vocabulary a sandbox actually uses.
    # Multi-token keys keep it specific: "encryption" alone would fire on any
    # program that calls a crypto API; "mass" plus "encryption" would not.
    "destruction": (
        "ransom",
        "ransomware",
        "encrypt_files",
        "mass_encryption",
        "mass_data_encryption",
        "shadow_copies",
        "delete_shadow",
        "deletes_shadow",
        "system_state_backup",
        "wiper",
        "overwrite",
    ),
    "exploit": ("exploit", "heap_spray", "rop_chain"),
    "privilege": ("privilege", "uac_bypass", "getsystem", "token_theft"),
    "discovery": ("discovery", "enumerate", "systeminfo", "recon"),
    "dropper": ("dropped_file", "drops"),
}

CAPABILITY_LABELS: dict[str, str] = {
    "execution": "Code execution",
    "network": "Network / C2 communication",
    "credential": "Credential & data access",
    "persistence": "Persistence",
    "evasion": "Defence evasion",
    "injection": "Code injection / dynamic loading",
    "dropper": "Carries an executable payload",
    "privilege": "Privilege / elevation abuse",
    "deception": "Disguise / misrepresentation",
    "destruction": "Destructive / ransomware",
    "exploit": "Exploitation",
    "discovery": "Discovery / reconnaissance",
}

#: The sandbox's OWN classification of a behavioural signature, mapped to our
#: capability vocabulary.
#:
#: This exists because inferring a capability from a signature *name* does not
#: work, and cannot be made to work by adding keys. Measured on a real WannaCry
#: detonation: 8 of its 22 high-severity signals matched no key at all, because a
#: sandbox writes `unbacked_process_creation` where a developer writes
#: `process_create`, and `antivm_checks_available_memory` where a developer
#: writes `anti_vm`. Every one of those signatures carries a `categories` field
#: saying "execution", "evasion" and so on — an authoritative answer we were
#: throwing away in favour of guessing.
#:
#: Only categories that genuinely imply a capability are mapped. "generic",
#: "static", "malware", "ipc", "command" and the lateral-movement categories are
#: deliberately absent: either they say nothing specific, or they describe
#: something our capability set does not model, and inventing a mapping would
#: put a claim in a report that the evidence does not support.
SANDBOX_CATEGORY_CAPABILITIES: dict[str, str] = {
    # Destruction
    "ransomware": "destruction",
    "wiper": "destruction",
    # Credential and data access
    "infostealer": "credential",
    "credential_access": "credential",
    "memory scraping": "credential",
    "keylogger": "credential",
    # Network / C2
    "c2": "network",
    "network": "network",
    "exfiltration": "network",
    # Persistence
    "persistence": "persistence",
    "bootkit": "persistence",
    # Defence evasion
    "evasion": "evasion",
    "stealth": "evasion",
    "antivm": "evasion",
    "anti-vm": "evasion",
    "anti-debug": "evasion",
    "anti-sandbox": "evasion",
    "anti_sandbox": "evasion",
    "anti-analysis": "evasion",
    "obfuscation": "evasion",
    "packer": "evasion",
    "geofence": "evasion",
    # Injection / in-memory execution
    "injection": "injection",
    "shellcode": "injection",
    "fileless": "injection",
    # Execution. "command" is included because that is what the category means —
    # a signature about running commands (script_tool_executed,
    # suspicious_command_tools). It is also the least alarming capability we
    # model: anything that runs at all has it, so a generous reading here cannot
    # inflate a verdict on its own.
    "execution": "execution",
    "command": "execution",
    "script": "execution",
    # Discovery
    "discovery": "discovery",
    "recon": "discovery",
    "system_discovery": "discovery",
    "location_discovery": "discovery",
    # Privilege
    "privilege_escalation": "privilege",
    # Payload delivery
    "dropper": "dropper",
    "downloader": "dropper",
    # Exploitation
    "exploit": "exploit",
}


#: Capabilities whose presence in a report is an accusation, not an observation.
#: Claiming a sample destroys data, steals credentials, exploits a vulnerability
#: or injects code into another process changes what an analyst does next, so
#: these are held to a higher standard than "the sandbox filed this signature
#: under that heading".
#:
#: Injection is here on measurement, not principle. Across three signed
#: installers detonated on our own host, the only injection-category signature
#: any of them produced was `reads_memory_remote_process` at severity 2 — while
#: every malware sample that unpacked produced 2 to 20 of them at severity 3.
#: Ungated, that one medium signature was enough to call the 7-Zip installer
#: malicious.
HIGH_CONSEQUENCE = frozenset({"destruction", "credential", "exploit", "injection"})


def _load_shared_behaviours() -> frozenset[str]:
    """Signatures ordinary software also trips, so they cannot alone accuse it.

    A sandbox categorises a signature by the threat class it helps *detect*, not
    by what it proves. `mountpoint_manager_access` is filed under `ransomware`
    because ransomware enumerates volumes — but so does every installer. Measured
    on this deployment before the list existed: the 7-Zip installer scored CIR
    8.3 with a destruction capability, identical to WannaCry, on five such
    signatures alone.
    """
    path = Path(__file__).with_name("data_shared_behaviours.txt")
    if not path.is_file():  # pragma: no cover - the file ships with the package
        return frozenset()
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.add(name)
    return frozenset(names)


SHARED_BEHAVIOURS: frozenset[str] = _load_shared_behaviours()


def _categories_of(signal: Signal) -> tuple[str, ...]:
    """The sandbox's categories for this signal, if it reported any."""
    evidence = getattr(signal, "evidence", None) or {}
    cats = evidence.get("categories") if isinstance(evidence, dict) else None
    if isinstance(cats, str):
        return (cats,)
    if isinstance(cats, (list, tuple)):
        return tuple(str(c) for c in cats)
    return ()


#: How many distinct conclusive signals a high-consequence capability needs.
#:
#: One is not enough, and no deny-list can make it enough. `SHARED_BEHAVIOURS`
#: below lists signatures ordinary software also trips, measured from three
#: signed installers — and the next benign program finds one that is not on it.
#:
#: A signed release of WinMerge was accused of `destruction` on a single
#: signature, `suspicious_iocontrol_codes` (filed by the sandbox under
#: bootkit/rootkit/wiper). WinMerge did not issue it. The signature's only
#: evidence is two calls from **pid 5832, `mousocoreworker.exe`** — the Windows
#: Update Session Orchestrator, a child of svchost — while the sample ran as pid
#: 5168 under explorer. Different branch of the process tree entirely. CAPE
#: attributes signatures to the ANALYSIS, not to a process, so whatever the
#: operating system happened to do during those two minutes became evidence
#: against the sample.
#:
#: That is why the deny-list cannot be completed. It is not enumerating
#: behaviours ordinary software performs — it is trying to enumerate everything
#: a Windows install might do while a sample is running. Corroboration does not
#: need that: real destructive behaviour produces destruction evidence over and
#: over (this WannaCry detonation emits twelve such signals), while background
#: noise contributes one. Measured across 108 detonations, requiring two removed
#: the last false positive and cost seven borderline malware samples their
#: `malicious` verdict — all of which remain `suspicious`.
#:
#: Filtering by process would be the direct fix and is NOT safe: malware
#: legitimately injects into other processes, and 29 malware jobs in this corpus
#: carry a high-severity signature marked only in a foreign process. It is also
#: not currently possible — see the `marks`/`data` note in the CAPE normaliser.
#:
#: Two, not three: three was also clean on the same corpus but cost three more
#: detections, so two is the weakest corroboration that does the job.
CORROBORATION_REQUIRED = 2


def _is_conclusive(signal: Signal) -> bool:
    """May this signal count toward a high-consequence claim?

    Two conditions, both measured rather than assumed: the sandbox rated it
    high, and it is not a behaviour ordinary software performs. Severity alone
    is not enough — `mass_file_modification_access` is severity 3 and an
    installer does it.

    Note "count toward": a conclusive signal is admissible evidence, not a
    verdict. `CORROBORATION_REQUIRED` decides how many it takes.
    """
    if SEVERITY_ORDER.get(signal.severity, 0) < SEVERITY_ORDER["high"]:
        return False
    tail = signal.id.split(".", 1)[1] if "." in signal.id else signal.id
    return tail not in SHARED_BEHAVIOURS


#: Reverse index, built once: signal id -> the capabilities it demonstrates.
_BY_SIGNAL: dict[str, tuple[str, ...]] = {}
for _cap, _ids in CAPABILITY_SIGNALS.items():
    for _sid in _ids:
        _BY_SIGNAL[_sid] = (*_BY_SIGNAL.get(_sid, ()), _cap)


#: Tokens that say what a signal IS, so that the rest of the name says what it
#: INSPECTED rather than what the sample can do.
#:
#: `antivm_network_adapters` enumerates adapters to spot a hypervisor;
#: `antivm_generic_disk` reads the disk for the same reason. Neither is a
#: capability to use the thing examined. Granting `network` for the first is
#: what made a .bat running `whoami` and `ping` into `Batch.Downloader`.
#:
#: Measured across the 88-sample fixture: 23 ids carry one of these markers and
#: exactly ONE granted a non-evasion capability — the adapters one, wrongly. So
#: this costs nothing and is not a trade.
#:
#: `stealth` is deliberately NOT here. `stealth_network_connection` really is a
#: connection, made quietly; the anti-* family is about LOOKING, and that is the
#: distinction the rule rests on.
_ANTI_ANALYSIS_MARKERS = frozenset({
    "antivm", "antidebug", "antisandbox", "antianalysis", "antiemulation",
    "antiav", "antidbg",
})


def _dynamic_capabilities(signal_id: str) -> tuple[str, ...]:
    """Capabilities for a behaviour signal produced by the dynamic tier."""
    tail = signal_id.split(".", 1)[1] if "." in signal_id else signal_id
    tokens = set(tail.split("_"))
    if tokens & _ANTI_ANALYSIS_MARKERS:
        # It is an anti-analysis check. The rest of the name is the subject of
        # the check, not a capability.
        return ("evasion",)
    found: list[str] = []
    for cap, keys in _DYNAMIC_TOKENS.items():
        for key in keys:
            # Whole-token match, or the multi-word key appearing as a run of
            # tokens — never a bare substring of a longer word.
            parts = key.split("_")
            if all(p in tokens for p in parts):
                found.append(cap)
                break
    return tuple(found)


def _signal_capabilities(signal: Signal) -> tuple[set[str], set[str]]:
    """``(ordinary, accusing)`` capabilities this ONE signal is evidence of.

    The two are returned separately because they are held to different
    standards. An ordinary capability is a description and one signal settles
    it. An accusing one is a claim about intent, so a single signal is evidence
    toward it and never a finding on its own — ``detect`` requires
    ``CORROBORATION_REQUIRED`` of them. ``accusing`` is empty unless the signal
    is conclusive.
    """
    ordinary: set[str] = set()
    accusing: set[str] = set()
    if SEVERITY_ORDER.get(signal.severity, 0) < _MIN_SEVERITY:
        return ordinary, accusing
    sid = signal.id
    if sid in _BY_SIGNAL:
        # Our own static analyzers. These ids are a curated mapping written
        # against evidence we chose to emit, not a sandbox's guess about its own
        # signature, so they are not subject to the corroboration gate.
        ordinary.update(_BY_SIGNAL[sid])
        return ordinary, accusing
    if not sid.startswith(_DYNAMIC_PREFIXES):
        return ordinary, accusing
    # Prefer the sandbox's own classification when it gave one: it is
    # authoritative about a signature it wrote, where reading the name is
    # inference. The token pass still runs, because engines that report no
    # categories (our native jail, Qiling) rely on it, and because a category
    # and a name can each catch what the other misses.
    #
    # The token pass is subject to the same gate. It used to run unconditionally,
    # which quietly re-granted whatever the category branch had just refused:
    # `capev2.injection_rwx` at severity medium matched the token `injection`
    # and handed back the injection capability. The corpus tests did not catch
    # it because no benign sample happened to carry a token-matching name.
    conclusive = _is_conclusive(signal)
    candidates: set[str] = {
        cap
        for cap in (
            SANDBOX_CATEGORY_CAPABILITIES.get(c.strip().lower())
            for c in _categories_of(signal)
        )
        if cap
    }
    candidates.update(_dynamic_capabilities(sid))
    for cap in candidates:
        if cap not in HIGH_CONSEQUENCE:
            # Discovery, evasion, execution and friends cost little to be
            # generous about — every running program has them, and an analyst
            # reading "performs discovery" is not misled.
            ordinary.add(cap)
        elif conclusive:
            accusing.add(cap)
    return ordinary, accusing


def evidence_capabilities(signal: Signal) -> set[str]:
    """Every capability this one signal is evidence of, corroborated or not.

    For weighing which capability a report *leans on* — naming, ranking — where
    the question is "what is this signal about", not "what may we accuse the
    sample of". Asking ``detect`` one signal at a time cannot answer that: under
    corroboration a lone signal never yields a high-consequence capability, so
    counting support that way scored WannaCry's twelve destruction signals at
    zero and renamed it ``Win32.Downloader.WanaCry``.
    """
    ordinary, accusing = _signal_capabilities(signal)
    return ordinary | accusing


def detect(signals: Iterable[Signal], iocs: IOCs | None = None) -> set[str]:
    """The capabilities the evidence actually demonstrates.

    ``iocs`` is accepted for call-site compatibility and deliberately unused:
    the mere presence of an indicator is not a capability. A README containing
    one URL used to be classified as a downloader because of it.
    """
    caps: set[str] = set()
    #: accusing capability -> the distinct signal ids that support it. Keyed by
    #: id so one signature reported twice cannot corroborate itself.
    support: dict[str, set[str]] = {}
    for signal in signals:
        ordinary, accusing = _signal_capabilities(signal)
        caps.update(ordinary)
        for cap in accusing:
            support.setdefault(cap, set()).add(signal.id)
    for cap, ids in support.items():
        if len(ids) >= CORROBORATION_REQUIRED:
            caps.add(cap)
    return caps


def describe(caps: Iterable[str]) -> list[str]:
    """Human-readable capability names, for the report and the UI."""
    return [CAPABILITY_LABELS.get(c, c) for c in sorted(caps)]
