"""The IOC noise filter must remove platform chatter and nothing else.

Two failure modes, with very different costs:

* Under-filtering leaves a dozen Microsoft CDN endpoints in every report. Noisy,
  embarrassing, harmless.
* **Over-filtering hides a real command-and-control address.** That is the one
  outcome this product cannot survive, so every test below that asserts
  "suppressed" has a partner asserting "kept" for the nearest thing an attacker
  would actually use.

Also covered: the sample-extension sanitiser on the backend side, because the
extension is the only attacker-controlled fragment that reaches the detonation
sandbox's file system.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WORKER = REPO / "worker"


@pytest.fixture(scope="module")
def baseline():
    sys.path.insert(0, str(WORKER))
    try:
        from engines import baseline as mod  # type: ignore

        yield mod
    finally:
        sys.path.remove(str(WORKER))


# --- the network baseline describes a real, current image -------------------


def test_baseline_file_exists_and_parses(baseline) -> None:
    nets = baseline.baseline_networks()
    assert nets, "no baseline networks loaded - the data file is missing or empty"
    # /24 or narrower. A wide block would silently swallow whole hosting
    # providers, and with them any sample hosted there.
    for net in nets:
        assert net.prefixlen >= 24, f"{net} is wider than /24"


def test_baseline_file_records_its_provenance(baseline) -> None:
    """A suppression list nobody can date is a suppression list nobody can audit."""
    text = (WORKER / "engines" / "baseline_networks.txt").read_text(encoding="utf-8")
    assert "golden image v2" in text
    assert "REGENERATE" in text
    assert "2026-07-27" in text


# --- domains -----------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "www.msftconnecttest.com",
        "msftconnecttest.com",
        "cdn.onenote.net",
        "login.microsoftonline.com",
        "v10.events.data.microsoft.com",
        "ctldl.windowsupdate.com",
    ],
)
def test_platform_domains_are_suppressed(baseline, host: str) -> None:
    assert baseline.noise_reason("domains", host) is not None


@pytest.mark.parametrize(
    "host",
    [
        # Lookalikes an attacker would register. Suffix matching must respect the
        # label boundary, or these vanish from the report.
        "evil-msftconnecttest.com",
        "msftconnecttest.com.attacker.ru",
        "notcdn.onenote.net.evil.tk",
        "login.microsoftonline.com.phish.io",
        # A vendor domain we deliberately do NOT blanket-suppress.
        "microsoft.com",
        "azurewebsites.net",
        # Ordinary C2
        "updates.example-c2.test",
        "203.0.113.9.nip.io",
    ],
)
def test_lookalike_and_real_domains_are_kept(baseline, host: str) -> None:
    assert baseline.noise_reason("domains", host) is None


# --- addresses ---------------------------------------------------------------


def test_an_address_inside_the_baseline_is_suppressed(baseline) -> None:
    net = baseline.baseline_networks()[0]
    inside = str(next(net.hosts()))
    assert baseline.noise_reason("ips", inside) is not None


def test_a_neighbouring_network_is_kept(baseline) -> None:
    """Aggregation stops at /24 - the next block over must still be reported."""
    net = baseline.baseline_networks()[0]
    neighbour = f"{str(net.network_address).rsplit('.', 2)[0]}.254.7"
    if baseline.noise_reason("ips", neighbour) is not None:
        pytest.skip("that /24 happens to be in the baseline too")
    assert baseline.noise_reason("ips", neighbour) is None


@pytest.mark.parametrize("ip", ["203.0.113.9", "198.51.100.4", "8.8.8.8", "1.1.1.1"])
def test_ordinary_addresses_are_kept(baseline, ip: str) -> None:
    assert baseline.noise_reason("ips", ip) is None


def test_garbage_is_kept_not_crashed_on(baseline) -> None:
    for value in ("", "not-an-ip", "999.999.999.999", "::gg"):
        assert baseline.noise_reason("ips", value) is None


# --- only network fields are touched -----------------------------------------


@pytest.mark.parametrize("field", ["file_paths", "registry_keys", "mutexes", "hashes", "emails"])
def test_non_network_fields_are_never_suppressed(baseline, field: str) -> None:
    assert baseline.noise_reason(field, "anything at all") is None


# --- partition reports what it removed ---------------------------------------


def test_partition_keeps_real_and_records_removals(baseline) -> None:
    net = baseline.baseline_networks()[0]
    noisy_ip = str(next(net.hosts()))
    iocs = {
        "ips": [noisy_ip, "203.0.113.9"],
        "domains": ["cdn.onenote.net", "updates.example-c2.test"],
        "urls": [f"https://{noisy_ip}/ping", "http://203.0.113.9/gate.php"],
        "mutexes": ["Local\\SM0:3744"],
    }
    kept, suppressed = baseline.partition(iocs)

    assert kept["ips"] == ["203.0.113.9"]
    assert kept["domains"] == ["updates.example-c2.test"]
    assert kept["urls"] == ["http://203.0.113.9/gate.php"]
    assert kept["mutexes"] == ["Local\\SM0:3744"]

    assert len(suppressed) == 3
    assert {s["field"] for s in suppressed} == {"ips", "domains", "urls"}
    assert all(s["reason"] for s in suppressed), "every removal must carry a reason"


def test_partition_of_empty_input_is_safe(baseline) -> None:
    kept, suppressed = baseline.partition({})
    assert kept == {} and suppressed == []


def test_missing_data_file_fails_open(baseline, monkeypatch) -> None:
    """A worker shipped without the list must over-report, never under-report."""
    baseline.baseline_networks.cache_clear()
    monkeypatch.setattr(baseline, "_NETWORKS_FILE", str(WORKER / "does-not-exist.txt"))
    try:
        assert baseline.baseline_networks() == ()
        assert baseline.noise_reason("ips", "150.171.28.12") is None
    finally:
        baseline.baseline_networks.cache_clear()


# --- the extension that reaches the sandbox ----------------------------------


@pytest.mark.parametrize(
    "name,want",
    [
        ("invoice.ps1", ".ps1"),
        ("SAMPLE.EXE", ".exe"),
        ("doc.docm", ".docm"),
        ("archive.tar.gz", ".gz"),
        ("noextension", ""),
        ("trailing.", ""),
        ("", ""),
        (None, ""),
        ("../../etc/passwd", ""),
        ("a.ps1/../../x", ""),
        ("a.ps1%00", ""),
        ('a."ps1', ""),
        ("a.p s1", ""),
        ("a.рs1", ""),  # Cyrillic homoglyph
        ("a." + "z" * 20, ""),
    ],
)
def test_safe_suffix(name, want) -> None:
    from app.api.dynamic import _safe_suffix

    assert _safe_suffix(name) == want


# --- the indicators an isolated sandbox actually produces --------------------


#: Shaped on a real CAPEv2 2.5 report from this deployment (task 12). The point
#: is the asymmetry: the probe's two command-and-control endpoints are in
#: `dead_hosts`, and `hosts` holds nothing but CDN noise. That is the normal case
#: for a network-isolated sandbox, not an edge case.
_REAL_SHAPED_REPORT = {
    "info": {"score": 3.4, "package": "ps1"},
    "signatures": [],
    "behavior": {"processes": [{"process_name": "powershell.exe"}]},
    "network": {
        "hosts": [{"ip": "23.52.181.237"}, {"ip": "23.32.243.39"}],
        "dead_hosts": [
            ["184.86.251.24", 443],
            ["203.0.113.77", 443],
            ["198.51.100.23", 8080],
            ["172.211.123.250", 443],
        ],
        "domains": [],
        "dns": [
            {
                "request": "cdn.onenote.net",
                "answers": [
                    {"type": "CNAME", "data": "cdn.onenote.net.edgekey.net"},
                    {"type": "A", "data": "23.52.181.237"},
                ],
            },
            {
                "request": "gate.cyclowareness-c2.test",
                "answers": [{"type": "A", "data": "203.0.113.77"}],
            },
        ],
        "http": [],
    },
}


@pytest.fixture()
def normalised():
    sys.path.insert(0, str(WORKER))
    try:
        from engines.base import Report  # type: ignore
        from engines.opensource import _normalise_cuckoo  # type: ignore

        report = Report(engine="capev2", worker="test")
        _normalise_cuckoo(_REAL_SHAPED_REPORT, report, prefix="capev2")
        yield report
    finally:
        sys.path.remove(str(WORKER))


def test_refused_c2_connections_are_reported(normalised) -> None:
    """The whole point. An isolated sandbox refuses every C2 dial, so reading
    only `hosts` would report the CDN noise and drop the actual indicators."""
    assert "203.0.113.77" in normalised.iocs["ips"]
    assert "198.51.100.23" in normalised.iocs["ips"]


def test_platform_noise_is_still_removed(normalised) -> None:
    assert "23.52.181.237" not in normalised.iocs["ips"]
    assert "184.86.251.24" not in normalised.iocs["ips"]
    assert "cdn.onenote.net" not in normalised.iocs["domains"]


def test_a_queried_c2_name_survives(normalised) -> None:
    assert "gate.cyclowareness-c2.test" in normalised.iocs["domains"]


def test_a_suppressed_names_cname_chain_goes_with_it(normalised) -> None:
    """Otherwise the filter plays whack-a-mole with CDN plumbing forever."""
    assert "cdn.onenote.net.edgekey.net" not in normalised.iocs["domains"]


def test_a_kept_names_answers_are_kept(normalised) -> None:
    """The inverse must hold, or resolving a C2 name would erase its address."""
    assert "203.0.113.77" in normalised.iocs["ips"]


def test_attempted_and_established_are_distinguished(normalised) -> None:
    endpoints = normalised.facts.get("network_endpoints")
    assert endpoints, "the attempted/established distinction was lost"
    assert "203.0.113.77:443" in endpoints["attempted"]
    assert "198.51.100.23:8080" in endpoints["attempted"]


def test_an_unanswered_packet_is_not_an_established_connection(normalised) -> None:
    """This assertion used to read

        assert "23.52.181.237" in endpoints["established"]

    and `23.52.181.237` is the address the test twelve lines above asserts is
    platform noise and must not appear in the indicators at all. The fixture has
    no `network.tcp` list, so nothing in it ever exchanged a byte — the suite was
    pinning the defect in place, and pinning it on an address the product had
    already decided was not the sample's.

    CAPE fills `network.hosts` from every packet destination, answered or not.
    Only `network.tcp` (`if tcp.data:`) means bytes moved. On the live
    deployment that difference was 1344 asserted connections against 1 with a
    flow behind it, on a host whose firewall drops every forwarded packet.
    """
    endpoints = normalised.facts.get("network_endpoints")
    assert endpoints["established"] == [], endpoints["established"]
    assert "23.52.181.237" not in str(endpoints), endpoints


def test_the_same_address_is_never_in_both_buckets(normalised) -> None:
    """1326 of 1344 stored entries were in both, because `hosts` is a superset
    of `dead_hosts` and the two loops did not know about each other."""
    endpoints = normalised.facts.get("network_endpoints")
    established = {e.rsplit(":", 1)[0] for e in endpoints["established"]}
    attempted = {e.rsplit(":", 1)[0] for e in endpoints["attempted"]}
    assert not (established & attempted), established & attempted


def test_the_baseline_reaches_the_endpoints_too(normalised, baseline) -> None:
    """`baseline.partition` ran after the facts were written and only over the
    indicators, so guest noise was stripped from one list and left in the other.
    249 stored jobs had `184.86.251.16` in `established` and not in `iocs`."""
    endpoints = normalised.facts.get("network_endpoints") or {}
    for entry in endpoints.get("established", []) + endpoints.get("attempted", []):
        assert not baseline.noise_reason("ips", entry.rsplit(":", 1)[0]), entry


def test_every_removal_is_accounted_for(normalised) -> None:
    suppressed = normalised.facts.get("iocs_suppressed")
    assert suppressed and suppressed["count"] >= 3
    removed = {e["value"] for e in suppressed["entries"]}
    assert "cdn.onenote.net" in removed
    assert "203.0.113.77" not in removed


def test_submission_name_keeps_the_hash_as_the_stem(baseline) -> None:
    """The extension travels; the attacker-controlled stem never does."""
    sys.path.insert(0, str(WORKER))
    try:
        from engines.opensource import _submission_name  # type: ignore

        sha = "a" * 64
        assert _submission_name("/tmp/cw-sample-xyz.ps1", sha) == f"{sha}.ps1"
        assert _submission_name("/tmp/cw-sample-xyz", sha) == f"{sha}.sample"
        # Whatever the temp file is called, only its extension survives.
        assert _submission_name("/tmp/evil name; rm -rf.docm", sha) == f"{sha}.docm"
    finally:
        sys.path.remove(str(WORKER))
