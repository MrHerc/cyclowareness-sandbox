# Containment probe, run INSIDE the detonation guest.
#
# One script, one round trip, machine-readable output. The first version asked
# the agent fourteen separate questions and each blocked port waited out a full
# TCP timeout: over six minutes for one answer. A safety gate that slow does not
# get run, and a gate that does not get run is not a gate.
#
# Every connect is capped explicitly rather than left to the stack's default,
# which is what made the difference.

$ErrorActionPreference = 'SilentlyContinue'
$HostIp = if ($env:CYCLO_HOST_IP) { $env:CYCLO_HOST_IP } else { '192.168.122.1' }

function Test-Port {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 2500)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok) { $client.EndConnect($async) | Out-Null }
        return $ok -and $client.Connected
    } catch { return $false } finally { $client.Close() }
}

function Test-Udp {
    # A raw UDP probe to a port the sinkhole does not serve. TCP/80 is the only
    # egress this probe used to test, and UDP is the channel malware actually
    # reaches for - DNS tunnelling above all. No answer is the pass.
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 3000)
    $c = New-Object Net.Sockets.UdpClient
    try {
        $c.Client.ReceiveTimeout = $TimeoutMs
        $c.Connect($Address, $Port)
        # A minimal DNS query for example.com/A.
        $q = [byte[]](0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,
                      0x00,0x00,0x01,0x00,0x01)
        $c.Send($q, $q.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $c.Receive([ref]$ep)
        return $r.Length -gt 0
    } catch { return $false } finally { $c.Close() }
}

$hostPorts = 22, 111, 2049, 5432, 6379, 8000, 8080, 8090, 9050, 27017
foreach ($p in $hostPorts) {
    "PORT $p " + (Test-Port -Address $HostIp -Port $p)
}
"RESULTSERVER " + (Test-Port -Address $HostIp -Port 2042)

# The Docker bridge. The old host-side rules named an interface pair
# (-i virbr0 -o enp41s0), so virbr0 -> docker0 matched nothing and a sample could
# reach the Cyclowareness API container on 172.17.0.2:8000. The probe never
# looked there, so the gate certified a host with a live hole in it.
$dockerTargets = @('172.17.0.1:8000', '172.17.0.1:5432', '172.17.0.2:8000', '172.17.0.2:80')
foreach ($t in $dockerTargets) {
    $parts = $t.Split(':')
    "DOCKER $t " + (Test-Port -Address $parts[0] -Port ([int]$parts[1]))
}

# Raw addresses, never names: DNS points everything at the sinkhole by design, so
# a name would test the simulator rather than the egress path.
$egressTargets = '1.1.1.1', '8.8.8.8', '93.184.216.34'
foreach ($ip in $egressTargets) {
    "EGRESS $ip " + (Test-Port -Address $ip -Port 80 -TimeoutMs 4000)
}
"EGRESSUDP 8.8.8.8:53 " + (Test-Udp -Address '8.8.8.8' -Port 53)

$answer = (Resolve-DnsName -Name example.com -Type A -DnsOnly).IPAddress | Select-Object -First 1
"DNS " + $(if ($answer) { $answer } else { 'none' })

try {
    $r = Invoke-WebRequest -Uri 'http://example.com/' -TimeoutSec 10 -UseBasicParsing
    $body = [string]$r.Content
    "HTTP " + $r.StatusCode + " " + ($body.Substring(0, [Math]::Min(120, $body.Length)) -replace '\s+', ' ')
} catch {
    "HTTP none " + $_.Exception.Message.Substring(0, [Math]::Min(80, $_.Exception.Message.Length))
}

# The sentinel, and the count that must match it.
#
# Without this the verifier could not tell "every egress test passed" from "the
# egress tests never ran". Its `while read` loops only inspect lines whose first
# field matches, so a probe that died after the PORT block - PowerShell throwing,
# the agent truncating, the 180s curl giving up - produced no EGRESS lines at
# all, every loop body was skipped, and the gate printed "Safe to detonate"
# having tested nothing. A single line reading `RESULTSERVER True` was enough to
# certify the host. Absent evidence must never read as success.
$expected = $hostPorts.Count + 1 + $dockerTargets.Count + $egressTargets.Count + 1 + 1 + 1
"PROBE-COMPLETE $expected"
