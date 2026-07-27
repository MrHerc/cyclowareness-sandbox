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

foreach ($p in 22, 111, 2049, 5432, 6379, 8000, 8080, 8090, 9050, 27017) {
    "PORT $p " + (Test-Port -Address $HostIp -Port $p)
}
"RESULTSERVER " + (Test-Port -Address $HostIp -Port 2042)

# Raw addresses, never names: DNS points everything at the sinkhole by design, so
# a name would test the simulator rather than the egress path.
foreach ($ip in '1.1.1.1', '8.8.8.8', '93.184.216.34') {
    "EGRESS $ip " + (Test-Port -Address $ip -Port 80 -TimeoutMs 4000)
}

$answer = (Resolve-DnsName -Name example.com -Type A -DnsOnly).IPAddress | Select-Object -First 1
"DNS " + $(if ($answer) { $answer } else { 'none' })

try {
    $r = Invoke-WebRequest -Uri 'http://example.com/' -TimeoutSec 10 -UseBasicParsing
    $body = [string]$r.Content
    "HTTP " + $r.StatusCode + " " + ($body.Substring(0, [Math]::Min(120, $body.Length)) -replace '\s+', ' ')
} catch {
    "HTTP none " + $_.Exception.Message.Substring(0, [Math]::Min(80, $_.Exception.Message.Length))
}
