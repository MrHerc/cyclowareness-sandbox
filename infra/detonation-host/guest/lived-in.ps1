# Make the guest look like a machine someone uses.
#
# A guest built in an afternoon is trivially identifiable: no documents, no
# browser history, no recent files, a pristine registry and an uptime measured in
# seconds. Commodity malware checks exactly these before unpacking, and a sample
# that decides it is being watched simply exits — which a sandbox then reports as
# "no malicious behaviour observed". That is the worst possible failure: a clean
# verdict on a live threat.
#
# Nothing here is a trick. It is the same content a real desk accumulates, put
# there deliberately: files with plausible names and dates, a recent-documents
# list, some registry history, and a user profile that is not empty.
#
# Run once against the golden image, then re-snapshot.

$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\lived-in.log'
function Say($m) { "$(Get-Date -Format o)  $m" | Tee-Object -FilePath $log -Append }

Say "populating the user profile"

$docs = "$env:USERPROFILE\Documents"
$down = "$env:USERPROFILE\Downloads"
$desk = "$env:USERPROFILE\Desktop"
$pics = "$env:USERPROFILE\Pictures"
foreach ($d in $docs, $down, $desk, $pics) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# Plausible working files. Content matters less than existence, mtime spread and
# non-zero size - emptiness and identical timestamps are what stand out.
$files = @(
    @{ p = "$docs\Q3-budget-review.xlsx";        d = -47 },
    @{ p = "$docs\supplier-agreement-v3.docx";   d = -12 },
    @{ p = "$docs\meeting-notes.txt";            d = -3  },
    @{ p = "$docs\payroll-jan.xlsx";             d = -88 },
    @{ p = "$docs\insurance-renewal.pdf";        d = -21 },
    @{ p = "$down\invoice-4471.pdf";             d = -5  },
    @{ p = "$down\driver-update.zip";            d = -33 },
    @{ p = "$down\presentation-final.pptx";      d = -9  },
    @{ p = "$desk\todo.txt";                     d = -1  },
    @{ p = "$desk\vpn-instructions.docx";        d = -61 },
    @{ p = "$pics\team-offsite.jpg";             d = -74 },
    @{ p = "$pics\screenshot-error.png";         d = -6  }
)
foreach ($f in $files) {
    $size = Get-Random -Minimum 18000 -Maximum 900000
    $bytes = New-Object byte[] $size
    (New-Object Random).NextBytes($bytes)
    [IO.File]::WriteAllBytes($f.p, $bytes)
    $when = (Get-Date).AddDays($f.d).AddHours(-(Get-Random -Minimum 1 -Maximum 20))
    (Get-Item $f.p).CreationTime = $when
    (Get-Item $f.p).LastWriteTime = $when
    (Get-Item $f.p).LastAccessTime = $when.AddDays(1)
}
Say "wrote $($files.Count) profile files with spread timestamps"

# Recent-documents shortcuts. An empty Recent folder is a strong tell, and it is
# one of the cheapest things for a sample to read.
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
New-Item -ItemType Directory -Force -Path $recent | Out-Null
$shell = New-Object -ComObject WScript.Shell
foreach ($f in $files[0..7]) {
    $lnk = $shell.CreateShortcut("$recent\$([IO.Path]::GetFileNameWithoutExtension($f.p)).lnk")
    $lnk.TargetPath = $f.p
    $lnk.Save()
}
Say "created recent-document shortcuts"

# Typed paths and run history: a registry that has never been used is as obvious
# as an empty desktop.
$typed = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
New-Item -Path $typed -Force | Out-Null
$i = 1
foreach ($p in "$docs", "$down", '\\fileserver\shared', 'C:\Program Files') {
    New-ItemProperty -Path $typed -Name "url$i" -Value $p -PropertyType String -Force | Out-Null
    $i++
}
$runmru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
New-Item -Path $runmru -Force | Out-Null
$j = 97
foreach ($c in 'cmd', 'notepad', 'control panel', '\\fileserver\shared') {
    New-ItemProperty -Path $runmru -Name ([char]$j) -Value "$c\1" -PropertyType String -Force | Out-Null
    $j++
}
Say "seeded typed paths and run history"

# Edge/IE history and favourites. Absent browser history is one of the checks
# commodity stealers make before deciding there is anything worth stealing.
$fav = "$env:USERPROFILE\Favorites"
New-Item -ItemType Directory -Force -Path $fav | Out-Null
foreach ($s in @(
    @{ n = 'Company intranet'; u = 'http://intranet.local/' },
    @{ n = 'Webmail';          u = 'https://outlook.office.com/' },
    @{ n = 'Expenses';         u = 'https://expenses.local/' }
)) {
    "[InternetShortcut]`r`nURL=$($s.u)" | Set-Content -Path "$fav\$($s.n).url" -Encoding ASCII
}
Say "seeded favourites"

# A non-default machine identity. Sandboxes ship with recognisable names.
$org = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Set-ItemProperty -Path $org -Name RegisteredOwner -Value 'A. Mammadova' -Force
Set-ItemProperty -Path $org -Name RegisteredOrganization -Value 'Caspian Logistics LLC' -Force
Say "set registered owner and organisation"

# Printer and mapped-drive artefacts: a workstation has them, a fresh VM does not.
Add-PrinterPort -Name 'IP_10.20.30.40' -PrinterHostAddress '10.20.30.40' 2>$null | Out-Null
Add-Printer -Name 'Office-MFP-2F' -DriverName 'Microsoft Print To PDF' -PortName 'IP_10.20.30.40' 2>$null | Out-Null
Say "added a plausible network printer"

Say "done"
