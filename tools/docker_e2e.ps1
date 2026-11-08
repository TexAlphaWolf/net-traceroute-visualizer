# End to end inside the image, from Windows PowerShell: the real traceroute traces the loopback and two saved outputs
# with a route change are read, reported and anonymised (read-only root, no capabilities). Needs Docker Desktop.
# Usage: .\tools\docker_e2e.ps1 [-Image pathmap]
param([string]$Image = "pathmap")
$ErrorActionPreference = "Stop"

$vol = "pathmap-e2e-$(Get-Random)"
$secure = @("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "-v", "${vol}:/data")

function Invoke-Pm {
    $out = docker run --rm @secure $Image @args
    if ($LASTEXITCODE -ne 0) { throw "pathmap $args failed (exit $LASTEXITCODE)" }
    $out | Out-String
}
function Add-Run($router, $time) {
    $text = "traceroute to 203.0.113.9 (203.0.113.9), 30 hops max, 60 byte packets`n 1  192.0.2.1  1.0 ms  1.1 ms  1.2 ms`n 2  $router  5.0 ms  5.1 ms  5.2 ms`n 3  203.0.113.9  9.0 ms  9.1 ms  9.2 ms`n"
    $text | docker run --rm -i @secure $Image parse - --target 203.0.113.9 --time $time --store | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "parse failed" }
}
function Assert-Contains($text, $needle) { if ($text -notmatch [regex]::Escape($needle)) { throw "expected '$needle' in: $text" } }
function Assert-Missing($text, $needle) { if ($text -match [regex]::Escape($needle)) { throw "did not expect '$needle' in: $text" } }

try {
    docker volume create $vol | Out-Null
    docker run --rm --user 0 -v "${vol}:/data" --entrypoint chown $Image 10001 /data
    if ($LASTEXITCODE -ne 0) { throw "could not prepare the volume" }

    Assert-Contains (Invoke-Pm trace 127.0.0.1) "reached"
    Assert-Contains (Invoke-Pm status --stale 1h) "127.0.0.1: "

    foreach ($i in 0..9) { Add-Run "198.51.100.1" "2026-10-01T0${i}:00:00Z" }
    foreach ($i in 0..4) { Add-Run "198.51.100.77" "2026-10-01T1${i}:00:00Z" }
    Assert-Contains (Invoke-Pm changes 203.0.113.9) "hop 2: 198.51.100.1 -> 198.51.100.77"
    Assert-Contains (Invoke-Pm show 203.0.113.9) "198.51.100.77"
    Assert-Contains (Invoke-Pm report --format html 203.0.113.9) "Route changed"
    $anon = Invoke-Pm report --anonymize --format html
    Assert-Contains $anon "node-"
    Assert-Missing $anon "198.51.100"
    Assert-Missing $anon "203.0.113"

    docker run --rm @secure $Image trace -- "-oProxyCommand=x" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 2) { throw "expected exit code 2 for a bad target, got $LASTEXITCODE" }
    Write-Host "docker end-to-end: OK"
}
finally {
    docker volume rm -f $vol 2>$null | Out-Null
}
