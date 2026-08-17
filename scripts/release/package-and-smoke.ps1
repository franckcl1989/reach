param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [Parameter(Mandatory = $true)]
    [string]$BinaryName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('linux', 'macos', 'windows')]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [string]$Artifact,

    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$workspace = (Get-Location).Path
$sourceBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$work = Join-Path $workspace "release-work/$Artifact"
$extract = Join-Path $work 'extracted'
New-Item -ItemType Directory -Path $extract -Force | Out-Null
$archive = Join-Path $workspace "reach-$Artifact.tar"
$rawInspection = Join-Path $workspace "reach-$Artifact-dependencies-raw.txt"
$extractedInspection = Join-Path $workspace "reach-$Artifact-dependencies-extracted.txt"

& "$PSScriptRoot/verify-binary.ps1" -Path $sourceBinary -Platform $Platform -EvidencePath $rawInspection
if ($LASTEXITCODE -notin @(0, $null)) {
    throw 'raw binary dependency inspection failed'
}

$sourceDirectory = Split-Path -Parent $sourceBinary
& tar -cf $archive -C $sourceDirectory $BinaryName
if ($LASTEXITCODE -ne 0) {
    throw 'archive creation failed'
}
$members = @(& tar -tf $archive)
if ($LASTEXITCODE -ne 0 -or $members.Count -ne 1 -or $members[0] -ne $BinaryName) {
    throw "archive must contain exactly $BinaryName"
}
& tar -xf $archive -C $extract
if ($LASTEXITCODE -ne 0) {
    throw 'archive extraction failed'
}
$extractedBinary = Join-Path $extract $BinaryName
$sourceHash = (Get-FileHash -LiteralPath $sourceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$extractedHash = (Get-FileHash -LiteralPath $extractedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHash -ne $extractedHash) {
    throw 'extracted executable hash differs from the inspected build output'
}

& "$PSScriptRoot/verify-binary.ps1" -Path $extractedBinary -Platform $Platform -EvidencePath $extractedInspection
if ($LASTEXITCODE -notin @(0, $null)) {
    throw 'extracted binary dependency inspection failed'
}

$versionOutput = (& $extractedBinary --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $versionOutput -ne "reach $Version") {
    throw "unexpected extracted --version result: $versionOutput"
}

& $extractedBinary 2>$null | Out-Null
if ($LASTEXITCODE -ne 2) {
    throw "missing address must exit 2, got $LASTEXITCODE"
}
& $extractedBinary 'not/an/address' 2>$null | Out-Null
if ($LASTEXITCODE -ne 2) {
    throw "invalid address must exit 2, got $LASTEXITCODE"
}

function Invoke-LoopbackSmoke([string]$Address, [bool]$DualMode) {
    $listenAddress = if ($DualMode) {
        [System.Net.IPAddress]::IPv6Any
    } else {
        [System.Net.IPAddress]::Loopback
    }
    $listener = [System.Net.Sockets.TcpListener]::new($listenAddress, 0)
    if ($DualMode) {
        $listener.Server.DualMode = $true
    }
    $listener.Start()
    try {
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $output = (& $extractedBinary $Address $port 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "loopback smoke for $Address failed with $LASTEXITCODE`n$output"
        }
    } finally {
        $listener.Stop()
    }
}

Invoke-LoopbackSmoke -Address '127.0.0.1' -DualMode $false
Invoke-LoopbackSmoke -Address 'localhost' -DualMode $true

@(
    "archive=$archive"
    "archive_member=$($members[0])"
    "executable_sha256=$extractedHash"
    "archive_sha256=$((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant())"
    "version_smoke=$versionOutput"
    'missing_argument_exit=2'
    'invalid_input_exit=2'
    'loopback_ipv4=pass'
    'loopback_localhost=pass'
) | Set-Content -LiteralPath (Join-Path $workspace "reach-$Artifact-artifact-verification.txt")
