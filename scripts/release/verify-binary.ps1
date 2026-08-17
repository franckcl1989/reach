param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [ValidateSet('linux', 'macos', 'windows')]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$binary = (Resolve-Path -LiteralPath $Path).Path
$evidence = [System.Collections.Generic.List[string]]::new()

switch ($Platform) {
    'linux' {
        $programHeaders = (& readelf -lW $binary 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'readelf program-header inspection failed'
        }
        $dynamic = (& readelf -dW $binary 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'readelf dynamic-section inspection failed'
        }
        $versions = (& readelf --version-info $binary 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'readelf symbol-version inspection failed'
        }
        $evidence.Add("readelf -lW`n$programHeaders")
        $evidence.Add("readelf -dW`n$dynamic")
        $evidence.Add("readelf --version-info`n$versions")
        if ($programHeaders -match '\bINTERP\b') {
            throw 'Linux release ELF contains PT_INTERP'
        }
        if ($dynamic -match '\(NEEDED\)|\(RPATH\)|\(RUNPATH\)') {
            throw 'Linux release ELF contains a dynamic runtime dependency or search path'
        }
        if ($versions -match 'GLIBC_') {
            throw 'Linux release ELF contains a GLIBC symbol-version requirement'
        }
    }
    'macos' {
        $dependencies = (& otool -L $binary 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'otool dependency inspection failed'
        }
        $evidence.Add("otool -L`n$dependencies")
        $paths = $dependencies -split "`n" |
            Select-Object -Skip 1 |
            ForEach-Object { ($_ -replace '^\s+', '').Split(' ')[0] } |
            Where-Object { $_ }
        foreach ($dependency in $paths) {
            if (-not ($dependency.StartsWith('/System/Library/') -or $dependency.StartsWith('/usr/lib/'))) {
                throw "macOS release has a non-system dependency: $dependency"
            }
        }
    }
    'windows' {
        $rustSysroot = (rustc --print sysroot).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw 'rustc sysroot discovery failed'
        }
        $rustHost = ((rustc -vV | Select-String '^host:').ToString().Split(':')[1].Trim())
        if ($LASTEXITCODE -ne 0) {
            throw 'rustc host discovery failed'
        }
        $llvmReadobj = Join-Path $rustSysroot "lib/rustlib/$rustHost/bin/llvm-readobj.exe"
        if (-not (Test-Path -LiteralPath $llvmReadobj -PathType Leaf)) {
            throw "llvm-readobj was not found at $llvmReadobj"
        }
        $imports = (& $llvmReadobj --coff-imports $binary 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'llvm-readobj PE import inspection failed'
        }
        $evidence.Add("llvm-readobj --coff-imports`n$imports")
        $dlls = $imports -split "`n" |
            ForEach-Object {
                if ($_ -match '^\s*Name:\s+([^\s]+\.dll)\s*$') {
                    $Matches[1].ToLowerInvariant()
                }
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
        $systemDlls = @(
            'advapi32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'cfgmgr32.dll',
            'crypt32.dll', 'dnsapi.dll', 'gdi32.dll', 'iphlpapi.dll', 'kernel32.dll',
            'ntdll.dll', 'ole32.dll', 'oleaut32.dll', 'rpcrt4.dll', 'secur32.dll',
            'shell32.dll', 'user32.dll', 'userenv.dll', 'ws2_32.dll'
        )
        foreach ($dll in $dlls) {
            if ($dll -match '^(vcruntime|msvcp)' -or $dll -match '^api-ms-win-crt-') {
                throw "Windows release imports a forbidden dynamic C/C++ runtime: $dll"
            }
            if ($dll -notin $systemDlls -and $dll -notmatch '^api-ms-win-core-[a-z0-9-]+\.dll$') {
                throw "Windows release imports a DLL outside the versioned system allowlist: $dll"
            }
        }
    }
}

$evidence | Set-Content -LiteralPath $EvidencePath
