# portwave uninstaller (Windows) — LEGACY FALLBACK.
#
# Preferred since v0.8.6:   portwave --uninstall
# This script is kept as a zero-binary-dependency escape hatch for
# cases where the portwave binary is missing, corrupt, or otherwise
# unrunnable. Functionally identical to `portwave --uninstall`.
#
# Auto-detects the installed binary via `Get-Command portwave` plus a list
# of common install prefixes, then removes it and its associated share /
# config directories. If no installation is found, alerts the user and
# exits cleanly without modifying anything.

#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Say  { param($m) Write-Host "==> $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

Write-Host 'portwave uninstaller'
Write-Host ''

# ── 1. Binary discovery ──
$candidates = @()

# Start with whatever Windows resolves from the current user's PATH.
$cmd = Get-Command portwave -ErrorAction SilentlyContinue
if ($cmd) {
    $candidates += $cmd.Source
    # Follow symlink / reparse point if any
    try {
        $target = (Get-Item $cmd.Source -ErrorAction SilentlyContinue).Target
        if ($target -and $target -ne $cmd.Source) { $candidates += $target }
    } catch { }
}

# Well-known install prefixes across Windows layouts.
$candidates += @(
    (Join-Path $env:USERPROFILE '.local\bin\portwave.exe'),
    (Join-Path $env:USERPROFILE 'bin\portwave.exe'),
    (Join-Path $env:USERPROFILE '.cargo\bin\portwave.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\portwave\portwave.exe'),
    (Join-Path ${env:ProgramFiles} 'portwave\portwave.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'portwave\portwave.exe')
)

# Dedupe + keep only existing files
$found = $candidates | Sort-Object -Unique | Where-Object {
    $_ -and (Test-Path -Path $_ -PathType Leaf)
}

if (-not $found -or $found.Count -eq 0) {
    Warn 'No portwave installation found on this system.'
    Write-Host '    Checked via `Get-Command portwave` plus these prefixes:'
    foreach ($c in $candidates) { Write-Host "      - $c" }
    Write-Host ''
    Warn 'If portwave isn''t installed yet, run .\install.ps1 first.'
    exit 0
}

# ── 2. Remove binary / binaries ──
Write-Host ("Found {0} binary file(s):" -f $found.Count)
foreach ($bin in $found) { Write-Host "  - $bin" }
Write-Host ''
foreach ($bin in $found) {
    try {
        Remove-Item -Force $bin
        Say "removed $bin"
    } catch {
        Warn "could not remove ${bin}: $_"
    }
}

# ── 3. Remove share directories ──
$shares = @(
    (Join-Path $env:USERPROFILE '.local\share\portwave'),
    (Join-Path $env:LOCALAPPDATA 'portwave'),
    (Join-Path ${env:ProgramFiles} 'share\portwave')
)
foreach ($d in $shares) {
    if (Test-Path -PathType Container $d) {
        try {
            Remove-Item -Recurse -Force $d
            Say "removed $d"
        } catch {
            Warn "could not remove ${d}: $_"
        }
    }
}

# ── 4. Config directory (confirm before delete) ──
$cfg = Join-Path $env:APPDATA 'portwave'
if (Test-Path -PathType Container $cfg) {
    $a = Read-Host "Delete config directory $cfg? [y/N]"
    if ($a -match '^[Yy]') {
        Remove-Item -Recurse -Force $cfg
        Say "removed $cfg"
    } else {
        Write-Host "kept $cfg"
    }
}

# ── 5. Optional scan-output directory ──
$a = Read-Host 'Delete scan output directory too? [y/N]'
if ($a -match '^[Yy]') {
    $p = Read-Host 'Full path to delete'
    if ($p -and (Test-Path -PathType Container $p)) {
        Remove-Item -Recurse -Force $p
        Say "removed $p"
    } else {
        Warn 'path not provided or not a directory — skipped'
    }
}

Write-Host ''
Say 'portwave uninstalled.'
