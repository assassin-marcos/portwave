# portwave — Windows uninstaller
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$candidates = @(
    (Join-Path $env:USERPROFILE '.local\bin\portwave.exe'),
    (Join-Path ${env:ProgramFiles} 'portwave\portwave.exe')
)

Write-Host 'portwave uninstaller' -ForegroundColor Cyan
foreach ($bin in $candidates) {
    if (Test-Path -PathType Leaf $bin) {
        Write-Host "Removing $bin"
        Remove-Item -Force $bin
    }
}

$shares = @(
    (Join-Path $env:USERPROFILE '.local\share\portwave'),
    (Join-Path ${env:ProgramFiles} 'share\portwave')
)
foreach ($d in $shares) {
    if (Test-Path -PathType Container $d) {
        Write-Host "Removing $d"
        Remove-Item -Recurse -Force $d
    }
}

$cfg = Join-Path $env:APPDATA 'portwave'
if (Test-Path -PathType Container $cfg) {
    $a = Read-Host "Delete config directory $cfg? [y/N]"
    if ($a -match '^[Yy]') { Remove-Item -Recurse -Force $cfg }
}

$a = Read-Host 'Delete scan output directory too? [y/N]'
if ($a -match '^[Yy]') {
    $p = Read-Host 'Full path to delete'
    if ($p -and (Test-Path -PathType Container $p)) {
        Remove-Item -Recurse -Force $p
        Write-Host "Removed $p"
    }
}
Write-Host 'Done.'
