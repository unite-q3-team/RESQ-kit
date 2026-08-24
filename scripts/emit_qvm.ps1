param(
  [Parameter(Mandatory = $true)]
  [string]$Qvm,
  [Parameter(Mandatory = $true)]
  [string]$OutDir,
  [string]$Names,
  [string]$Sigs
)

$ErrorActionPreference = 'Stop'
$kit = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path $Qvm)) { throw "missing QVM: $Qvm" }

$qvm = (Resolve-Path $Qvm).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = (Resolve-Path $OutDir).Path
$stem = [IO.Path]::GetFileNameWithoutExtension($qvm)
$probeDir = Join-Path $kit 'toolchain\qvm'
$probe = Join-Path $probeDir 'target\release\probe_emit.exe'

if (-not (Test-Path $probe)) {
  Write-Host "Building probe_emit / probe_sigs / probe_dump_all..."
  Push-Location $probeDir
  cargo build --release --bin probe_emit --bin probe_sigs --bin probe_dump_all
  if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed" }
  Pop-Location
}

$sigs = $Sigs
if (-not $sigs) {
  $cand = Join-Path $out "$stem.sigs"
  $sib = Join-Path (Split-Path $qvm) "$stem.sigs"
  if (Test-Path $cand) { $sigs = $cand }
  elseif (Test-Path $sib) { $sigs = $sib }
}
if (-not $sigs) {
  $sigs = Join-Path $out "$stem.sigs"
  Write-Host "probe_sigs -> $sigs"
  & (Join-Path $probeDir 'target\release\probe_sigs.exe') $qvm $sigs
  if ($LASTEXITCODE -ne 0) { throw "probe_sigs failed" }
}

$names = $Names
if (-not $names) {
  $cand = Join-Path $out "$stem.names"
  $sib = Join-Path (Split-Path $qvm) "$stem.names"
  if (Test-Path $cand) { $names = $cand }
  elseif (Test-Path $sib) { $names = $sib }
}

$cFile = Join-Path $out "$stem.c"
$sys = Join-Path $out 'syscalls.asm'
$emitArgs = @($qvm, $cFile, $sys, '--no-typed')
if ($sigs -and (Test-Path $sigs)) { $emitArgs += @('--sigs', $sigs) }
if ($names -and (Test-Path $names)) { $emitArgs += @('--names', $names) }

Write-Host "probe_emit --no-typed $stem"
& $probe @emitArgs
if ($LASTEXITCODE -ne 0) { throw "probe_emit failed" }

$struct = Join-Path $out "$stem.struct.c"
$dumpAll = Join-Path $probeDir 'target\release\probe_dump_all.exe'
$dumpArgs = @($qvm, $struct)
if ($names -and (Test-Path $names)) { $dumpArgs += $names }
Write-Host "probe_dump_all -> $struct"
& $dumpAll @dumpArgs
if ($LASTEXITCODE -ne 0) { throw "probe_dump_all failed" }

Write-Host "OK $out"
Write-Host "  identity   $cFile"
Write-Host "  structured $struct"
Write-Host "  syscalls   $sys"
