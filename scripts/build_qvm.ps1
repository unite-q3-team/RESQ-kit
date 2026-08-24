param(
  [Parameter(Mandatory = $true)]
  [string]$SrcDir,
  [string]$Stem
)

$ErrorActionPreference = 'Stop'
$kit = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tools = Join-Path $kit 'tools\win32-qvm'
if (-not (Test-Path (Join-Path $tools 'q3lcc.exe'))) { throw "missing $tools\q3lcc.exe" }

$src = (Resolve-Path $SrcDir).Path
if (-not $Stem) { $Stem = Split-Path $src -Leaf }
$cFile = Join-Path $src "$Stem.c"
$sys = Join-Path $src 'syscalls.asm'
if (-not (Test-Path $cFile)) { throw "missing $cFile — run emit_qvm.ps1 first" }
if (-not (Test-Path $sys)) { throw "missing $sys" }

$tmp = Join-Path $env:USERPROFILE 'AppData\Local\Temp'
$q3lcc = Join-Path $tools 'q3lcc.exe'
$q3asm = Join-Path $tools 'q3asm.exe'

Push-Location $src
try {
  Write-Host "q3lcc -DQ3_VM -S $Stem.c"
  cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& set PATH=$tools;%PATH%& `"$q3lcc`" -DQ3_VM -S `"$Stem.c`""
  if ($LASTEXITCODE -ne 0) { throw "q3lcc failed: $LASTEXITCODE" }
  Write-Host "q3asm -o $Stem"
  cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& set PATH=$tools;%PATH%& `"$q3asm`" -vq3 -m -o `"$Stem`" syscalls.asm `"$Stem.asm`""
  if ($LASTEXITCODE -ne 0) { throw "q3asm failed: $LASTEXITCODE" }
  Get-Item (Join-Path $src "$Stem.qvm") | Format-List FullName, Length, LastWriteTime
} finally {
  Pop-Location
}
