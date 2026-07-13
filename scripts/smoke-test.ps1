param(
    [switch]$NoHermes
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

Write-Host "Violin smoke test (PowerShell)"
Write-Host "Repo: $RepoRoot"

python scripts/violin_guard.py check-release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($NoHermes) {
    Write-Host "Skipping Hermes install smoke because -NoHermes was supplied."
    exit 0
}

$Hermes = Get-Command hermes -ErrorAction SilentlyContinue
if (-not $Hermes) {
    Write-Host "Hermes not found on PATH. Release checks passed; install smoke skipped."
    exit 0
}

$ProfileName = "violin-smoke-$([int][double]::Parse((Get-Date -UFormat %s)))"
try {
    hermes profile install . --name $ProfileName -y
    if ($LASTEXITCODE -ne 0) { throw "Hermes profile install failed." }
    hermes profile show $ProfileName
    if ($LASTEXITCODE -ne 0) { throw "Hermes profile show failed." }
    hermes -p $ProfileName tools --summary
    if ($LASTEXITCODE -ne 0) { throw "Hermes tool listing failed." }
    hermes -p $ProfileName chat -q "Smoke test: reply with Violin profile loaded" -Q
    if ($LASTEXITCODE -ne 0) { throw "Hermes chat smoke test failed." }
}
finally {
    hermes profile delete $ProfileName -y 2>$null
}
