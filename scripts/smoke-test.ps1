$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$python = if (Test-Path -LiteralPath $venvPython) {
    $venvPython
} else {
    (Get-Command python -ErrorAction Stop).Source
}
$smokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("violin-smoke-" + [guid]::NewGuid().ToString("N"))
$engagement = Join-Path $smokeRoot "engagement"

function Invoke-Guard {
    param([string[]]$Arguments)
    $output = & $python (Join-Path $repoRoot "scripts\violin_guard.py") @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "violin_guard.py $($Arguments -join ' ') failed with exit code $LASTEXITCODE`n$($output -join "`n")"
    }
    return $output
}

try {
    New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
    Invoke-Guard @("init-engagement", $engagement, "--host", "10.10.10.10", "--session-id", "windows-smoke") | Out-Null

    $scopePath = Join-Path $engagement "scope\scope.yaml"
    $scope = Get-Content -LiteralPath $scopePath -Raw
    $scope = $scope -replace "confirmed: false", "confirmed: true"
    Set-Content -LiteralPath $scopePath -Value $scope -Encoding UTF8
    Invoke-Guard @("validate-scope", "--scope", $scopePath) | Out-Null

    Invoke-Guard @("check-bootstrap", "--eng-dir", $engagement) | Out-Null
    Invoke-Guard @("target", "--eng-dir", $engagement, "--field", "host") | Out-Null

    Write-Output "PASS: Windows administrative smoke completed bootstrap, scope, and target resolution checks."
}
finally {
    if (Test-Path -LiteralPath $smokeRoot) {
        Remove-Item -LiteralPath $smokeRoot -Recurse -Force
    }
}
