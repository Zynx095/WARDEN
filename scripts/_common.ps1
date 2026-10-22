# Shared helpers for the WARDEN PowerShell scripts. Dot-source; do not run directly.

$ErrorActionPreference = 'Stop'
$script:Root = Split-Path -Parent $PSScriptRoot
$script:VenvDir = Join-Path $Root '.venv'
$script:VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "[ OK ] $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Fail([string]$Message) { Write-Host "[FAIL] $Message" -ForegroundColor Red }

function Stop-WithError([string]$Message, [string]$Recovery) {
    Write-Fail $Message
    if ($Recovery) { Write-Host "       Fix: $Recovery" -ForegroundColor Yellow }
    exit 1
}

function Get-VenvPython {
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Stop-WithError "Project virtual environment not found at $VenvDir." 'Run .\scripts\setup.ps1'
    }
    return $VenvPython
}

# Run the venv interpreter from the repository root and return its exit code.
# Output goes straight to the console (it is not captured into the return value).
function Invoke-Venv {
    # Deliberately a simple function (no param block) so arguments like -m / -c reach Python untouched.
    $py = Get-VenvPython
    $pyArgs = $args
    Push-Location $Root
    try {
        & $py @pyArgs | Out-Host
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

# Same as Invoke-Venv but discards all output; returns only the exit code. Used for silent probes.
# ErrorActionPreference is relaxed locally because Windows PowerShell 5.1 turns redirected native
# stderr into terminating errors under 'Stop'.
function Test-Venv {
    $py = Get-VenvPython
    $pyArgs = $args
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $Root
    try {
        $null = & $py @pyArgs 2>&1
        return $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $previous
    }
}

# Run any native command silently and return its exit code (see Test-Venv for why EAP is relaxed).
function Test-Native {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $rest = @($args | Select-Object -Skip 1)
        $null = & $args[0] @rest 2>&1
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}
