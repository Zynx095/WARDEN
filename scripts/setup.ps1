<#
.SYNOPSIS
  One-command, rerunnable local setup for WARDEN on Windows.
.DESCRIPTION
  Creates .venv if needed, installs dependencies from pyproject.toml, creates .env from
  .env.example only when .env is missing, generates an agent identity only when none is
  configured (never replaces one), prepares the workspace, runs the tests and the doctor.
  Secrets are never printed. No external accounts or credentials are required.
.PARAMETER SkipTests
  Skip the validation test run.
.PARAMETER NoOptional
  Skip optional packages (the openai client used only for ASI:One intent parsing).
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$NoOptional
)

. (Join-Path $PSScriptRoot '_common.ps1')
Set-Location $Root

function Find-Python {
    foreach ($candidate in @(@('py', '-3.12'), @('py', '-3'), @('python'), @('python3'))) {
        $exe = $candidate[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $extra = @($candidate | Select-Object -Skip 1)
        $ver = $null
        try { $ver = & $exe @extra -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { }
        if ($LASTEXITCODE -ne 0 -or -not $ver) { continue }
        $parts = "$ver".Trim().Split('.')
        if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10)) {
            return ,(@($exe) + $extra)
        }
    }
    return $null
}

# 1-2. Python and virtual environment (created only when missing) ----------------------
Write-Step 'Python and virtual environment'
if (Test-Path -LiteralPath $VenvPython) {
    Write-Ok ".venv already exists; reusing it"
} else {
    $found = Find-Python
    if (-not $found) {
        Stop-WithError 'Python 3.10+ was not found.' 'Install Python 3.12 from https://www.python.org/downloads/ (tick "Add to PATH") and rerun.'
    }
    Write-Host "Creating .venv with: $($found -join ' ')"
    $exe = $found[0]; $extra = @($found | Select-Object -Skip 1)
    & $exe @extra -m venv $VenvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPython)) {
        Stop-WithError 'Could not create the virtual environment.' 'Delete a partial .venv folder and rerun setup.'
    }
    Write-Ok 'Created .venv'
}
$null = Invoke-Venv -c "import sys; assert sys.version_info >= (3, 10), sys.version; print('Python', sys.version.split()[0])"
if ($LASTEXITCODE -ne 0) { Stop-WithError 'The .venv interpreter is older than Python 3.10.' 'Delete .venv and rerun with Python 3.10+ installed.' }

# 3. Dependencies from pyproject.toml ---------------------------------------------------
Write-Step 'Installing dependencies (pyproject.toml)'
$spec = if ($NoOptional) { '.[dev]' } else { '.[dev,fetch]' }
$code = Invoke-Venv -m pip install --disable-pip-version-check --quiet -e $spec
if ($code -ne 0) {
    Stop-WithError 'Dependency installation failed.' 'Check your internet connection / proxy, then rerun .\scripts\setup.ps1'
}
Write-Ok "Installed $spec"

# 4. Import verification ----------------------------------------------------------------
Write-Step 'Verifying imports'
$code = Invoke-Venv -c "import uagents, uagents_core.contrib.protocols.chat, pydantic, dotenv, warden.agents.run_agent; print('imports ok')"
if ($code -ne 0) { Stop-WithError 'Import verification failed.' 'Rerun setup; if it persists run .\scripts\doctor.ps1' }

# 5. Configuration template and .env ----------------------------------------------------
Write-Step 'Configuration'
$example = Join-Path $Root '.env.example'
$envFile = Join-Path $Root '.env'
if (-not (Test-Path -LiteralPath $example)) { Stop-WithError '.env.example is missing.' 'Restore it with: git checkout -- .env.example' }
if (Test-Path -LiteralPath $envFile) {
    Write-Ok '.env already exists; leaving it untouched'
} else {
    Copy-Item -LiteralPath $example -Destination $envFile
    Write-Ok 'Created .env from .env.example (placeholders only)'
}

# 6. Secrets excluded from Git ----------------------------------------------------------
Write-Step 'Checking Git exclusions'
if (Get-Command git -ErrorAction SilentlyContinue) {
    & git -C $Root check-ignore -q .env
    if ($LASTEXITCODE -ne 0) { Stop-WithError '.env is NOT ignored by Git.' "Add '.env' to .gitignore before continuing." }
    & git -C $Root ls-files --error-unmatch .env 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Stop-WithError '.env is tracked by Git.' 'Run: git rm --cached .env  (then rotate AGENT_SEED)' }
    Write-Ok '.env is ignored and untracked'
} else {
    Write-Warn 'git not found; could not verify .env exclusion'
}

# 7. Identity (created only when absent; never replaced) --------------------------------
Write-Step 'Agent identity'
$code = Invoke-Venv -m warden.identity address 2>$null
if ($code -ne 0) {
    Write-Host 'No valid AGENT_SEED configured; generating one into .env (the seed is not printed).'
    $code = Invoke-Venv -m warden.identity init
    if ($code -ne 0) { Stop-WithError 'Identity initialization failed.' 'See the message above; an existing seed is never replaced.' }
}

# 8. Workspace --------------------------------------------------------------------------
Write-Step 'Workspace'
$code = Invoke-Venv -c "from warden.config import load_environment, WardenConfig; load_environment(); from warden.execution.workspace import Workspace; w = Workspace(WardenConfig().workspace_root); print('workspace ready:', w.root_path)"
if ($code -ne 0) { Stop-WithError 'Workspace initialization failed.' 'Check WARDEN_WORKSPACE_ROOT in .env' }

# 9. Tests ------------------------------------------------------------------------------
if ($SkipTests) {
    Write-Warn 'Skipping tests (-SkipTests)'
} else {
    Write-Step 'Running validation tests'
    $code = Invoke-Venv -m pytest -q
    if ($code -ne 0) { Stop-WithError 'Tests failed.' 'Run .\scripts\test.ps1 -x for details' }
    Write-Ok 'Test suite passed'
}

# 10. Doctor ----------------------------------------------------------------------------
Write-Step 'Diagnostics'
$code = Invoke-Venv -m warden.doctor
if ($code -ne 0) { Stop-WithError 'Doctor reported failures.' 'Follow the "fix:" hints above, then rerun .\scripts\setup.ps1' }

Write-Host ''
Write-Ok 'WARDEN is ready (local-only mode; no external credentials needed).'
Write-Host '  Demo:   .\scripts\demo.ps1'
Write-Host '  Run:    .\scripts\run.ps1'
Write-Host '  Check:  .\scripts\doctor.ps1'
