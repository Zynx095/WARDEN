<#
.SYNOPSIS
  Run the deterministic, offline WARDEN demonstration on a disposable synthetic workspace
  (temp_demo_workspace). Exits non-zero if any independent check fails.
#>
. (Join-Path $PSScriptRoot '_common.ps1')
exit (Invoke-Venv demo/run_demo.py)
