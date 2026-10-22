<#
.SYNOPSIS
  Diagnose the local WARDEN setup (configuration, identity, dependencies, Git hygiene, workspace).
  Never prints secrets. Add -Tests to also run the test suite.
#>
[CmdletBinding()]
param([switch]$Tests)

. (Join-Path $PSScriptRoot '_common.ps1')
$extra = @()
if ($Tests) { $extra += '--tests' }
exit (Invoke-Venv -m warden.doctor @extra)
