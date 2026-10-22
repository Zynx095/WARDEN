<#
.SYNOPSIS
  Compile everything, then run the pytest suite with the project .venv. Extra arguments go to pytest.
.EXAMPLE
  .\scripts\test.ps1
  .\scripts\test.ps1 -k acp -x
#>
. (Join-Path $PSScriptRoot '_common.ps1')

Write-Step 'Compiling sources'
$code = Invoke-Venv -m compileall -q src tests demo scripts
if ($code -ne 0) { Stop-WithError 'Compilation failed.' 'Fix the syntax errors reported above.' }
Write-Ok 'Compilation succeeded'

Write-Step 'Running pytest'
exit (Invoke-Venv -m pytest @args)
