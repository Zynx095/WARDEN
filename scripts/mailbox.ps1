<#
.SYNOPSIS
  Check or connect the local WARDEN agent's Agentverse Mailbox using the project .venv.
.EXAMPLE
  .\scripts\mailbox.ps1 status                # what the Inspector sees, the Almanac record, the mailbox
  .\scripts\mailbox.ps1 connect -DryRun       # show the registration; send nothing
  .\scripts\mailbox.ps1 connect -Confirm      # register as a Mailbox agent (needs AGENTVERSE_API_KEY in .env)
  .\scripts\mailbox.ps1 disconnect -Confirm   # remove the Agentverse registration, e.g. before re-connecting
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'connect', 'disconnect')]
    [string]$Action = 'status',
    [switch]$DryRun,
    [switch]$Confirm,
    [int]$Port = 0
)

. (Join-Path $PSScriptRoot '_common.ps1')
$pyArgs = @('-m', 'warden.agents.mailbox', $Action)
if ($Action -eq 'status') {
    if ($Port -gt 0) { $pyArgs += @('--port', "$Port") }
} else {
    if ($Confirm -eq $DryRun) {
        Stop-WithError "$Action needs exactly one of -DryRun or -Confirm." ".\scripts\mailbox.ps1 $Action -DryRun"
    }
    $pyArgs += $(if ($Confirm) { '--confirm' } else { '--dry-run' })
}
exit (Invoke-Venv @pyArgs)
