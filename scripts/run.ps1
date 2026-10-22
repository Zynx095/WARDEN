<#
.SYNOPSIS
  Start the WARDEN uAgent (local-only by default, bound to 127.0.0.1) using the project .venv.
.EXAMPLE
  .\scripts\run.ps1                 # start the agent
  .\scripts\run.ps1 -ShowAddress    # print the public agent address and exit
  .\scripts\run.ps1 -Port 8001      # use another local port
  .\scripts\run.ps1 -Mailbox        # opt in to Agentverse mailbox mode (needs account provisioning)
#>
[CmdletBinding()]
param(
    [switch]$ShowAddress,
    [switch]$Mailbox,
    [int]$Port = 0
)

. (Join-Path $PSScriptRoot '_common.ps1')
$extra = @()
if ($ShowAddress) { $extra += '--show-address' }
if ($Mailbox)     { $extra += '--mailbox' }
if ($Port -gt 0)  { $extra += @('--port', "$Port") }
exit (Invoke-Venv -m warden.agents.run_agent @extra)
