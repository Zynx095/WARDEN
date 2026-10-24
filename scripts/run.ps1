<#
.SYNOPSIS
  Start the WARDEN uAgent (local-only by default, bound to 127.0.0.1) using the project .venv.
.EXAMPLE
  .\scripts\run.ps1                   # start the agent
  .\scripts\run.ps1 -ShowAddress      # print the public agent address and exit
  .\scripts\run.ps1 -Port 8001        # use another local port
  .\scripts\run.ps1 -Mailbox          # opt in to Agentverse mailbox mode (needs account provisioning)
  .\scripts\run.ps1 -PublishManifest  # publish protocol manifest to Almanac for discovery
  .\scripts\run.ps1 -DemoWorkspace    # use the synthetic public-demo workspace (fixtures only)
  .\scripts\run.ps1 -Mailbox -PublishManifest -DemoWorkspace   # the ASI:One mailbox agent
#>
[CmdletBinding()]
param(
    [switch]$ShowAddress,
    [switch]$Mailbox,
    [switch]$PublishManifest,
    [switch]$DemoWorkspace,
    [int]$Port = 0
)

. (Join-Path $PSScriptRoot '_common.ps1')
$extra = @()
if ($ShowAddress)     { $extra += '--show-address' }
if ($Mailbox)         { $extra += '--mailbox' }
if ($PublishManifest) { $extra += '--publish-manifest' }
if ($DemoWorkspace)   { $extra += '--demo-workspace' }
if ($Port -gt 0)      { $extra += @('--port', "$Port") }
exit (Invoke-Venv -m warden.agents.run_agent @extra)
