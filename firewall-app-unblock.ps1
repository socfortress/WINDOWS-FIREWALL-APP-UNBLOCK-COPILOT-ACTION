[CmdletBinding()]
param(
  [string]$AppName,
  [int]$MaxWaitSeconds=300,
  [string]$LogPath="$env:TEMP\UnblockApp-script.log",
  [string]$ARLog='C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

if (-not $AppName -and $Arg1)     { $AppName = $Arg1 }
if (-not $AppName -and $env:ARG1) { $AppName = $env:ARG1 }

if (-not $AppName) { throw "AppName is required (set -AppName, caller `$Arg1, or `$env:ARG1)" }

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN'{Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  return (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz')
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Unblock Application ==="

$ts = Now-Timestamp
$lines = @()

try {
  if(-not $AppName){ throw "AppName is required (pass -AppName or -Arg1)" }

  $RuleBase="BlockApp_$($AppName.Replace(' ','_'))"
  $RuleInbound="$RuleBase`_In"
  $RuleOutbound="$RuleBase`_Out"

  $removedIn=$false
  $removedOut=$false

  $ruleIn=Get-NetFirewallRule -DisplayName $RuleInbound -ErrorAction SilentlyContinue
  if($ruleIn){
    Remove-NetFirewallRule -DisplayName $RuleInbound
    $removedIn=$true
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_app'
      copilot_action = $true
      type           = 'rule_removed'
      direction      = 'inbound'
      display_name   = $RuleInbound
    } | ConvertTo-Json -Compress -Depth 4)
  } else {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_app'
      copilot_action = $true
      type           = 'rule_missing'
      direction      = 'inbound'
      display_name   = $RuleInbound
    } | ConvertTo-Json -Compress -Depth 4)
  }
  $ruleOut=Get-NetFirewallRule -DisplayName $RuleOutbound -ErrorAction SilentlyContinue
  if($ruleOut){
    Remove-NetFirewallRule -DisplayName $RuleOutbound
    $removedOut=$true
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_app'
      copilot_action = $true
      type           = 'rule_removed'
      direction      = 'outbound'
      display_name   = $RuleOutbound
    } | ConvertTo-Json -Compress -Depth 4)
  } else {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_app'
      copilot_action = $true
      type           = 'rule_missing'
      direction      = 'outbound'
      display_name   = $RuleOutbound
    } | ConvertTo-Json -Compress -Depth 4)
  }
  foreach ($rn in @($RuleOutbound, $RuleInbound)) {
    $r = Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_app'
      copilot_action = $true
      type           = 'verify_rule'
      display_name   = $rn
      exists         = [bool]$r
      enabled        = if ($r) { [bool]$r.Enabled } else { $false }
    } | ConvertTo-Json -Compress -Depth 4)
  }

  # Summary always first
  $status=if($removedIn -or $removedOut){'unblocked'}else{'not_found'}
  $summary=[pscustomobject]@{
    timestamp     = $ts
    host          = $HostName
    action        = 'unblock_app'
    copilot_action = $true
    type          = 'summary'
    app_name      = $AppName
    rule_inbound  = $RuleInbound
    rule_outbound = $RuleOutbound
    status        = $status
    duration_s    = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }

  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'unblock_app'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}



