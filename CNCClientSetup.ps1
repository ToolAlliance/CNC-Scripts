# ==== CNC Client Setup (bullet-proof for GPO Startup) ====

# ---------- Config ----------
$RegPath      = "HKLM:\SOFTWARE\Saacke"
$LogRoot      = "C:\ProgramData\CNCClientSetup"
$LogFile      = Join-Path $LogRoot "CNCClientSetup.log"
$LockName     = "CNCClientSetupLock"
$OneTimeName  = "ClientSetupCompleted"
$ForceRerun   = $false   # set $true to force re-run even if completed already

$PathsToCreate = @("C:\Saacke","C:\Numtool2","C:\Nr_Plus")
$LocalGroupName = "Saacke"
$DomainGroupSam = "CNC_Machines_Accounts"

$MaxNetworkWaitSec = 180
$MaxAdResolveWaitSec = 180
$RetryDelaySec = 5

# ---------- Helpers ----------
function Ensure-Dir([string]$p) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Ensure-RegKey([string]$p) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
}

function Set-RegString([string]$name, [string]$value) {
    Ensure-RegKey $RegPath
    New-ItemProperty -Path $RegPath -Name $name -Value $value -PropertyType String -Force | Out-Null
}

function Set-RegDword([string]$name, [int]$value) {
    Ensure-RegKey $RegPath
    New-ItemProperty -Path $RegPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
}

function Wait-ForDomain([int]$maxSec) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $maxSec) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem
            if ($cs.PartOfDomain -and $cs.Domain -and $cs.Domain -ne $env:COMPUTERNAME) { return $cs.Domain }
        } catch {}
        Start-Sleep -Seconds 2
    }
    return $null
}

function Wait-ForSysvol([string]$domainFqdn, [int]$maxSec) {
    $sysvol = "\\$domainFqdn\SYSVOL"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $maxSec) {
        if (Test-Path $sysvol) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Ensure-LocalGroup([string]$name, [string]$desc) {
    try {
        if (-not (Get-LocalGroup -Name $name -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $name -Description $desc | Out-Null
        }
    } catch {
        cmd /c "net localgroup `"$name`" /add" | Out-Null
    }
}

function Ensure-PathAclModify([string]$path, [string]$identity) {
    # Ensure Modify on folders recursively
    icacls $path /grant "$identity:(OI)(CI)M" /T | Out-Null
}

function Ensure-RegistryFullControl([string]$regKeyPath, [string]$identity) {
    $acl = Get-Acl -Path $regKeyPath
    $nt  = New-Object System.Security.Principal.NTAccount($identity)

    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $nt,
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        'Allow'
    )

    # Remove existing rules for that identity (clean replace)
    $existing = $acl.Access | Where-Object { $_.IdentityReference -eq $nt }
    foreach ($e in $existing) { [void]$acl.RemoveAccessRule($e) }

    $acl.AddAccessRule($rule)
    Set-Acl -Path $regKeyPath -AclObject $acl
}

function Get-DomainShortName([string]$domainFqdn) {
    if ([string]::IsNullOrWhiteSpace($domainFqdn)) { return $null }
    return $domainFqdn.Split('.')[0].ToUpper()
}

function Add-LocalGroupMemberSafe([string]$localGroup, [string]$memberSam, [int]$maxWaitSec) {
    # Retry because at startup AD group lookup can fail briefly
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $maxWaitSec) {
        try {
            # If already present, we're done
            try {
                $members = Get-LocalGroupMember -Group $localGroup -ErrorAction SilentlyContinue
                if ($members -and ($members.Name -contains $memberSam)) { return $true }
            } catch {}

            Add-LocalGroupMember -Group $localGroup -Member $memberSam -ErrorAction Stop
            return $true
        }
        catch {
            # fallback attempt
            try {
                cmd /c "net localgroup `"$localGroup`" `"$memberSam`" /add" | Out-Null
                return $true
            } catch {}
        }
        Start-Sleep -Seconds $RetryDelaySec
    }
    return $false
}

function Set-PowerAndPerformance() {
    $ultimate = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    try { powercfg -setactive $ultimate 2>$null }
    catch {
        powercfg -duplicatescheme $ultimate | Out-Null
        powercfg -setactive $ultimate | Out-Null
    }

    $current = (powercfg -getactivescheme) -replace '.*GUID:\s*([0-9a-fA-F-]+).*','$1'

    cmd /c "powercfg /change standby-timeout-ac 0"   | Out-Null
    cmd /c "powercfg /change standby-timeout-dc 0"   | Out-Null
    cmd /c "powercfg /change monitor-timeout-ac 0"   | Out-Null
    cmd /c "powercfg /change monitor-timeout-dc 0"   | Out-Null
    cmd /c "powercfg /change hibernate-timeout-ac 0" | Out-Null
    cmd /c "powercfg /change hibernate-timeout-dc 0" | Out-Null

    powercfg -setacvalueindex $current SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
    powercfg -setacvalueindex $current SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
    powercfg -attributes      SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE      | Out-Null
    powercfg -setacvalueindex $current SUB_PROCESSOR CPMINCORES 100      | Out-Null
    powercfg -setacvalueindex $current SUB_USB  USBSELECTIVESETTING 0    | Out-Null
    powercfg -setacvalueindex $current SUB_PCIE ASPM 0                   | Out-Null

    powercfg /hibernate off | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f | Out-Null
}

# ---------- Start ----------
Ensure-Dir $LogRoot
Start-Transcript -Path $LogFile -Append
$ErrorActionPreference = "Stop"

try {
    # Lock to avoid double-run during weird startup conditions
    Ensure-RegKey $RegPath
    $lock = (Get-ItemProperty -Path $RegPath -Name $LockName -ErrorAction SilentlyContinue).$LockName
    if ($lock -and $lock -eq 1) {
        Write-Output "Another instance appears to be running. Exiting."
        exit 0
    }
    Set-RegDword $LockName 1

    # One-time gate
    $completed = (Get-ItemProperty -Path $RegPath -Name $OneTimeName -ErrorAction SilentlyContinue).$OneTimeName
    if (-not $ForceRerun -and $completed -eq 1) {
        Write-Output "Setup already completed. Exiting."
        exit 0
    }

    Set-RegString "ClientSetupLastStart" (Get-Date).ToString("s")

    # Wait for domain + SYSVOL so share / AD lookups are stable
    $domainFqdn = Wait-ForDomain -maxSec $MaxNetworkWaitSec
    if (-not $domainFqdn) { throw "Machine does not appear to be domain-joined (or domain not reachable) after waiting $MaxNetworkWaitSec seconds." }

    if (-not (Wait-ForSysvol -domainFqdn $domainFqdn -maxSec $MaxNetworkWaitSec)) {
        throw "SYSVOL not reachable (\\$domainFqdn\SYSVOL) after waiting $MaxNetworkWaitSec seconds."
    }

    # 1) Local group
    Ensure-LocalGroup -name $LocalGroupName -desc "SAACKE operators"

    # 2) Folders + registry key
    foreach ($p in $PathsToCreate) { Ensure-Dir $p }
    Ensure-RegKey $RegPath

    # 3) Folder ACLs (Modify)
    foreach ($p in $PathsToCreate) { Ensure-PathAclModify -path $p -identity $LocalGroupName }

    # 4) Registry ACL (Full Control)
    Ensure-RegistryFullControl -regKeyPath $RegPath -identity $LocalGroupName

    # 5) Add domain group into local group (retry)
    $domShort = Get-DomainShortName -domainFqdn $domainFqdn
    if (-not $domShort) { throw "Unable to determine domain short name from $domainFqdn" }

    $domGroup = "$domShort\$DomainGroupSam"
    $added = Add-LocalGroupMemberSafe -localGroup $LocalGroupName -memberSam $domGroup -maxWaitSec $MaxAdResolveWaitSec
    if (-not $added) { throw "Failed to add $domGroup to local group $LocalGroupName after retries." }

    # 6) Power & performance
    Set-PowerAndPerformance

    # Success breadcrumbs
    Set-RegString "ClientSetupLastRun" (Get-Date).ToString("s")
    Set-RegDword  $OneTimeName 1
    Set-RegString "ClientSetupLastResult" "OK"

    Write-Output "CNCClientSetup completed OK at $(Get-Date)."
}
catch {
    $msg = $_.Exception.Message
    Write-Error "CNCClientSetup FAILED: $msg"
    try {
        Set-RegString "ClientSetupLastResult" ("FAILED: " + $msg)
        Set-RegString "ClientSetupLastFail" (Get-Date).ToString("s")
    } catch {}
    throw
}
finally {
    # release lock
    try { Set-RegDword $LockName 0 } catch {}
    Stop-Transcript | Out-Null
}
  
