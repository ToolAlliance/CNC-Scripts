# ==== CNC Client Setup (Windows PowerShell 5.1 / GPO Startup safe) ====
# What it does:
# - Creates local group "Saacke"
# - Creates folders: C:\Saacke, C:\Numtool2, C:\Nr_Plus
# - Creates registry key: HKLM:\SOFTWARE\Saacke
# - Grants Saacke Modify on folders
# - Grants Saacke Full Control on HKLM:\SOFTWARE\Saacke
# - Adds DOMAIN\CNC_Machines_Accounts into local Saacke (uses NetBIOS domain name correctly)
# - Applies power/performance (best effort; ignores unsupported settings)
# - Enables Explorer: show file extensions + hidden items + protected OS files (Default + existing profiles)
# - Logs to C:\ProgramData\CNCClientSetup\CNCClientSetup.log
# - Status breadcrumbs in HKLM:\SOFTWARE\Saacke
#
# Run (elevated):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   & "C:\Temp\CNCClientSetup.ps1"

$ErrorActionPreference = "Stop"

# ----------------- CONFIG -----------------
$RegPath        = "HKLM:\SOFTWARE\Saacke"
$LogRoot        = "C:\ProgramData\CNCClientSetup"
$LogFile        = Join-Path $LogRoot "CNCClientSetup.log"

$PathsToCreate  = @("C:\Saacke","C:\Numtool2","C:\Nr_Plus")
$LocalGroupName = "Saacke"
$DomainGroupSam = "CNC_Machines_Accounts"

# Flags so we don’t endlessly re-apply
$FlagLocalDone  = "ClientSetupLocalCompleted"     # DWORD
$FlagDomAdded   = "ClientSetupDomainGroupAdded"   # DWORD

$ForceRerun = $false  # set $true to force a full rerun

# ----------------- BASIC HELPERS -----------------
function Ensure-Dir([string]$p) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}
function Ensure-RegKey([string]$p) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
}
Ensure-Dir $LogRoot
Ensure-RegKey $RegPath

# ----------------- LOGGING -----------------
function Log([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date).ToString("s"), $m
    try { [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine) } catch {}
}
function Say([string]$m) { Write-Host $m; Log $m }

# ----------------- ADMIN CHECK -----------------
function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ----------------- REG HELPERS -----------------
function Set-RegString([string]$name, [string]$value) {
    Ensure-RegKey $RegPath
    New-ItemProperty -Path $RegPath -Name $name -Value $value -PropertyType String -Force | Out-Null
}
function Set-RegDword([string]$name, [int]$value) {
    Ensure-RegKey $RegPath
    New-ItemProperty -Path $RegPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
}
function Get-RegDword([string]$name) {
    try { return (Get-ItemProperty -Path $RegPath -Name $name -ErrorAction Stop).$name } catch { return $null }
}

# ----------------- STEP WRAPPER -----------------
function Step([string]$name, [scriptblock]$action, [bool]$critical = $true) {
    Say "STEP START: $name"
    try {
        & $action | Out-Null
        Say "STEP OK:   $name"
        return $true
    } catch {
        $msg = $_.Exception.Message
        Say "STEP FAIL: $name :: $msg"
        if ($critical) { throw } else { return $false }
    }
}

# ----------------- LOCAL GROUP -----------------
function Ensure-LocalGroup([string]$name) {
    $out = & net.exe localgroup $name 2>&1
    if ($LASTEXITCODE -eq 0) { return }

    $out2 = & net.exe localgroup $name /add 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create local group '$name'. net.exe said: $($out2 -join ' | ')"
    }
}

function Test-LocalGroupHasMemberText([string]$localGroup, [string]$member) {
    $txt = (& net.exe localgroup $localGroup 2>&1) -join "`n"
    return ($txt -match [regex]::Escape($member))
}

# ----------------- DOMAIN HELPERS -----------------
function Get-ComputerDomainFqdn {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.PartOfDomain) { return $null }
    return $cs.Domain
}

function Wait-ForDc([string]$domainFqdn, [int]$maxSec = 120) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $maxSec) {
        $out = & nltest.exe "/dsgetdc:$domainFqdn" 2>&1
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Test-SecureChannel {
    try { return [bool](Test-ComputerSecureChannel -ErrorAction SilentlyContinue) } catch { return $false }
}

# ----------------- ADD DOMAIN GROUP (ROBUST + CORRECT NETBIOS) -----------------
function Add-DomainGroupToLocalGroup([string]$localGroup, [string]$domainNetBIOS, [string]$groupSam) {
    $member = "$domainNetBIOS\$groupSam"

    # If already in group, done
    if (Test-LocalGroupHasMemberText -localGroup $localGroup -member $member) {
        Log "Already member: $member"
        return $true
    }

    # 1) Try Add-LocalGroupMember if available
    $cmd = Get-Command Add-LocalGroupMember -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            Add-LocalGroupMember -Group $localGroup -Member $member -ErrorAction Stop
            Start-Sleep -Milliseconds 500
            if (Test-LocalGroupHasMemberText -localGroup $localGroup -member $member) { return $true }
        } catch {
            Log "Add-LocalGroupMember failed: $($_.Exception.Message)"
        }
    } else {
        Log "Add-LocalGroupMember not available; using ADSI fallback."
    }

    # 2) ADSI fallback (WinNT provider)
    try {
        $grp = [ADSI]"WinNT://./$localGroup,group"
        $grp.Add("WinNT://$domainNetBIOS/$groupSam,group")
        Start-Sleep -Milliseconds 500
        if (Test-LocalGroupHasMemberText -localGroup $localGroup -member $member) { return $true }
    } catch {
        Log "ADSI add failed: $($_.Exception.Message)"
    }

    return $false
}

# ----------------- ACL HELPERS -----------------
function Ensure-PathAclModify([string]$path, [string]$identity) {
    $grant = "${identity}:(OI)(CI)M"
    $out = & icacls.exe $path /grant $grant /T 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed on $path. Output: $($out -join ' | ')"
    }
}

function Ensure-RegistryFullControl([string]$regKeyPath, [string]$identity) {
    $acl = Get-Acl -Path $regKeyPath
    $nt  = New-Object System.Security.Principal.NTAccount($identity)

    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $nt,
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        "Allow"
    )

    $existing = $acl.Access | Where-Object { $_.IdentityReference -eq $nt }
    foreach ($e in $existing) { [void]$acl.RemoveAccessRule($e) }

    $acl.AddAccessRule($rule)
    Set-Acl -Path $regKeyPath -AclObject $acl
}

# ----------------- POWER SETTINGS (BEST EFFORT) -----------------
function Set-PowerAndPerformance {
    $ultimate = "e9a42b02-d5df-448d-aa00-03f14749eb61"

    try {
        & powercfg.exe -setactive $ultimate 2>$null
        if ($LASTEXITCODE -ne 0) {
            & powercfg.exe -duplicatescheme $ultimate | Out-Null
            & powercfg.exe -setactive $ultimate | Out-Null
        }
    } catch {}

    $activeText = (& powercfg.exe -getactivescheme 2>&1) -join " "
    $current = ($activeText -replace '.*GUID:\s*([0-9a-fA-F-]+).*','$1')

    foreach ($cmd in @(
        "powercfg /change standby-timeout-ac 0",
        "powercfg /change standby-timeout-dc 0",
        "powercfg /change monitor-timeout-ac 0",
        "powercfg /change monitor-timeout-dc 0",
        "powercfg /change hibernate-timeout-ac 0",
        "powercfg /change hibernate-timeout-dc 0"
    )) {
        try { cmd /c "$cmd >nul 2>&1" | Out-Null } catch {}
    }

    # Some systems throw "Attempted to write to unsupported setting" on these. Ignore.
    foreach ($cmd in @(
        "powercfg -setacvalueindex $current SUB_PROCESSOR PROCTHROTTLEMIN 100",
        "powercfg -setacvalueindex $current SUB_PROCESSOR PROCTHROTTLEMAX 100",
        "powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE",
        "powercfg -setacvalueindex $current SUB_PROCESSOR CPMINCORES 100",
        "powercfg -setacvalueindex $current SUB_USB USBSELECTIVESETTING 0",
        "powercfg -setacvalueindex $current SUB_PCIE ASPM 0",
        "powercfg /hibernate off"
    )) {
        try { cmd /c "$cmd >nul 2>&1" | Out-Null } catch {}
    }

    try { & reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f | Out-Null } catch {}
}

# ----------------- EXPLORER PREFS (ALL USERS) -----------------
function Set-ExplorerPrefsInHive([string]$hiveRoot) {
    $adv = Join-Path $hiveRoot "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (-not (Test-Path $adv)) { New-Item -Path $adv -Force | Out-Null }

    New-ItemProperty -Path $adv -Name "Hidden"          -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $adv -Name "ShowSuperHidden" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $adv -Name "HideFileExt"     -Value 0 -PropertyType DWord -Force | Out-Null
}

function Try-LoadHiveAndSet([string]$ntUserDatPath) {
    if (-not (Test-Path $ntUserDatPath)) { return }

    $tempName = "TempHive_" + ([Guid]::NewGuid().ToString("N"))
    $tempRoot = "Registry::HKEY_USERS\$tempName"

    $p = Start-Process -FilePath "reg.exe" -ArgumentList @("load","HKU\$tempName",$ntUserDatPath) -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { return }

    try { Set-ExplorerPrefsInHive -hiveRoot $tempRoot }
    finally { Start-Process -FilePath "reg.exe" -ArgumentList @("unload","HKU\$tempName") -Wait -WindowStyle Hidden | Out-Null }
}

# ----------------- MAIN -----------------
Say "=== CNCClientSetup starting ==="
Log ("User: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name))
Log ("Elevated: {0}" -f (Test-IsAdmin))

if (-not (Test-IsAdmin)) {
    Set-RegString "ClientSetupLastResult" "FAILED: Must run as Administrator (elevated)."
    throw "Must run as Administrator (elevated)."
}

# Mutex prevents double-run
$mutex = New-Object System.Threading.Mutex($false, "Global\CNCClientSetup")
if (-not $mutex.WaitOne(0)) {
    Say "Another instance is already running; exiting."
    exit 0
}

try {
    if ($ForceRerun) {
        Set-RegDword $FlagLocalDone 0
        Set-RegDword $FlagDomAdded  0
    }

    Set-RegString "ClientSetupLastStart"  (Get-Date).ToString("s")
    Set-RegString "ClientSetupLastResult" "RUNNING"

    $warnings = @()

    # --- LOCAL SETUP ---
    if ((Get-RegDword $FlagLocalDone) -ne 1) {
        Step "Ensure local group Saacke" { Ensure-LocalGroup $LocalGroupName } | Out-Null
        Step "Create folders" { foreach ($p in $PathsToCreate) { Ensure-Dir $p } } | Out-Null
        Step "Ensure registry key HKLM:\SOFTWARE\Saacke" { Ensure-RegKey $RegPath } | Out-Null
        Step "Apply folder ACLs" { foreach ($p in $PathsToCreate) { Ensure-PathAclModify -path $p -identity $LocalGroupName } } | Out-Null
        Step "Apply registry ACL" { Ensure-RegistryFullControl -regKeyPath $RegPath -identity $LocalGroupName } | Out-Null

        if (-not (Step "Apply power/performance settings" { Set-PowerAndPerformance } $false)) {
            $warnings += "Power settings had unsupported items"
        }

        Step "Set Explorer prefs (hidden + extensions)" {
            Try-LoadHiveAndSet "C:\Users\Default\NTUSER.DAT"
            Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") } |
                ForEach-Object { Try-LoadHiveAndSet (Join-Path $_.FullName "NTUSER.DAT") }
        } $false | Out-Null

        Set-RegDword $FlagLocalDone 1
    } else {
        Say "Local setup already completed; skipping local steps."
    }

    # --- DOMAIN GROUP ADD ---
    if ((Get-RegDword $FlagDomAdded) -ne 1) {
        $okDom = Step "Add domain group into local Saacke" {
            $domainFqdn = Get-ComputerDomainFqdn
            if ([string]::IsNullOrWhiteSpace($domainFqdn)) { throw "Computer is not domain joined." }

            if (-not (Wait-ForDc -domainFqdn $domainFqdn -maxSec 120)) { throw "No domain controller reachable for $domainFqdn." }
            if (-not (Test-SecureChannel)) { throw "Secure channel not established (Test-ComputerSecureChannel failed)." }

            # IMPORTANT: Use the correct NetBIOS domain name (ULTRA-TOOL), not FQDN (ULTRA-TOOL.INT)
            $netbios = $env:USERDOMAIN
            if ([string]::IsNullOrWhiteSpace($netbios)) { $netbios = $domainFqdn.Split('.')[0] }
            $netbios = $netbios.ToUpper()

            Log "DomainFQDN=$domainFqdn NetBIOS=$netbios"

            if (-not (Add-DomainGroupToLocalGroup -localGroup $LocalGroupName -domainNetBIOS $netbios -groupSam $DomainGroupSam)) {
                throw "Could not add $netbios\$DomainGroupSam to local $LocalGroupName."
            }

            Set-RegDword $FlagDomAdded 1
        } $false

        if (-not $okDom) { $warnings += "Domain group add pending" }
    } else {
        Say "Domain group already added; skipping."
    }

    Set-RegString "ClientSetupLastRun" (Get-Date).ToString("s")

    $localOK = ((Get-RegDword $FlagLocalDone) -eq 1)
    $domOK   = ((Get-RegDword $FlagDomAdded) -eq 1)

    if ($localOK -and $domOK) {
        if ($warnings.Count -eq 0) {
            Set-RegString "ClientSetupLastResult" "OK"
            Say "=== CNCClientSetup completed OK ==="
        } else {
            Set-RegString "ClientSetupLastResult" ("OK_WITH_WARNINGS: " + ($warnings -join "; "))
            Say "=== CNCClientSetup completed with warnings ==="
        }
    } else {
        Set-RegString "ClientSetupLastResult" ("PARTIAL: " + ($warnings -join "; "))
        Say "=== CNCClientSetup partial (will retry domain add next run) ==="
    }

    # Breadcrumb (kept)
    New-ItemProperty -Path $RegPath -Name "ClientSetupLastRun" -Value (Get-Date).ToString("s") -PropertyType String -Force | Out-Null
}
catch {
    $msg = $_.Exception.Message
    Say "=== CNCClientSetup FAILED: $msg ==="
    try {
        Set-RegString "ClientSetupLastResult" ("FAILED: " + $msg)
        Set-RegString "ClientSetupLastFail" (Get-Date).ToString("s")
    } catch {}
    throw
}
finally {
    try { $mutex.ReleaseMutex() | Out-Null } catch {}
    try { $mutex.Dispose() } catch {}
    Log "=== CNCClientSetup finished ==="
}
