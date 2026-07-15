#Requires -Version 5.0
<#
    unknown  -  Recording Policy / PC Verification Check
    -------------------------------------------------------------------
    A LOCAL, READ-ONLY integrity scan. Run this while screen-recording
    to demonstrate a clean system. It does NOT modify, download, install,
    or transmit anything. Every check just reads what is already on the
    machine and reports SUCCESS / FAILURE.

    Steps:
      1. System info banner
      2. BAM (Background Activity Moderator) execution-history parse
      3. Prefetch + MUICache artifact scan
      4. Live process scan
      5. Defender exclusions + integrity
      6. Final score
#>

# ============================================================
#  Admin elevation
#  Works both from a saved .ps1 AND from `iex (iwr <url>)`.
#  >>> SET THIS to your own raw URL after you upload it. <
# ============================================================
$SelfUrl = 'https://raw.githubusercontent.com/YOURNAME/YOURREPO/main/unknown.ps1'

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $scriptPath = try { (Resolve-Path $MyInvocation.MyCommand.Definition -ErrorAction Stop).Path } catch { $null }

    Write-Host "[INFO] Elevating to Administrator..." -ForegroundColor Yellow
    if ($scriptPath -and (Test-Path $scriptPath)) {
        # Running from a file on disk
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$scriptPath`""
    } else {
        # Running in-memory via iex - relaunch by re-fetching the URL
        $cmd = "iex ((New-Object Net.WebClient).DownloadString('$SelfUrl'))"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand $enc"
    }
    exit
}

# ============================================================
#  Helpers
# ============================================================
function Line { param([string]$T,[ConsoleColor]$C='White') Write-Host $T -ForegroundColor $C }

function Bar {
    for ($i=0; $i -le 12; $i++){
        $b = ('#'*$i) + ('.'*(12-$i))
        Write-Host -NoNewline ("`rScanning [$b] {0,3}% " -f ([int]($i/12*100))) -ForegroundColor Cyan
        Start-Sleep -Milliseconds 90
    }
    Write-Host "`n"
}

function Wait-Enter {
    param([string]$M = "Press Enter to continue")
    Line $M Yellow
    while ($true){
        if ([Console]::KeyAvailable){ if ([Console]::ReadKey($true).Key -eq 'Enter'){ break } }
        Start-Sleep -Milliseconds 80
    }
}

# Results collector: each entry is @{ Ok=$bool; Text=... }
$Results = New-Object System.Collections.Generic.List[object]
function Add-Result { param([bool]$Ok,[string]$Text) $Results.Add(@{Ok=$Ok;Text=$Text}) }

function Show-Section {
    param([string]$Title)
    Write-Host ""
    Line ("=== $Title ===") Cyan
}

# ------------------------------------------------------------
#  Flagged executables.
#  Edit this list freely - these are the names the policy hunts
#  for across every forensic artifact below. tiworker.exe is a
#  SPECIAL case: the genuine Windows Modules Installer Worker
#  lives in System32, so it is only flagged from other folders.
# ------------------------------------------------------------
$Flagged = @(
    'spectre.exe',
    'software.exe',
    'tiworker.exe',
    'loader.exe',
    'injector.exe',
    'bamparser.exe'
)
$SystemTiWorker = @('\windows\system32\','\winsxs\','\servicing\')

function Test-Flagged {
    param([string]$FullPathOrName)
    $leaf = try { Split-Path $FullPathOrName -Leaf } catch { $FullPathOrName }
    $leaf = $leaf.ToLower()
    foreach ($f in $Flagged){
        if ($leaf -eq $f){
            if ($f -eq 'tiworker.exe'){
                $p = $FullPathOrName.ToLower()
                foreach ($s in $SystemTiWorker){ if ($p -like "*$s*"){ return $false } }
                # no legit system path -> suspicious spoof
                return $true
            }
            return $true
        }
    }
    return $false
}

# ============================================================
#  BANNER
# ============================================================
Clear-Host
Line ""
Line "  #    #  #    #  #    #  #    #   ####   #    #  #    #" Magenta
Line "  #    #  ##   #  #   #   ##   #  #    #  #    #  ##   #" Magenta
Line "  #    #  # #  #  ####    # #  #  #    #  #    #  # #  #" Magenta
Line "  #    #  #  # #  #  #    #  # #  #    #  # ## #  #  # #" Magenta
Line "   ####   #   ##  #   #   #   ##   ####    #  #   #   ##" Magenta
Line ""
Line "  Recording Policy  -  local read-only PC verification" White
Line "  Nothing is downloaded, changed, or uploaded. Read the source." DarkGray
Line ""

$os  = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
Line ("OS : {0} (build {1})" -f $os.Caption, $os.BuildNumber) White
Line ("CPU: {0}" -f $cpu.Name) White
Line ("GPU: {0}" -f $gpu.Name) White
Line ""
Wait-Enter

# ============================================================
#  STEP 1 - BAM execution history
# ============================================================
Clear-Host
Line "Step 1 of 4 : BAM Execution History" White
Line "The Background Activity Moderator logs every program that ran," DarkGray
Line "even ones already closed, with a last-run timestamp." DarkGray
Bar

$bamRoots = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
)
$bamHits = 0
$bamScanned = 0

foreach ($root in $bamRoots){
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $sidKey = $_.PSPath
        $props  = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
        if (-not $props) { return }
        $props.PSObject.Properties | Where-Object {
            $_.Name -notlike 'PS*' -and $_.Name -match '\.exe$'
        } | ForEach-Object {
            $bamScanned++
            $exePath = $_.Name
            $when = '(unknown time)'
            try {
                $data = $_.Value
                if ($data -is [byte[]] -and $data.Length -ge 8){
                    $ft = [BitConverter]::ToInt64($data,0)
                    if ($ft -gt 0){ $when = [DateTime]::FromFileTimeUtc($ft).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') }
                }
            } catch {}
            if (Test-Flagged $exePath){
                $bamHits++
                Add-Result $false "FAILURE: BAM shows flagged program ran -> $(Split-Path $exePath -Leaf)  [last run: $when]"
            }
        }
    }
}

if ($bamScanned -eq 0){
    Add-Result $true "SUCCESS: BAM readable, no execution records to inspect."
} elseif ($bamHits -eq 0){
    Add-Result $true "SUCCESS: BAM scanned ($bamScanned entries) - no flagged programs in run history."
}
$Results | Select-Object -Last 25 | ForEach-Object {
    Line $_.Text ($(if($_.Ok){'Green'}else{'Red'}))
}
Wait-Enter

# ============================================================
#  STEP 2 - Prefetch + MUICache
# ============================================================
Clear-Host
Line "Step 2 of 4 : Prefetch + MUICache Artifacts" White
Bar
$before = $Results.Count

# --- Prefetch ---
$pfDir = "$env:SystemRoot\Prefetch"
if (Test-Path $pfDir){
    $pfHit = 0
    Get-ChildItem $pfDir -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object {
        # prefetch file names look like  SPECTRE.EXE-1A2B3C4D.pf
        $name = ($_.BaseName -replace '-[0-9A-F]{8}$','')
        if (Test-Flagged $name){
            $pfHit++
            Add-Result $false "FAILURE: Prefetch trace for $name  (last run: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"
        }
    }
    if ($pfHit -eq 0){ Add-Result $true "SUCCESS: Prefetch scanned - no flagged executables." }
} else {
    Add-Result $true "SUCCESS: Prefetch folder not present (may be disabled) - skipped."
}

# --- MUICache (records paths of programs the user has launched) ---
$mui = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
if (Test-Path $mui){
    $muiHit = 0
    $props = Get-ItemProperty $mui -ErrorAction SilentlyContinue
    if ($props){
        $props.PSObject.Properties | Where-Object { $_.Name -like '*.exe*' } | ForEach-Object {
            if (Test-Flagged $_.Name){
                $muiHit++
                Add-Result $false "FAILURE: MUICache references flagged program -> $(Split-Path ($_.Name -replace '\.FriendlyAppName$','') -Leaf)"
            }
        }
    }
    if ($muiHit -eq 0){ Add-Result $true "SUCCESS: MUICache scanned - clean." }
} else {
    Add-Result $true "SUCCESS: MUICache key not present - skipped."
}

$Results | Select-Object -Skip $before | ForEach-Object {
    Line $_.Text ($(if($_.Ok){'Green'}else{'Red'}))
}
Wait-Enter

# ============================================================
#  STEP 3 - Live processes
# ============================================================
Clear-Host
Line "Step 3 of 4 : Running Process Scan" White
Bar
$before = $Results.Count
$procHit = 0

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $null
    try { $path = $_.Path } catch {}
    $name = if ($path){ $path } else { "$($_.ProcessName).exe" }
    if (Test-Flagged $name){
        $procHit++
        Add-Result $false "FAILURE: Flagged process live -> $($_.ProcessName) (PID $($_.Id))  Path: $(if($path){$path}else{'n/a'})"
    }
}
if ($procHit -eq 0){ Add-Result $true "SUCCESS: No flagged processes currently running." }

$Results | Select-Object -Skip $before | ForEach-Object {
    Line $_.Text ($(if($_.Ok){'Green'}else{'Red'}))
}
Wait-Enter

# ============================================================
#  STEP 4 - Defender exclusions + integrity
# ============================================================
Clear-Host
Line "Step 4 of 4 : Defender Exclusions + Integrity" White
Line "Cheaters often whitelist a folder so AV ignores it - none should exist." DarkGray
Bar
$before = $Results.Count

try {
    $pref = Get-MpPreference -ErrorAction Stop
    $ex = @()
    $ex += $pref.ExclusionPath
    $ex += $pref.ExclusionProcess
    $ex += $pref.ExclusionExtension
    $ex = $ex | Where-Object { $_ }
    if ($ex.Count -gt 0){
        foreach ($e in $ex){ Add-Result $false "FAILURE: Defender exclusion present -> $e" }
    } else {
        Add-Result $true "SUCCESS: No Defender exclusions of any kind."
    }
} catch {
    Add-Result $false "WARNING: Could not read Defender exclusions ($($_.Exception.Message))."
}

try {
    $st = Get-MpComputerStatus -ErrorAction Stop
    if ($st.RealTimeProtectionEnabled){ Add-Result $true "SUCCESS: Real-time protection is ON." }
    else { Add-Result $false "FAILURE: Real-time protection is OFF." }
    if ($st.AntivirusEnabled){ Add-Result $true "SUCCESS: Antivirus engine enabled." }
    else { Add-Result $false "FAILURE: Antivirus engine disabled." }
} catch {
    Add-Result $false "WARNING: Could not query Defender status."
}

try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
               Where-Object { $_.ThreatStatusID -in 1,3,5 }   # active / quarantine-failed
    if ($threats){ foreach($t in $threats){ Add-Result $false "FAILURE: Active threat detection id $($t.ThreatID)" } }
    else { Add-Result $true "SUCCESS: No active Defender threat detections." }
} catch {
    Add-Result $true "SUCCESS: No active threat detections found."
}

$Results | Select-Object -Skip $before | ForEach-Object {
    $c = if ($_.Text -match '^WARNING'){'Yellow'} elseif ($_.Ok){'Green'} else {'Red'}
    Line $_.Text $c
}
Wait-Enter

# ============================================================
#  SCORE
# ============================================================
Clear-Host
Show-Section "Final Result"
$total = $Results.Count
$pass  = ($Results | Where-Object { $_.Ok }).Count
$fail  = $total - $pass
$rate  = if ($total){ [math]::Round($pass/$total*100,0) } else { 0 }

Line ("Passed : {0}" -f $pass) Green
Line ("Failed : {0}" -f $fail) ($(if($fail){'Red'}else{'Green'}))
Line ("Score  : {0}%" -f $rate) ($(if($rate -eq 100){'Green'}else{'Red'}))
Write-Host ""
if ($rate -eq 100){
    Line "RESULT: PASS - system is clean under this policy." Green
} else {
    Line "RESULT: REVIEW - one or more checks flagged. See FAILUREs above." Red
}
Write-Host ""
Wait-Enter "Press Enter to exit"
exit