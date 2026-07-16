#Requires -Version 5.0
<#
    unknown  -  Recording Policy / PC Verification Check
    ---------------------------------------------------------------
    LOCAL, READ-ONLY forensic scan. Nothing is downloaded, modified,
    installed, or transmitted. Run while screen-recording.

    HOW TO RUN
      Save as unknown.ps1, then right-click > Run with PowerShell,
      or from an Administrator terminal:
          powershell -ExecutionPolicy Bypass -File .\unknown.ps1

    COLOURS
      GREEN  = checked, clean
      ORANGE = could not determine / artifact missing or emptied
      RED    = flagged
    A missing artifact is ORANGE, not GREEN - gaps in history are a finding.
#>

# ===================== ELEVATION (file-based only) =====================
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $sp = try { (Resolve-Path $MyInvocation.MyCommand.Definition -ErrorAction Stop).Path } catch { $null }
    if ($sp -and (Test-Path $sp)) {
        Write-Host "[INFO] Restarting as Administrator..." -ForegroundColor Yellow
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$sp`""
        exit
    } else {
        Write-Host "`n[ERROR] Run this from a saved file. Save as unknown.ps1, right-click > Run with PowerShell.`n" -ForegroundColor Red
        Pause; exit 1
    }
}

# ===================== HELPERS =====================
$PASS='Pass'; $WARN='Unsure'; $FAIL='Fail'
function C-Of { param([string]$S) switch ($S){ 'Pass'{'Green'} 'Unsure'{'DarkYellow'} 'Fail'{'Red'} default{'Gray'} } }
function Line { param([string]$T,[ConsoleColor]$C='Gray') Write-Host $T -ForegroundColor $C }

function Bar { param([string]$L='Scanning')
    for ($i=0; $i -le 14; $i++){
        $b = ([char]0x2588).ToString()*$i + ('-'*(14-$i))
        Write-Host -NoNewline ("`r  $L [$b] {0,3}%" -f ([int]($i/14*100))) -ForegroundColor DarkCyan
        Start-Sleep -Milliseconds 55
    }
    Write-Host "`n" }

function Wait-Enter { param([string]$M="  Press Enter to continue")
    Write-Host ""; Line $M DarkYellow
    while ($true){ if ([Console]::KeyAvailable){ if ([Console]::ReadKey($true).Key -eq 'Enter'){break} } Start-Sleep -Milliseconds 70 } }

$Results = New-Object System.Collections.Generic.List[object]
function R { param([string]$State,[string]$Text,[string]$Tool=$null)
    $Results.Add([pscustomobject]@{State=$State;Text=$Text;Tool=$Tool}) }

function Flush { param([int]$From)
    for ($i=$From; $i -lt $Results.Count; $i++){
        $r=$Results[$i]
        $tag = switch ($r.State){ 'Pass'{'[ OK ]'} 'Unsure'{'[ ?? ]'} 'Fail'{'[FAIL]'} }
        Line ("  $tag $($r.Text)") (C-Of $r.State)
        if ($r.Tool -and $r.State -ne 'Pass'){ Line ("         -> deeper: $($r.Tool)") DarkGray }
    } }

function Head { param([string]$N,[string]$T,[string]$Sub)
    Clear-Host; Write-Host ""
    Line ("  STEP $N  |  $T") White
    Line ("  $Sub") DarkGray
    Line ("  " + ('-'*66)) DarkGray; Write-Host "" }

# ===================== FLAGGED NAMES =====================
# Edit freely. tiworker.exe is special-cased: the real one lives in
# System32, so it is only flagged when found outside system folders.
$Flagged = @('spectre.exe','software.exe','tiworker.exe','loader.exe',
             'injector.exe','bamparser.exe','svhost.exe','csrss32.exe')
$TiOk = @('\windows\system32\','\winsxs\','\servicing\')

function Test-Flagged { param([string]$P)
    if (-not $P) { return $false }
    $leaf = try { (Split-Path $P -Leaf).ToLower() } catch { $P.ToLower() }
    foreach ($f in $Flagged){
        if ($leaf -eq $f){
            if ($f -eq 'tiworker.exe'){
                $lp=$P.ToLower(); foreach ($s in $TiOk){ if ($lp -like "*$s*"){ return $false } }
                return $true
            }
            return $true
        }
    }
    return $false }

# ===================== BANNER =====================
Clear-Host
Write-Host ""
Line "   #    #  #    #  #    #  #    #   ####   #    #  #    #" Magenta
Line "   #    #  ##   #  #   #   ##   #  #    #  #    #  ##   #" Magenta
Line "   #    #  # #  #  ####    # #  #  #    #  #    #  # #  #" Magenta
Line "   #    #  #  # #  #  #    #  # #  #    #  # ## #  #  # #" Magenta
Line "    ####   #   ##  #   #   #   ##   ####    #  #   #   ##" Magenta
Write-Host ""
Line "   Recording Policy  -  local, read-only verification" White
Line "   Nothing downloaded. Nothing changed. Nothing uploaded." DarkGray
Write-Host ""
Line "   GREEN  = checked and clean"  Green
Line "   ORANGE = could not determine / artifact cleared" DarkYellow
Line "   RED    = flagged" Red
Write-Host ""
$os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
Line ("   OS      : {0} (build {1})" -f $os.Caption,$os.BuildNumber) Gray
Line ("   CPU     : {0}" -f $cpu.Name) Gray
Line ("   Install : {0}" -f $os.InstallDate.ToString('yyyy-MM-dd HH:mm')) Gray
Line ("   Uptime  : {0:dd\d\ hh\h\ mm\m}" -f ((Get-Date)-$os.LastBootUpTime)) Gray
Wait-Enter "  Press Enter to begin Step 1"

# ============================================================
#  STEP 1 - EXECUTION HISTORY
# ============================================================
Head "1 of 3" "EXECUTION HISTORY" "What has run on this machine, including programs already deleted."
$s1=$Results.Count
Bar "Parsing artifacts"

# --- BAM ---
$bamN=0; $bamHit=0
foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
                    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')){
    if (-not (Test-Path $root)){ continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if (-not $p){ return }
        $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -match '\.exe$' } | ForEach-Object {
            $bamN++
            $when='?'
            try { $d=$_.Value
                  if ($d -is [byte[]] -and $d.Length -ge 8){
                      $ft=[BitConverter]::ToInt64($d,0)
                      if ($ft -gt 0){ $when=[DateTime]::FromFileTimeUtc($ft).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } } } catch {}
            if (Test-Flagged $_.Name){ $bamHit++
                R $FAIL "BAM: flagged program executed -> $(Split-Path $_.Name -Leaf)  [last run $when]" 'BamParser++' }
        } } }
if     ($bamN -eq 0)  { R $WARN "BAM: no execution records - key missing or cleared." 'BamParser++' }
elseif ($bamN -lt 10) { R $WARN "BAM: only $bamN entries - suspiciously sparse." 'BamParser++' }
elseif ($bamHit -eq 0){ R $PASS "BAM: $bamN entries parsed, none flagged." }

# --- Amcache ---
$am="$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $am){
    $kb=[int]((Get-Item $am -Force).Length/1KB)
    if ($kb -lt 256){ R $WARN "Amcache: only ${kb}KB - unusually small, may be trimmed." 'AmcacheParser++' }
    else           { R $PASS "Amcache: present (${kb}KB). Deep parse needs a hive parser." }
} else { R $WARN "Amcache: hive missing entirely." 'AmcacheParser++' }

# --- Prefetch ---
$pfEnabled = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher } catch { $null }
if ($pfEnabled -eq 0){ R $WARN "Prefetch: DISABLED in registry - traces not recorded." 'WinPrefetchView++' }
$pfDir="$env:SystemRoot\Prefetch"
if (Test-Path $pfDir){
    $pf=@(Get-ChildItem $pfDir -Filter *.pf -Force -ErrorAction SilentlyContinue)
    $pfHit=0
    foreach ($x in $pf){
        $n=($x.BaseName -replace '-[0-9A-F]{8}$','')
        if (Test-Flagged $n){ $pfHit++
            R $FAIL "Prefetch: trace for $n  [last run $($x.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))]" 'WinPrefetchView++' } }
    if     ($pf.Count -eq 0) { R $WARN "Prefetch: folder empty - cleared or disabled." 'WinPrefetchView++' }
    elseif ($pf.Count -lt 20){ R $WARN "Prefetch: only $($pf.Count) files - likely wiped." 'WinPrefetchView++' }
    elseif ($pfHit -eq 0)    { R $PASS "Prefetch: $($pf.Count) traces scanned, none flagged." }
} else { R $WARN "Prefetch: folder does not exist." 'WinPrefetchView++' }

# --- ShimCache raw sweep ---
try {
    $blob=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $txt=[Text.Encoding]::Unicode.GetString($blob); $scHit=0
    foreach ($f in $Flagged){ if ($txt -match [regex]::Escape($f)){ $scHit++; R $FAIL "ShimCache: references $f" 'PathsParser++' } }
    if ($scHit -eq 0){ R $PASS "ShimCache: $([int]($blob.Length/1KB))KB swept, no flagged names." }
} catch { R $WARN "ShimCache: could not read AppCompatCache." 'PathsParser++' }

# --- MUICache ---
$mui='HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
if (Test-Path $mui){
    $mp=Get-ItemProperty $mui -ErrorAction SilentlyContinue; $mHit=0; $mN=0
    if ($mp){ $mp.PSObject.Properties | Where-Object { $_.Name -like '*.exe*' } | ForEach-Object { $mN++
        if (Test-Flagged ($_.Name -replace '\.FriendlyAppName$','')){ $mHit++
            R $FAIL "MUICache: launched -> $(Split-Path ($_.Name -replace '\.FriendlyAppName$','') -Leaf)" 'PathsParser++' } } }
    if ($mHit -eq 0){ R $PASS "MUICache: $mN entries, clean." }
} else { R $WARN "MUICache: key absent." 'PathsParser++' }

# --- SRUM ---
$srum="$env:SystemRoot\System32\sru\SRUDB.dat"
if (Test-Path $srum){
    $mb=[math]::Round((Get-Item $srum -Force).Length/1MB,1)
    if ($mb -lt 1){ R $WARN "SRUM: database only ${mb}MB - likely reset." 'SRUMExplorer++' }
    else          { R $PASS "SRUM: database present (${mb}MB)." }
} else { R $WARN "SRUM: SRUDB.dat missing." 'SRUMExplorer++' }

# --- PowerShell history: presence + emptiness only (no command strings) ---
$hist="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $hist){
    $h=@(Get-Content $hist -ErrorAction SilentlyContinue)
    if ($h.Count -eq 0){ R $WARN "PS history: file exists but is empty - cleared." 'PowerShellParser++' }
    else { R $PASS "PS history: $($h.Count) lines present (review manually if needed)." }
} else { R $WARN "PS history: file missing - deleted or never created." 'PowerShellParser++' }

Flush $s1
Wait-Enter "  Press Enter for Step 2"

# ============================================================
#  STEP 2 - PERSISTENCE, STORAGE & TRACES
# ============================================================
Head "2 of 3" "PERSISTENCE, STORAGE & TRACES" "Startup entries, filesystem journals, devices, and log-clearing evidence."
$s2=$Results.Count
Bar "Reading journals"

# --- USN journal ---
try {
    $usn = & fsutil usn queryjournal C: 2>&1
    if ($LASTEXITCODE -ne 0 -or "$usn" -match 'not.*active|Error'){
        R $FAIL "USN journal: disabled or deleted on C: - strong wipe indicator." 'JournalTrace++'
    } else {
        $m=([regex]'Maximum Size\s*:\s*(0x[0-9a-f]+)').Match("$usn")
        $sz= if ($m.Success){ [Convert]::ToInt64($m.Groups[1].Value,16) } else { 0 }
        if ($sz -gt 0 -and $sz -lt 32MB){ R $WARN "USN journal: active but only $([int]($sz/1MB))MB retained." 'JournalTrace++' }
        else { R $PASS "USN journal: active on C: ($([int]($sz/1MB))MB max)." }
    }
} catch { R $WARN "USN journal: query failed." 'JournalTrace++' }

# --- Event log clearing (effect-based tamper detection) ---
foreach ($pair in @(@('Security',1102),@('System',104))){
    try {
        $ev=Get-WinEvent -FilterHashtable @{LogName=$pair[0];Id=$pair[1]} -MaxEvents 5 -ErrorAction Stop
        foreach ($e in $ev){ R $FAIL "Event log: '$($pair[0])' CLEARED at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" 'CrashedFileViewer++' }
    } catch { R $PASS "Event log: no clear events in '$($pair[0])'." }
}

# --- Autoruns: Run keys ---
$runKeys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
$arHit=0; $arN=0
foreach ($k in $runKeys){
    if (-not (Test-Path $k)){ continue }
    $p=Get-ItemProperty $k -ErrorAction SilentlyContinue
    if (-not $p){ continue }
    $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $arN++
        $v="$($_.Value)"
        if (Test-Flagged $v){ $arHit++; R $FAIL "Autorun: flagged entry '$($_.Name)' -> $v" 'Autoruns++' }
        else {
            $exe = if ($v -match '"([^"]+\.exe)"'){$matches[1]} elseif ($v -match '([A-Za-z]:\\[^ ]+\.exe)'){$matches[1]} else {$null}
            if ($exe -and (Test-Path $exe)){
                $sg=Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
                if ($sg.Status -ne 'Valid'){ $arHit++; R $WARN "Autorun: unsigned startup entry '$($_.Name)' -> $exe" 'Autoruns++' } } } } }
if ($arHit -eq 0){ R $PASS "Autoruns: $arN Run/RunOnce entries, all clean." }

# --- Startup folders ---
$stHit=0
foreach ($d in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                 "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")){
    if (Test-Path $d){ Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        if (Test-Flagged $_.Name){ $stHit++; R $FAIL "Startup folder: flagged item -> $($_.FullName)" 'Autoruns++' } } } }
if ($stHit -eq 0){ R $PASS "Startup folders: clean." }

# --- Scheduled tasks ---
try {
    $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })
    $tHit=0
    foreach ($t in $tasks){ foreach ($a in ($t.Actions|Where-Object{$_.Execute})){
        if (Test-Flagged $a.Execute){ $tHit++; R $FAIL "Task: '$($t.TaskName)' runs flagged -> $($a.Execute)" 'Autoruns++' } } }
    if ($tHit -eq 0){ R $PASS "Scheduled tasks: $($tasks.Count) third-party tasks, none flagged." }
} catch { R $WARN "Scheduled tasks: enumeration failed." 'Autoruns++' }

# --- Alternate Data Streams ---
$adsHit=0; $adsN=0
foreach ($d in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents")){
    if (-not (Test-Path $d)){ continue }
    Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {
        try { $st=Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
              foreach ($s in $st){ $adsHit++; R $WARN "ADS: unusual stream '$($s.Stream)' on $($_.Name)" 'MFTExplorer++' } } catch {}
        $adsN++ } }
if ($adsHit -eq 0){ R $PASS "Alternate Data Streams: $adsN files checked, none hiding data." }

# --- Downloads ---
$dl="$env:USERPROFILE\Downloads"
if (Test-Path $dl){
    $dHit=0; $dN=0
    Get-ChildItem $dl -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $dN++
        if (Test-Flagged $_.Name){ $dHit++
            $src='unknown origin'
            try { $z=Get-Content "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
                  $hu=$z|Where-Object{$_ -like 'HostUrl=*'}|Select-Object -First 1
                  if ($hu){ $src=$hu -replace '^HostUrl=','' } } catch {}
            R $FAIL "Downloads: flagged file '$($_.Name)' [from $src]" 'BrowserDownloadsView++' } }
    if ($dHit -eq 0){ R $PASS "Downloads: $dN files, none flagged." }
} else { R $WARN "Downloads folder missing." 'SavedFilesViewer++' }

# --- USB history ---
$usbK='HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
if (Test-Path $usbK){
    $u=@(Get-ChildItem $usbK -ErrorAction SilentlyContinue)
    if ($u.Count -eq 0){ R $WARN "USB history: USBSTOR empty - device traces removed." 'USBDeview++' }
    else { R $PASS "USB history: $($u.Count) storage devices recorded." }
} else { R $WARN "USB history: USBSTOR key missing." 'USBDeview++' }

# --- Recycle Bin ---
try {
    $rb=@(Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -like '$R*' })
    $rHit=0
    foreach ($x in $rb){ if (Test-Flagged $x.Name){ $rHit++; R $FAIL "Recycle Bin: flagged deleted file -> $($x.Name)" 'MFTExplorer++' } }
    if ($rHit -eq 0){ R $PASS "Recycle Bin: $($rb.Count) items, none flagged." }
} catch { R $WARN "Recycle Bin: could not enumerate." 'MFTExplorer++' }

Flush $s2
Wait-Enter "  Press Enter for Step 3"

# ============================================================
#  STEP 3 - LIVE SYSTEM & DEFENCE INTEGRITY
# ============================================================
Head "3 of 3" "LIVE SYSTEM & DEFENCE INTEGRITY" "What is running now, and whether protections have been weakened."
$s3=$Results.Count
Bar "Inspecting system"

# --- Live processes ---
$pHit=0; $pN=0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $pN++
    $path=$null; try { $path=$_.Path } catch {}
    $nm= if ($path){$path} else {"$($_.ProcessName).exe"}
    if (Test-Flagged $nm){ $pHit++
        R $FAIL "Process: flagged LIVE -> $($_.ProcessName) (PID $($_.Id)) $(if($path){"at $path"}else{'[path hidden]'})" } }
if ($pHit -eq 0){ R $PASS "Processes: $pN running, none flagged." }

# --- Unsigned processes from user/temp dirs ---
$uHit=0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $path=$null; try { $path=$_.Path } catch {}
    if ($path -and ($path -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\')){
        $sg=Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
        if ($sg.Status -ne 'Valid'){ $uHit++; R $WARN "Process: unsigned binary from user space -> $path" 'StringExplorer++' } } }
if ($uHit -eq 0){ R $PASS "Processes: none unsigned from temp/user directories." }

# --- Defender exclusions (cmdlet) ---
try {
    $pref=Get-MpPreference -ErrorAction Stop
    $ex=@(); $ex+=$pref.ExclusionPath; $ex+=$pref.ExclusionProcess; $ex+=$pref.ExclusionExtension; $ex+=$pref.ExclusionIpAddress
    $ex=$ex|Where-Object{$_}
    if ($ex.Count){ foreach($e in $ex){ R $FAIL "Defender: exclusion set -> $e" } }
    else { R $PASS "Defender: no exclusions of any type." }
} catch { R $WARN "Defender: could not read exclusions." }

# --- Defender exclusions (registry cross-check) ---
$exR='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
if (Test-Path $exR){
    $rHit=0
    Get-ChildItem $exR -ErrorAction SilentlyContinue | ForEach-Object {
        $p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p){ $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $rHit++; R $FAIL "Defender: registry exclusion -> $($_.Name)" } } }
    if ($rHit -eq 0){ R $PASS "Defender: registry exclusions empty (matches cmdlet)." }
} else { R $PASS "Defender: no exclusion registry keys." }

# --- Defender status (effect-based) ---
try {
    $st=Get-MpComputerStatus -ErrorAction Stop
    if ($st.RealTimeProtectionEnabled){ R $PASS "Defender: real-time protection ON." } else { R $FAIL "Defender: real-time protection OFF." }
    if ($st.AntivirusEnabled){ R $PASS "Defender: antivirus engine enabled." } else { R $FAIL "Defender: antivirus engine disabled." }
    if ($st.IsTamperProtected){ R $PASS "Defender: tamper protection ON." } else { R $WARN "Defender: tamper protection OFF." }
    $age=[int]$st.AntivirusSignatureAge
    if ($age -le 7){ R $PASS "Defender: signatures $age day(s) old." } else { R $WARN "Defender: signatures $age days old - stale." }
} catch { R $WARN "Defender: status query failed." }

# --- Defender config-change events (effect-based tamper detection) ---
try {
    $de=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=5001,5007} -MaxEvents 10 -ErrorAction Stop
    foreach ($e in $de){ R $WARN "Defender: config/RTP change event $($e.Id) at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }
} catch { R $PASS "Defender: no protection-disable or config-change events logged." }

# --- Boot configuration ---
try {
    $bcd = & bcdedit /enum "{current}" 2>&1 | Out-String
    if ($bcd -match 'testsigning\s+Yes'){ R $FAIL "Boot: test signing enabled - unsigned drivers can load." } else { R $PASS "Boot: test signing off." }
    if ($bcd -match 'nointegritychecks\s+Yes'){ R $FAIL "Boot: integrity checks disabled." } else { R $PASS "Boot: integrity checks on." }
    if ($bcd -match 'debug\s+Yes'){ R $WARN "Boot: kernel debugging enabled." } else { R $PASS "Boot: kernel debugging off." }
} catch { R $WARN "Boot: bcdedit read failed." }

# --- Memory integrity (HVCI) ---
try {
    $hv=Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -ErrorAction Stop
    if ($hv -eq 1){ R $PASS "Memory Integrity (HVCI): ON." } else { R $WARN "Memory Integrity (HVCI): OFF." }
} catch { R $WARN "Memory Integrity: not supported or unreadable." }

# --- Running kernel drivers signatures ---
try {
    $drv=@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' })
    $dHit=0
    foreach ($d in $drv){
        $pp=$d.PathName -replace '^\\\??\\',''
        if ($pp -and (Test-Path $pp -ErrorAction SilentlyContinue)){
            $sg=Get-AuthenticodeSignature $pp -ErrorAction SilentlyContinue
            if ($sg.Status -ne 'Valid'){ $dHit++; R $WARN "Driver: invalid signature -> $($d.Name) ($pp)" } } }
    if ($dHit -eq 0){ R $PASS "Drivers: $($drv.Count) running, all validly signed." }
} catch { R $WARN "Drivers: enumeration failed." }

Flush $s3
Wait-Enter "  Press Enter for the final result"

# ============================================================
#  SCORE
# ============================================================
Clear-Host
Write-Host ""
Line ("  " + ('='*68)) DarkGray
Line "   FINAL RESULT" White
Line ("  " + ('='*68)) DarkGray
Write-Host ""
$tot=$Results.Count
$p=@($Results|Where-Object{$_.State -eq 'Pass'}).Count
$w=@($Results|Where-Object{$_.State -eq 'Unsure'}).Count
$f=@($Results|Where-Object{$_.State -eq 'Fail'}).Count
Line ("   Passed  : {0,3} / {1}" -f $p,$tot) Green
Line ("   Unsure  : {0,3} / {1}" -f $w,$tot) DarkYellow
Line ("   Failed  : {0,3} / {1}" -f $f,$tot) Red
Write-Host ""
if ($f -gt 0){
    Line "   VERDICT: FAIL" Red
    Line "   Flagged artifacts found. Review every red line above." Gray
    Write-Host ""
    foreach ($r in ($Results|Where-Object{$_.State -eq 'Fail'})){ Line "     - $($r.Text)" Red }
} elseif ($w -gt 0){
    Line "   VERDICT: INCONCLUSIVE" DarkYellow
    Line "   Nothing caught, but $w check(s) could not be verified. Missing or" Gray
    Line "   emptied artifacts are themselves suspicious - investigate each." Gray
    Write-Host ""
    foreach ($r in ($Results|Where-Object{$_.State -eq 'Unsure'})){
        Line "     - $($r.Text)" DarkYellow
        if ($r.Tool){ Line "       deeper: $($r.Tool)" DarkGray } }
} else {
    Line "   VERDICT: PASS" Green
    Line "   All $tot checks completed clean with no gaps in history." Gray
}
Write-Host ""
Line ("   Completed {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) DarkGray
Wait-Enter "  Press Enter to exit"
exit
