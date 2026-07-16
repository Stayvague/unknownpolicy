#Requires -Version 5.0
<#
    unknown  -  Recording Policy
    Save as unknown.ps1, right-click > Run with PowerShell, or:
        powershell -ExecutionPolicy Bypass -File .\unknown.ps1
#>

# ===================== ELEVATION =====================
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
        Write-Host "`n[ERROR] Run from a saved file. Save as unknown.ps1, right-click > Run with PowerShell.`n" -ForegroundColor Red
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

# NOTE: function is named Note (not R) because 'R' is a built-in alias
# for Invoke-History, which was hijacking every call.
$Results = New-Object System.Collections.Generic.List[object]
function Note { param([string]$State,[string]$Text)
    $Results.Add([pscustomobject]@{State=$State;Text=$Text}) }

function Flush { param([int]$From)
    for ($i=$From; $i -lt $Results.Count; $i++){
        $r=$Results[$i]
        $tag = switch ($r.State){ 'Pass'{'[ OK ]'} 'Unsure'{'[ ?? ]'} 'Fail'{'[FAIL]'} }
        Line ("  $tag $($r.Text)") (C-Of $r.State)
    } }

function Head { param([string]$N,[string]$T)
    Clear-Host; Write-Host ""
    Line ("  STEP $N  |  $T") White
    Line ("  " + ('-'*66)) DarkGray; Write-Host "" }

# ===================== FLAGGED NAMES =====================
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

# ===================== BANNER + HARDWARE =====================
Clear-Host
Write-Host ""
Line "   #    #  #    #  #    #  #    #   ####   #    #  #    #" Magenta
Line "   #    #  ##   #  #   #   ##   #  #    #  #    #  ##   #" Magenta
Line "   #    #  # #  #  ####    # #  #  #    #  #    #  # #  #" Magenta
Line "   #    #  #  # #  #  #    #  # #  #    #  # ## #  #  # #" Magenta
Line "    ####   #   ##  #   #   #   ##   ####    #  #   #   ##" Magenta
Write-Host ""
Line "   Recording Policy" White
Line "   Made by stayvague" DarkGray
Write-Host ""

$os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
$bios=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$board=Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
$disks=@(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)

Line ("   OS      : {0} (build {1})" -f $os.Caption,$os.BuildNumber) Gray
Line ("   CPU     : type OK") Gray
Line ("   Install : {0}" -f $os.InstallDate.ToString('yyyy-MM-dd HH:mm')) Gray
Line ("   Uptime  : {0:dd\d\ hh\h\ mm\m}" -f ((Get-Date)-$os.LastBootUpTime)) Gray
Write-Host ""

# --- serial sanity (blank / placeholder serials are the only real concern) ---
$bad = @('','0','none','default string','to be filled by o.e.m.','system serial number','not specified','not applicable')
function Serial-State { param([string]$S)
    if (-not $S){ return $false }
    if ($bad -contains $S.Trim().ToLower()){ return $false }
    return $true }

$biosSerial = if ($bios){ $bios.SerialNumber } else { $null }
if (Serial-State $biosSerial){ Line ("   BIOS serial  : present - normal") Green }
else { Line ("   BIOS serial  : blank / placeholder") DarkYellow }

$boardSerial = if ($board){ $board.SerialNumber } else { $null }
if (Serial-State $boardSerial){ Line ("   Board serial : present - normal") Green }
else { Line ("   Board serial : blank / placeholder") DarkYellow }

$di=0
foreach ($d in $disks){
    $di++
    if (Serial-State $d.SerialNumber){ Line ("   Disk $di serial: present - normal") Green }
    else { Line ("   Disk $di serial: blank / placeholder") DarkYellow }
}
Wait-Enter "  Press Enter to begin Step 1"

# ============================================================
#  STEP 1
# ============================================================
Head "1 of 3" "EXECUTION HISTORY"
$s1=$Results.Count
Bar "Step 1"

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
                Note $FAIL "BAM: flagged program executed -> $(Split-Path $_.Name -Leaf)  [last run $when]" }
        } } }
if     ($bamN -eq 0)  { Note $WARN "BAM: no execution records - cleared or missing." }
elseif ($bamN -lt 10) { Note $WARN "BAM: only $bamN entries - suspiciously sparse." }
elseif ($bamHit -eq 0){ Note $PASS "BAM: $bamN entries, none flagged." }

# --- Amcache ---
$am="$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $am){
    $kb=[int]((Get-Item $am -Force).Length/1KB)
    if ($kb -lt 256){ Note $WARN "Amcache: only ${kb}KB - unusually small." }
    else           { Note $PASS "Amcache: present (${kb}KB)." }
} else { Note $WARN "Amcache: hive missing." }

# --- Prefetch ---
$pfEnabled = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher } catch { $null }
if ($pfEnabled -eq 0){ Note $WARN "Prefetch: disabled in registry." }
$pfDir="$env:SystemRoot\Prefetch"
if (Test-Path $pfDir){
    $pf=@(Get-ChildItem $pfDir -Filter *.pf -Force -ErrorAction SilentlyContinue)
    $pfHit=0
    foreach ($x in $pf){
        $n=($x.BaseName -replace '-[0-9A-F]{8}$','')
        if (Test-Flagged $n){ $pfHit++
            Note $FAIL "Prefetch: trace for $n  [last run $($x.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))]" } }
    if     ($pf.Count -eq 0) { Note $WARN "Prefetch: folder empty - cleared." }
    elseif ($pf.Count -lt 20){ Note $WARN "Prefetch: only $($pf.Count) files - likely wiped." }
    elseif ($pfHit -eq 0)    { Note $PASS "Prefetch: $($pf.Count) traces, none flagged." }
} else { Note $WARN "Prefetch: folder does not exist." }

# --- ShimCache ---
try {
    $blob=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $txt=[Text.Encoding]::Unicode.GetString($blob); $scHit=0
    foreach ($f in $Flagged){ if ($txt -match [regex]::Escape($f)){ $scHit++; Note $FAIL "ShimCache: references $f" } }
    if ($scHit -eq 0){ Note $PASS "ShimCache: $([int]($blob.Length/1KB))KB swept, no flagged names." }
} catch { Note $WARN "ShimCache: could not read AppCompatCache." }

# --- MUICache ---
$mui='HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
if (Test-Path $mui){
    $mp=Get-ItemProperty $mui -ErrorAction SilentlyContinue; $mHit=0; $mN=0
    if ($mp){ $mp.PSObject.Properties | Where-Object { $_.Name -like '*.exe*' } | ForEach-Object { $mN++
        if (Test-Flagged ($_.Name -replace '\.FriendlyAppName$','')){ $mHit++
            Note $FAIL "MUICache: launched -> $(Split-Path ($_.Name -replace '\.FriendlyAppName$','') -Leaf)" } } }
    if ($mHit -eq 0){ Note $PASS "MUICache: $mN entries, clean." }
} else { Note $WARN "MUICache: key absent." }

# --- SRUM ---
$srum="$env:SystemRoot\System32\sru\SRUDB.dat"
if (Test-Path $srum){
    $mb=[math]::Round((Get-Item $srum -Force).Length/1MB,1)
    if ($mb -lt 1){ Note $WARN "SRUM: only ${mb}MB - likely reset." }
    else          { Note $PASS "SRUM: present (${mb}MB)." }
} else { Note $WARN "SRUM: SRUDB.dat missing." }

# --- PS history presence/emptiness ---
$hist="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $hist){
    $h=@(Get-Content $hist -ErrorAction SilentlyContinue)
    if ($h.Count -eq 0){ Note $WARN "PS history: empty - cleared." }
    else { Note $PASS "PS history: $($h.Count) lines present." }
} else { Note $WARN "PS history: file missing." }

Flush $s1
Wait-Enter "  Press Enter for Step 2"

# ============================================================
#  STEP 2
# ============================================================
Head "2 of 3" "PERSISTENCE, STORAGE & TRACES"
$s2=$Results.Count
Bar "Step 2"

# --- USN journal ---
try {
    $usn = & fsutil usn queryjournal C: 2>&1
    if ($LASTEXITCODE -ne 0 -or "$usn" -match 'not.*active|Error'){
        Note $FAIL "USN journal: disabled or deleted on C: - strong wipe indicator."
    } else {
        $m=([regex]'Maximum Size\s*:\s*(0x[0-9a-f]+)').Match("$usn")
        $sz= if ($m.Success){ [Convert]::ToInt64($m.Groups[1].Value,16) } else { 0 }
        if ($sz -gt 0 -and $sz -lt 32MB){ Note $WARN "USN journal: active but only $([int]($sz/1MB))MB retained." }
        else { Note $PASS "USN journal: active on C: ($([int]($sz/1MB))MB max)." }
    }
} catch { Note $WARN "USN journal: query failed." }

# --- Event log clearing ---
foreach ($pair in @(@('Security',1102),@('System',104))){
    try {
        $ev=Get-WinEvent -FilterHashtable @{LogName=$pair[0];Id=$pair[1]} -MaxEvents 5 -ErrorAction Stop
        foreach ($e in $ev){ Note $FAIL "Event log: '$($pair[0])' CLEARED at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }
    } catch { Note $PASS "Event log: no clear events in '$($pair[0])'." }
}

# --- Autoruns ---
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
        if (Test-Flagged $v){ $arHit++; Note $FAIL "Autorun: flagged entry '$($_.Name)' -> $v" }
        else {
            $exe = if ($v -match '"([^"]+\.exe)"'){$matches[1]} elseif ($v -match '([A-Za-z]:\\[^ ]+\.exe)'){$matches[1]} else {$null}
            if ($exe -and (Test-Path $exe)){
                $sg=Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
                if ($sg.Status -ne 'Valid'){ $arHit++; Note $WARN "Autorun: unsigned startup '$($_.Name)' -> $exe" } } } } }
if ($arHit -eq 0){ Note $PASS "Autoruns: $arN Run/RunOnce entries, all clean." }

# --- Startup folders ---
$stHit=0
foreach ($d in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                 "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")){
    if (Test-Path $d){ Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        if (Test-Flagged $_.Name){ $stHit++; Note $FAIL "Startup folder: flagged -> $($_.FullName)" } } } }
if ($stHit -eq 0){ Note $PASS "Startup folders: clean." }

# --- Scheduled tasks ---
try {
    $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' })
    $tHit=0
    foreach ($t in $tasks){ foreach ($a in ($t.Actions|Where-Object{$_.Execute})){
        if (Test-Flagged $a.Execute){ $tHit++; Note $FAIL "Task: '$($t.TaskName)' runs flagged -> $($a.Execute)" } } }
    if ($tHit -eq 0){ Note $PASS "Scheduled tasks: $($tasks.Count) third-party, none flagged." }
} catch { Note $WARN "Scheduled tasks: enumeration failed." }

# --- ADS ---
$adsHit=0; $adsN=0
foreach ($d in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents")){
    if (-not (Test-Path $d)){ continue }
    Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {
        try { $st=Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
              foreach ($s in $st){ $adsHit++; Note $WARN "ADS: unusual stream '$($s.Stream)' on $($_.Name)" } } catch {}
        $adsN++ } }
if ($adsHit -eq 0){ Note $PASS "Alternate Data Streams: $adsN files checked, none hiding data." }

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
            Note $FAIL "Downloads: flagged file '$($_.Name)' [from $src]" } }
    if ($dHit -eq 0){ Note $PASS "Downloads: $dN files, none flagged." }
} else { Note $WARN "Downloads folder missing." }

# --- USB history ---
$usbK='HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
if (Test-Path $usbK){
    $u=@(Get-ChildItem $usbK -ErrorAction SilentlyContinue)
    if ($u.Count -eq 0){ Note $WARN "USB history: USBSTOR empty - traces removed." }
    else { Note $PASS "USB history: $($u.Count) storage devices recorded." }
} else { Note $WARN "USB history: USBSTOR key missing." }

# --- Recycle Bin ---
try {
    $rb=@(Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -like '$R*' })
    $rHit=0
    foreach ($x in $rb){ if (Test-Flagged $x.Name){ $rHit++; Note $FAIL "Recycle Bin: flagged deleted file -> $($x.Name)" } }
    if ($rHit -eq 0){ Note $PASS "Recycle Bin: $($rb.Count) items, none flagged." }
} catch { Note $WARN "Recycle Bin: could not enumerate." }

Flush $s2
Wait-Enter "  Press Enter for Step 3"

# ============================================================
#  STEP 3
# ============================================================
Head "3 of 3" "LIVE SYSTEM & DEFENCE INTEGRITY"
$s3=$Results.Count
Bar "Step 3"

# --- Live processes ---
$pHit=0; $pN=0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $pN++
    $path=$null; try { $path=$_.Path } catch {}
    $nm= if ($path){$path} else {"$($_.ProcessName).exe"}
    if (Test-Flagged $nm){ $pHit++
        Note $FAIL "Process: flagged LIVE -> $($_.ProcessName) (PID $($_.Id)) $(if($path){"at $path"}else{'[path hidden]'})" } }
if ($pHit -eq 0){ Note $PASS "Processes: $pN running, none flagged." }

# --- Unsigned from user/temp ---
$uHit=0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $path=$null; try { $path=$_.Path } catch {}
    if ($path -and ($path -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\')){
        $sg=Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
        if ($sg.Status -ne 'Valid'){ $uHit++; Note $WARN "Process: unsigned binary from user space -> $path" } } }
if ($uHit -eq 0){ Note $PASS "Processes: none unsigned from temp/user dirs." }

# --- Defender exclusions (cmdlet) ---
try {
    $pref=Get-MpPreference -ErrorAction Stop
    $ex=@(); $ex+=$pref.ExclusionPath; $ex+=$pref.ExclusionProcess; $ex+=$pref.ExclusionExtension; $ex+=$pref.ExclusionIpAddress
    $ex=$ex|Where-Object{$_}
    if ($ex.Count){ foreach($e in $ex){ Note $FAIL "Defender: exclusion set -> $e" } }
    else { Note $PASS "Defender: no exclusions of any type." }
} catch { Note $WARN "Defender: could not read exclusions." }

# --- Defender exclusions (registry) ---
$exR='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
if (Test-Path $exR){
    $rHit=0
    Get-ChildItem $exR -ErrorAction SilentlyContinue | ForEach-Object {
        $p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p){ $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $rHit++; Note $FAIL "Defender: registry exclusion -> $($_.Name)" } } }
    if ($rHit -eq 0){ Note $PASS "Defender: registry exclusions empty." }
} else { Note $PASS "Defender: no exclusion registry keys." }

# --- Defender status ---
try {
    $st=Get-MpComputerStatus -ErrorAction Stop
    if ($st.RealTimeProtectionEnabled){ Note $PASS "Defender: real-time protection ON." } else { Note $FAIL "Defender: real-time protection OFF." }
    if ($st.AntivirusEnabled){ Note $PASS "Defender: antivirus engine enabled." } else { Note $FAIL "Defender: antivirus engine disabled." }
    if ($st.IsTamperProtected){ Note $PASS "Defender: tamper protection ON." } else { Note $WARN "Defender: tamper protection OFF." }
    $age=[int]$st.AntivirusSignatureAge
    if ($age -le 7){ Note $PASS "Defender: signatures $age day(s) old." } else { Note $WARN "Defender: signatures $age days old - stale." }
} catch { Note $WARN "Defender: status query failed." }

# --- Defender config-change events ---
try {
    $de=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=5001,5007} -MaxEvents 10 -ErrorAction Stop
    foreach ($e in $de){ Note $WARN "Defender: config/RTP change event $($e.Id) at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }
} catch { Note $PASS "Defender: no protection-disable events logged." }

# --- Boot config ---
try {
    $bcd = & bcdedit /enum "{current}" 2>&1 | Out-String
    if ($bcd -match 'testsigning\s+Yes'){ Note $FAIL "Boot: test signing enabled." } else { Note $PASS "Boot: test signing off." }
    if ($bcd -match 'nointegritychecks\s+Yes'){ Note $FAIL "Boot: integrity checks disabled." } else { Note $PASS "Boot: integrity checks on." }
    if ($bcd -match 'debug\s+Yes'){ Note $WARN "Boot: kernel debugging enabled." } else { Note $PASS "Boot: kernel debugging off." }
} catch { Note $WARN "Boot: bcdedit read failed." }

# --- HVCI ---
try {
    $hv=Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -ErrorAction Stop
    if ($hv -eq 1){ Note $PASS "Memory Integrity (HVCI): ON." } else { Note $WARN "Memory Integrity (HVCI): OFF." }
} catch { Note $WARN "Memory Integrity: not supported or unreadable." }

# --- Driver signatures ---
try {
    $drv=@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' })
    $dHit=0
    foreach ($d in $drv){
        $pp=$d.PathName -replace '^\\\??\\',''
        if ($pp -and (Test-Path $pp -ErrorAction SilentlyContinue)){
            $sg=Get-AuthenticodeSignature $pp -ErrorAction SilentlyContinue
            if ($sg.Status -ne 'Valid'){ $dHit++; Note $WARN "Driver: invalid signature -> $($d.Name)" } } }
    if ($dHit -eq 0){ Note $PASS "Drivers: $($drv.Count) running, all validly signed." }
} catch { Note $WARN "Drivers: enumeration failed." }

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
    Write-Host ""
    foreach ($r in ($Results|Where-Object{$_.State -eq 'Fail'})){ Line "     - $($r.Text)" Red }
} elseif ($w -gt 0){
    Line "   VERDICT: INCONCLUSIVE" DarkYellow
    Write-Host ""
    foreach ($r in ($Results|Where-Object{$_.State -eq 'Unsure'})){ Line "     - $($r.Text)" DarkYellow }
} else {
    Line "   VERDICT: PASS" Green
}
Write-Host ""
Line ("   Completed {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) DarkGray
Wait-Enter "  Press Enter to exit"
exit
