#Requires -Version 5.1
<#
.SYNOPSIS
    Remote Access Detection & Removal Tool
.DESCRIPTION
    Scans for remote access software commonly used in tech support scams.
    Detects installations, registry entries, startup items, and open ports.
    Offers interactive step-by-step removal with full logging.
.NOTES
    Author: IT-Tools Project
    Version: 1.1
    Portable - No installation required
#>

# ============================================================================
# UPDATE CONFIGURATION
# ============================================================================

# GitHub URL for signature updates
$Script:UpdateUrl = "https://raw.githubusercontent.com/domin0z/RemoteAccessScanner/main/signatures.json"

# Local signature file path (same folder as script)
$Script:SignatureFile = Join-Path $PSScriptRoot "signatures.json"
$Script:CurrentVersion = "1.0.0"
$Script:SignaturesLoaded = $false

# ============================================================================
# SIGNATURE LOADING FUNCTIONS
# ============================================================================

function Load-Signatures {
    <#
    .SYNOPSIS
        Loads RAT signatures from the local JSON file
    #>

    $signaturePath = $Script:SignatureFile
    if (-not $signaturePath) {
        $signaturePath = Join-Path (Get-Location) "signatures.json"
    }

    if (Test-Path $signaturePath) {
        try {
            $json = Get-Content $signaturePath -Raw | ConvertFrom-Json

            # Update version info
            $Script:CurrentVersion = $json.version
            $Script:SignaturesLastUpdated = $json.lastUpdated
            $Script:SignaturesLastUpdatedTime = $json.lastUpdatedTime
            $Script:SignaturesChangeLog = $json.changeLog

            # Convert JSON signatures to the format our scanner expects
            $Script:KnownRATs = @()
            foreach ($sig in $json.signatures) {
                $Script:KnownRATs += @{
                    Name = $sig.name
                    Risk = $sig.risk
                    Category = $sig.category
                    Reason = $sig.reason
                    IsLegitimate = $sig.isLegitimate
                    Processes = $sig.processes
                    Services = $sig.services
                    Ports = $sig.ports
                    InstallPaths = $sig.installPaths
                    RegistryKeys = $sig.registryKeys
                    AutoStartMethods = $sig.autoStartMethods
                    FileSignatures = $sig.fileSignatures
                    Notes = $sig.notes
                }
            }

            $Script:SignaturesLoaded = $true
            return $true
        } catch {
            Write-Host "  Error loading signatures: $_" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "  Signatures file not found: $signaturePath" -ForegroundColor Yellow
        Write-Host "  Using built-in signatures (may be outdated)" -ForegroundColor Yellow
        return $false
    }
}

function Update-Signatures {
    <#
    .SYNOPSIS
        Downloads the latest signatures from GitHub
    #>

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SIGNATURE UPDATE" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    # Show current version
    Write-Host "  Current signature version: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:CurrentVersion -ForegroundColor White
    if ($Script:SignaturesLastUpdated) {
        Write-Host "  Last updated: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:SignaturesLastUpdated -ForegroundColor White
    }
    Write-Host ""

    Write-Host "  Checking for updates..." -ForegroundColor Yellow

    try {
        # Download the latest signatures
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "RemoteAccessScanner/1.0")

        $latestJson = $webClient.DownloadString($Script:UpdateUrl)
        $latest = $latestJson | ConvertFrom-Json

        $latestVersion = $latest.version
        $latestDate = $latest.lastUpdated
        $signatureCount = $latest.signatures.Count

        Write-Host ""
        Write-Host "  Latest version available: " -NoNewline -ForegroundColor Gray
        Write-Host $latestVersion -ForegroundColor Green
        Write-Host "  Release date: " -NoNewline -ForegroundColor Gray
        Write-Host $latestDate -ForegroundColor White
        Write-Host "  Signatures in update: " -NoNewline -ForegroundColor Gray
        Write-Host $signatureCount -ForegroundColor White
        Write-Host ""

        # Compare versions
        if ($latestVersion -eq $Script:CurrentVersion) {
            Write-Host "  You already have the latest signatures!" -ForegroundColor Green
            return
        }

        # Show what's new (compare signature counts)
        $currentCount = $Script:KnownRATs.Count
        $newSigs = $signatureCount - $currentCount
        if ($newSigs -gt 0) {
            Write-Host "  New signatures available: $newSigs" -ForegroundColor Yellow
        }

        # Ask to update
        Write-Host ""
        $confirm = Read-Host "  Download and install update? (Y/N)"

        if ($confirm -match "^[Yy]") {
            Write-Host ""
            Write-Host "  Downloading signatures..." -ForegroundColor Yellow

            # Backup current signatures
            $backupPath = "$($Script:SignatureFile).backup"
            if (Test-Path $Script:SignatureFile) {
                Copy-Item $Script:SignatureFile $backupPath -Force
                Write-Host "  Backed up current signatures to: $backupPath" -ForegroundColor Gray
            }

            # Save new signatures
            Set-Content -Path $Script:SignatureFile -Value $latestJson -Encoding UTF8
            Write-Host "  Signatures updated successfully!" -ForegroundColor Green

            # Reload signatures
            Write-Host "  Reloading signatures..." -ForegroundColor Yellow
            Load-Signatures | Out-Null

            Write-Host ""
            Write-Host "  Update complete!" -ForegroundColor Green
            Write-Host "  New version: $latestVersion" -ForegroundColor White
            Write-Host "  Total signatures: $($Script:KnownRATs.Count)" -ForegroundColor White

            # Show new entries if possible
            Write-Host ""
            Write-Host "  New/Updated tools in this release:" -ForegroundColor Cyan
            foreach ($sig in $latest.signatures | Select-Object -Last 5) {
                Write-Host "    - $($sig.name) [$($sig.risk)]" -ForegroundColor White
            }
            Write-Host "    (Showing last 5 entries)" -ForegroundColor Gray
        } else {
            Write-Host "  Update cancelled." -ForegroundColor Yellow
        }

    } catch {
        Write-Host ""
        Write-Host "  Error checking for updates: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Possible causes:" -ForegroundColor Yellow
        Write-Host "    - No internet connection" -ForegroundColor Gray
        Write-Host "    - GitHub URL not configured" -ForegroundColor Gray
        Write-Host "    - Firewall blocking connection" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Current Update URL:" -ForegroundColor Gray
        Write-Host "  $($Script:UpdateUrl)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  To configure, edit the `$Script:UpdateUrl variable at the top of the script." -ForegroundColor Gray
    }
}

function Show-SignatureInfo {
    <#
    .SYNOPSIS
        Shows information about loaded signatures
    #>

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SIGNATURE DATABASE INFO" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Version: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:CurrentVersion -ForegroundColor White

    # Show full timestamp if available, otherwise just the date
    if ($Script:SignaturesLastUpdatedTime) {
        Write-Host "  Last Updated: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:SignaturesLastUpdatedTime -ForegroundColor White
    } elseif ($Script:SignaturesLastUpdated) {
        Write-Host "  Last Updated: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:SignaturesLastUpdated -ForegroundColor White
    }

    Write-Host "  Total Signatures: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:KnownRATs.Count -ForegroundColor White

    Write-Host "  Signature File: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:SignatureFile -ForegroundColor Cyan

    Write-Host ""
    Write-Host "  Signatures by Category:" -ForegroundColor Yellow

    $categories = $Script:KnownRATs | Group-Object -Property Category
    foreach ($cat in $categories) {
        Write-Host "    $($cat.Name): $($cat.Count)" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  Signatures by Risk Level:" -ForegroundColor Yellow

    $risks = $Script:KnownRATs | Group-Object -Property Risk
    foreach ($risk in $risks) {
        $color = switch ($risk.Name) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
            default { "Gray" }
        }
        Write-Host "    $($risk.Name): $($risk.Count)" -ForegroundColor $color
    }

    # Show recent changes if available
    if ($Script:SignaturesChangeLog -and $Script:SignaturesChangeLog.Count -gt 0) {
        Write-Host ""
        Write-Host "  Recent Changes:" -ForegroundColor Yellow

        # Show last 5 changes
        $recentChanges = $Script:SignaturesChangeLog | Select-Object -First 5
        foreach ($change in $recentChanges) {
            Write-Host "    v$($change.version) ($($change.date)):" -ForegroundColor Cyan
            foreach ($item in $change.changes) {
                Write-Host "      - $item" -ForegroundColor White
            }
        }

        if ($Script:SignaturesChangeLog.Count -gt 5) {
            Write-Host "    ... and $($Script:SignaturesChangeLog.Count - 5) more" -ForegroundColor Gray
        }
    }
}

function Add-NewSignature {
    <#
    .SYNOPSIS
        Allows user to manually add a new signature when they discover a new tool
    #>

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     ADD NEW SIGNATURE" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Use this to add a new remote access tool you discovered." -ForegroundColor Gray
    Write-Host "  Fill in as much info as you can - you can leave some blank." -ForegroundColor Gray
    Write-Host ""

    # Gather information
    Write-Host "  --- BASIC INFO ---" -ForegroundColor Yellow
    $name = Read-Host "  Tool Name (e.g., 'AnyDesk')"
    if ([string]::IsNullOrWhiteSpace($name)) {
        Write-Host "  Name is required. Cancelled." -ForegroundColor Red
        return
    }

    # Check if already exists
    $existing = $Script:KnownRATs | Where-Object { $_.Name -eq $name }
    if ($existing) {
        Write-Host "  '$name' already exists in signatures!" -ForegroundColor Yellow
        $confirm = Read-Host "  Update existing entry? (Y/N)"
        if ($confirm -notmatch "^[Yy]") {
            return
        }
    }

    Write-Host ""
    Write-Host "  Risk Level:" -ForegroundColor Gray
    Write-Host "    [1] Critical - Known malware/RAT" -ForegroundColor Red
    Write-Host "    [2] High - Commonly used in scams" -ForegroundColor Red
    Write-Host "    [3] Medium - Legitimate but often abused" -ForegroundColor Yellow
    Write-Host "    [4] Low - Usually legitimate" -ForegroundColor Green
    $riskChoice = Read-Host "  Select (1-4)"
    $risk = switch ($riskChoice) {
        "1" { "Critical" }
        "2" { "High" }
        "3" { "Medium" }
        "4" { "Low" }
        default { "Medium" }
    }

    Write-Host ""
    Write-Host "  Category:" -ForegroundColor Gray
    Write-Host "    [1] Remote Desktop (AnyDesk, TeamViewer type)" -ForegroundColor White
    Write-Host "    [2] VNC (UltraVNC, TightVNC type)" -ForegroundColor White
    Write-Host "    [3] RMM (Atera, ConnectWise type)" -ForegroundColor White
    Write-Host "    [4] Malware (RATs, trojans)" -ForegroundColor White
    $catChoice = Read-Host "  Select (1-4)"
    $category = switch ($catChoice) {
        "1" { "Remote Desktop" }
        "2" { "VNC" }
        "3" { "RMM" }
        "4" { "Malware" }
        default { "Remote Desktop" }
    }

    $reason = Read-Host "  Why is this suspicious? (e.g., 'Common in tech support scams')"
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "Remote access tool" }

    Write-Host ""
    Write-Host "  --- DETECTION INFO ---" -ForegroundColor Yellow
    Write-Host "  (Separate multiple values with commas)" -ForegroundColor Gray
    Write-Host ""

    $processesInput = Read-Host "  Process names (e.g., 'AnyDesk,AnyDeskService')"
    $processes = if ($processesInput) {
        @($processesInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else { @() }

    $servicesInput = Read-Host "  Windows service names (e.g., 'AnyDesk')"
    $services = if ($servicesInput) {
        @($servicesInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else { @() }

    $portsInput = Read-Host "  Network ports (e.g., '7070,6568')"
    $ports = if ($portsInput) {
        @($portsInput -split ',' | ForEach-Object {
            $p = $_.Trim()
            if ($p -match '^\d+$') { [int]$p }
        } | Where-Object { $_ })
    } else { @() }

    Write-Host ""
    Write-Host "  --- INSTALL LOCATIONS ---" -ForegroundColor Yellow
    Write-Host "  Use %APPDATA%, %PROGRAMFILES%, etc. for paths" -ForegroundColor Gray
    Write-Host "  (Separate multiple paths with commas)" -ForegroundColor Gray
    Write-Host ""

    $pathsInput = Read-Host "  Install paths (e.g., '%APPDATA%\AnyDesk,%PROGRAMFILES%\AnyDesk')"
    $installPaths = if ($pathsInput) {
        @($pathsInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else { @() }

    $regKeysInput = Read-Host "  Registry keys (e.g., 'HKCU\Software\AnyDesk')"
    $registryKeys = if ($regKeysInput) {
        @($regKeysInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else { @() }

    $notes = Read-Host "  Additional notes (optional)"

    # Create the signature object
    $newSig = [ordered]@{
        name = $name
        risk = $risk
        category = $category
        reason = $reason
        isLegitimate = ($risk -ne "Critical")
        processes = $processes
        services = $services
        ports = $ports
        installPaths = $installPaths
        registryKeys = $registryKeys
        autoStartMethods = @()
        fileSignatures = @()
        notes = $notes
    }

    # Show preview
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SIGNATURE PREVIEW" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Name:       $name" -ForegroundColor White
    Write-Host "  Risk:       $risk" -ForegroundColor $(if ($risk -eq "Critical" -or $risk -eq "High") { "Red" } elseif ($risk -eq "Medium") { "Yellow" } else { "Green" })
    Write-Host "  Category:   $category" -ForegroundColor White
    Write-Host "  Reason:     $reason" -ForegroundColor Gray
    Write-Host "  Processes:  $($processes -join ', ')" -ForegroundColor Cyan
    Write-Host "  Services:   $($services -join ', ')" -ForegroundColor Cyan
    Write-Host "  Ports:      $($ports -join ', ')" -ForegroundColor Cyan
    Write-Host "  Paths:      $($installPaths -join ', ')" -ForegroundColor Cyan
    Write-Host "  Registry:   $($registryKeys -join ', ')" -ForegroundColor Cyan
    Write-Host "  Notes:      $notes" -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "  Save this signature? (Y/N)"
    if ($confirm -notmatch "^[Yy]") {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    # Load current signatures.json
    $sigPath = $Script:SignatureFile
    if (-not (Test-Path $sigPath)) {
        Write-Host "  Signatures file not found: $sigPath" -ForegroundColor Red
        return
    }

    try {
        $json = Get-Content $sigPath -Raw | ConvertFrom-Json

        # Remove existing entry if updating
        if ($existing) {
            $json.signatures = @($json.signatures | Where-Object { $_.name -ne $name })
        }

        # Determine if adding or updating
        $changeType = if ($existing) { "Updated" } else { "Added" }

        # Add new signature
        $json.signatures += [PSCustomObject]$newSig

        # Bump version (patch increment)
        if ($json.version -match '^(\d+)\.(\d+)\.(\d+)$') {
            $major = $Matches[1]
            $minor = $Matches[2]
            $patch = [int]$Matches[3] + 1
            $json.version = "$major.$minor.$patch"
        }

        # Update date and time
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $json.lastUpdated = Get-Date -Format "yyyy-MM-dd"
        $json.lastUpdatedTime = $timestamp

        # Add to change log
        if (-not $json.changeLog) {
            $json | Add-Member -NotePropertyName "changeLog" -NotePropertyValue @() -Force
        }

        $changeEntry = [PSCustomObject]@{
            version = $json.version
            date = $timestamp
            changes = @("$changeType signature: $name [$risk]")
        }

        # Prepend new change to beginning of array
        $json.changeLog = @($changeEntry) + @($json.changeLog)

        # Save
        $json | ConvertTo-Json -Depth 10 | Set-Content $sigPath -Encoding UTF8

        Write-Host ""
        Write-Host "  Signature saved successfully!" -ForegroundColor Green
        Write-Host "  New version: $($json.version)" -ForegroundColor White
        Write-Host "  Change: $changeType $name" -ForegroundColor Cyan
        Write-Host "  Total signatures: $($json.signatures.Count)" -ForegroundColor White
        Write-Host ""
        Write-Host "  NOTE: Upload signatures.json to GitHub to share this update." -ForegroundColor Yellow
        Write-Host "  Repo: https://github.com/domin0z/RemoteAccessScanner" -ForegroundColor Cyan

        # Reload signatures
        Load-Signatures | Out-Null

    } catch {
        Write-Host "  Error saving signature: $_" -ForegroundColor Red
    }
}

function Compare-ScanLogs {
    <#
    .SYNOPSIS
        Compares two scan logs to show what changed (for verifying cleanups)
    #>

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     LOG COMPARISON TOOL" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Compare two scan logs to verify cleanup success or" -ForegroundColor Gray
    Write-Host "  see what changed between scans on the same machine." -ForegroundColor Gray
    Write-Host ""

    # Get script directory for log files
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Get-Location }

    # Find all log files
    $logFiles = Get-ChildItem -Path $scriptDir -Filter "RAT-Scan-Log_*.txt" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending

    if ($logFiles.Count -lt 2) {
        Write-Host "  Not enough log files found for comparison." -ForegroundColor Yellow
        Write-Host "  Need at least 2 log files in: $scriptDir" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Run scans on a machine before and after cleanup," -ForegroundColor Gray
        Write-Host "  then use this tool to compare the results." -ForegroundColor Gray
        return
    }

    # Group logs by computer name
    $logsByPC = @{}
    foreach ($log in $logFiles) {
        # Extract PC name from filename: RAT-Scan-Log_PCNAME_date.txt
        if ($log.Name -match "RAT-Scan-Log_([^_]+)_") {
            $pcName = $Matches[1]
            if (-not $logsByPC.ContainsKey($pcName)) {
                $logsByPC[$pcName] = @()
            }
            $logsByPC[$pcName] += $log
        }
    }

    # Show available PCs
    Write-Host "  Available computers with logs:" -ForegroundColor Yellow
    Write-Host ""
    $pcList = @($logsByPC.Keys)
    for ($i = 0; $i -lt $pcList.Count; $i++) {
        $pc = $pcList[$i]
        $count = $logsByPC[$pc].Count
        Write-Host "    [$($i + 1)] $pc ($count log files)" -ForegroundColor Cyan
    }
    Write-Host ""

    $pcChoice = Read-Host "  Select computer (1-$($pcList.Count))"
    $pcIndex = [int]$pcChoice - 1

    if ($pcIndex -lt 0 -or $pcIndex -ge $pcList.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Red
        return
    }

    $selectedPC = $pcList[$pcIndex]
    $pcLogs = $logsByPC[$selectedPC] | Sort-Object LastWriteTime

    if ($pcLogs.Count -lt 2) {
        Write-Host "  Need at least 2 logs for $selectedPC to compare." -ForegroundColor Yellow
        return
    }

    # Show available logs for this PC
    Write-Host ""
    Write-Host "  Log files for $selectedPC`:" -ForegroundColor Yellow
    Write-Host ""
    for ($i = 0; $i -lt $pcLogs.Count; $i++) {
        $log = $pcLogs[$i]
        $dateStr = $log.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        Write-Host "    [$($i + 1)] $dateStr - $($log.Name)" -ForegroundColor White
    }

    Write-Host ""
    $oldChoice = Read-Host "  Select OLDER log (before cleanup)"
    $newChoice = Read-Host "  Select NEWER log (after cleanup)"

    $oldIndex = [int]$oldChoice - 1
    $newIndex = [int]$newChoice - 1

    if ($oldIndex -lt 0 -or $oldIndex -ge $pcLogs.Count -or
        $newIndex -lt 0 -or $newIndex -ge $pcLogs.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Red
        return
    }

    $oldLog = $pcLogs[$oldIndex]
    $newLog = $pcLogs[$newIndex]

    Write-Host ""
    Write-Host "  Comparing logs..." -ForegroundColor Yellow
    Write-Host "    OLD: $($oldLog.Name)" -ForegroundColor Gray
    Write-Host "    NEW: $($newLog.Name)" -ForegroundColor Gray

    # Parse findings from each log
    $oldFindings = Parse-LogFindings -LogPath $oldLog.FullName
    $newFindings = Parse-LogFindings -LogPath $newLog.FullName

    # Compare findings
    $removed = @()
    $added = @()
    $unchanged = @()

    foreach ($finding in $oldFindings) {
        $key = "$($finding.Name)|$($finding.Path)"
        $stillExists = $newFindings | Where-Object { "$($_.Name)|$($_.Path)" -eq $key }
        if ($stillExists) {
            $unchanged += $finding
        } else {
            $removed += $finding
        }
    }

    foreach ($finding in $newFindings) {
        $key = "$($finding.Name)|$($finding.Path)"
        $existedBefore = $oldFindings | Where-Object { "$($_.Name)|$($_.Path)" -eq $key }
        if (-not $existedBefore) {
            $added += $finding
        }
    }

    # Display results
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     COMPARISON RESULTS: $selectedPC" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Old scan: $($oldFindings.Count) finding(s)" -ForegroundColor Gray
    Write-Host "  New scan: $($newFindings.Count) finding(s)" -ForegroundColor Gray
    Write-Host ""

    # Summary
    if ($removed.Count -gt 0) {
        Write-Host "  REMOVED (cleanup successful): $($removed.Count) item(s)" -ForegroundColor Green
    }
    if ($added.Count -gt 0) {
        Write-Host "  NEW ITEMS FOUND: $($added.Count) item(s)" -ForegroundColor Red
    }
    if ($unchanged.Count -gt 0) {
        Write-Host "  UNCHANGED (still present): $($unchanged.Count) item(s)" -ForegroundColor Yellow
    }

    # Details - Removed items
    if ($removed.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- SUCCESSFULLY REMOVED ---" -ForegroundColor Green
        $removedGrouped = $removed | Group-Object -Property Name
        foreach ($group in $removedGrouped) {
            Write-Host "    $($group.Name):" -ForegroundColor White
            foreach ($item in $group.Group) {
                Write-Host "      - $($item.Type): $($item.Path)" -ForegroundColor Gray
            }
        }
    }

    # Details - New items (concerning!)
    if ($added.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- NEW ITEMS (investigate these!) ---" -ForegroundColor Red
        $addedGrouped = $added | Group-Object -Property Name
        foreach ($group in $addedGrouped) {
            Write-Host "    $($group.Name):" -ForegroundColor White
            foreach ($item in $group.Group) {
                Write-Host "      - $($item.Type): $($item.Path)" -ForegroundColor Yellow
            }
        }
    }

    # Details - Unchanged (may need more cleanup)
    if ($unchanged.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- STILL PRESENT (may need attention) ---" -ForegroundColor Yellow
        $unchangedGrouped = $unchanged | Group-Object -Property Name
        foreach ($group in $unchangedGrouped) {
            Write-Host "    $($group.Name):" -ForegroundColor White
            foreach ($item in $group.Group) {
                Write-Host "      - $($item.Type): $($item.Path)" -ForegroundColor Gray
            }
        }
    }

    # Final verdict
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    if ($removed.Count -gt 0 -and $unchanged.Count -eq 0 -and $added.Count -eq 0) {
        Write-Host "  VERDICT: CLEANUP SUCCESSFUL!" -ForegroundColor Green
        Write-Host "  All previously detected items have been removed." -ForegroundColor Green
    } elseif ($unchanged.Count -gt 0) {
        Write-Host "  VERDICT: CLEANUP INCOMPLETE" -ForegroundColor Yellow
        Write-Host "  Some items are still present - may need manual removal." -ForegroundColor Yellow
    } elseif ($added.Count -gt 0) {
        Write-Host "  VERDICT: NEW THREATS DETECTED" -ForegroundColor Red
        Write-Host "  New remote access tools found since last scan!" -ForegroundColor Red
    } else {
        Write-Host "  VERDICT: NO CHANGE" -ForegroundColor Gray
        Write-Host "  Both scans show the same results." -ForegroundColor Gray
    }
    Write-Host "  ======================================================" -ForegroundColor Cyan
}

function Parse-LogFindings {
    param([string]$LogPath)

    $findings = @()

    try {
        $content = Get-Content $LogPath -ErrorAction Stop

        foreach ($line in $content) {
            # Match lines like: [timestamp] FOUND: Name | Risk: X | Type: Y | Path: Z
            if ($line -match "FOUND:\s*([^|]+)\s*\|\s*Risk:\s*([^|]+)\s*\|\s*Type:\s*([^|]+)\s*\|\s*Path:\s*(.+)$") {
                $findings += [PSCustomObject]@{
                    Name = $Matches[1].Trim()
                    Risk = $Matches[2].Trim()
                    Type = $Matches[3].Trim()
                    Path = $Matches[4].Trim()
                }
            }
        }
    } catch {
        Write-Host "  Error reading log: $_" -ForegroundColor Red
    }

    return $findings
}

# ============================================================================
# CONFIGURATION - Known Remote Access Software Signatures (FALLBACK)
# ============================================================================

$Script:KnownRATs = @(
    # Common Tech Support Scam Tools
    @{ Name = "AnyDesk"; Processes = @("AnyDesk"); Ports = @(7070, 6568); Risk = "High"; Reason = "Frequently used in tech support scams" }
    @{ Name = "TeamViewer"; Processes = @("TeamViewer"); Ports = @(5938, 5939, 5353); Risk = "Medium"; Reason = "Legitimate tool often exploited by scammers" }
    @{ Name = "ScreenConnect"; Processes = @("ScreenConnect.ClientService", "ScreenConnect.WindowsClient"); Ports = @(8040, 8041); Risk = "High"; Reason = "ConnectWise Control - common scam tool" }
    @{ Name = "ConnectWise"; Processes = @("ConnectWiseControl"); Ports = @(8040, 8041); Risk = "High"; Reason = "Same as ScreenConnect - rebranded" }
    @{ Name = "GoToAssist"; Processes = @("g2ax_user", "g2ax_service"); Ports = @(8200); Risk = "High"; Reason = "Very common in tech support scams" }
    @{ Name = "GoToMyPC"; Processes = @("g2comm", "g2tray"); Ports = @(8200); Risk = "Medium"; Reason = "LogMeIn product used in scams" }
    @{ Name = "LogMeIn"; Processes = @("LogMeIn", "LMIGuardianSvc"); Ports = @(443); Risk = "Medium"; Reason = "Legitimate but abused by scammers" }
    @{ Name = "Supremo"; Processes = @("Supremo", "SupremoService"); Ports = @(443); Risk = "High"; Reason = "Italian remote tool popular with scammers" }
    @{ Name = "RemotePC"; Processes = @("RemotePC", "RPCService"); Ports = @(443); Risk = "Medium"; Reason = "Remote access tool" }
    @{ Name = "Splashtop"; Processes = @("SRManager", "SRService", "SplashtopStreamer", "Splashtop", "SRStreamer", "splusvc", "SplashtopSOS", "SRFeature", "SplashtopBusiness", "SRUpdateService", "strwinclt"); Ports = @(443, 6783, 6784); Risk = "Medium"; Reason = "Remote access tool" }
    @{ Name = "UltraVNC"; Processes = @("winvnc", "vncviewer"); Ports = @(5900, 5800); Risk = "Medium"; Reason = "VNC server - allows remote desktop" }
    @{ Name = "TightVNC"; Processes = @("tvnserver"); Ports = @(5900, 5800); Risk = "Medium"; Reason = "VNC server - allows remote desktop" }
    @{ Name = "RealVNC"; Processes = @("vncserver", "vncviewer"); Ports = @(5900, 5800); Risk = "Medium"; Reason = "VNC server - allows remote desktop" }
    @{ Name = "Ammyy Admin"; Processes = @("AA_v3"); Ports = @(443); Risk = "High"; Reason = "Known scammer favorite" }
    @{ Name = "AeroAdmin"; Processes = @("AeroAdmin"); Ports = @(443); Risk = "High"; Reason = "Free remote tool used in scams" }
    @{ Name = "Zoho Assist"; Processes = @("ZohoMeeting", "ZAAgent"); Ports = @(443); Risk = "Medium"; Reason = "Remote support tool" }
    @{ Name = "ISL Online"; Processes = @("ISLLight"); Ports = @(443, 7615); Risk = "Medium"; Reason = "Remote support tool" }
    @{ Name = "RustDesk"; Processes = @("rustdesk"); Ports = @(21115, 21116, 21117); Risk = "Medium"; Reason = "Open source remote desktop" }
    @{ Name = "DWService"; Processes = @("dwagent"); Ports = @(443); Risk = "Medium"; Reason = "Open source remote agent" }

    # Suspicious/Commonly Abused RMM Tools
    @{ Name = "NetSupport Manager"; Processes = @("client32"); Ports = @(5405); Risk = "High"; Reason = "Frequently abused by malware/scammers" }
    @{ Name = "SimpleHelp"; Processes = @("Remote Access"); Ports = @(80, 443); Risk = "Medium"; Reason = "RMM tool sometimes abused" }
    @{ Name = "Atera"; Processes = @("AteraAgent"); Ports = @(443); Risk = "Medium"; Reason = "RMM tool" }
    @{ Name = "Action1"; Processes = @("action1_agent"); Ports = @(443); Risk = "Medium"; Reason = "RMM tool" }
    @{ Name = "FleetDeck"; Processes = @("fleetdeck_agent"); Ports = @(443); Risk = "Medium"; Reason = "RMM tool" }
    @{ Name = "MeshCentral"; Processes = @("MeshAgent"); Ports = @(443, 4433); Risk = "Medium"; Reason = "Open source RMM - can be abused" }
    @{ Name = "TacticalRMM"; Processes = @("tacticalrmm"); Ports = @(443); Risk = "Medium"; Reason = "Open source RMM" }

    # Known Malware RATs
    @{ Name = "Hidden VNC"; Processes = @("hVNC", "hvnc"); Ports = @(5900); Risk = "Critical"; Reason = "MALWARE - Hidden VNC backdoor" }
    @{ Name = "AsyncRAT"; Processes = @("AsyncClient"); Ports = @(6606, 7707, 8808); Risk = "Critical"; Reason = "MALWARE - Known RAT" }
    @{ Name = "QuasarRAT"; Processes = @("Quasar"); Ports = @(4782); Risk = "Critical"; Reason = "MALWARE - Known RAT" }
    @{ Name = "NjRAT"; Processes = @("njRAT"); Ports = @(5552); Risk = "Critical"; Reason = "MALWARE - Known RAT" }
    @{ Name = "DarkComet"; Processes = @("DarkComet"); Ports = @(1604); Risk = "Critical"; Reason = "MALWARE - Known RAT" }
)

# Paths to scan for remote access software
$Script:ScanPaths = @(
    "$env:ProgramFiles"
    "${env:ProgramFiles(x86)}"
    "$env:ProgramData"
    "$env:APPDATA"
    "$env:LOCALAPPDATA"
    "$env:USERPROFILE\Downloads"
    "$env:TEMP"
    "$env:SystemRoot\Temp"
)

# Registry locations for persistence
$Script:RegistryRunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

# Startup folder paths
$Script:StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

# Known process descriptions (fallback when file metadata isn't available)
$Script:ProcessDescriptions = @{
    # Intel
    "LMS" = "Intel Active Management Technology (AMT) Local Manageability Service - legitimate Intel remote management"
    "IntelCpHDCPSvc" = "Intel Content Protection HDCP Service - legitimate Intel graphics component"
    "IntelCpHeciSvc" = "Intel Content Protection HECI Service - legitimate Intel ME component"
    "jhi_service" = "Intel Dynamic Application Loader Host Interface - legitimate Intel security component"
    "igfxCUIService" = "Intel Graphics Command Center - legitimate Intel graphics control panel"
    "igfxEM" = "Intel Graphics Executive Manager - legitimate Intel graphics component"

    # NVIDIA
    "nvcontainer" = "NVIDIA Container - legitimate NVIDIA driver component"
    "NVDisplay.Container" = "NVIDIA Display Container - legitimate NVIDIA display service"
    "NVIDIA Share" = "NVIDIA GeForce Experience sharing feature - legitimate but can be disabled"

    # AMD
    "RadeonSoftware" = "AMD Radeon Software - legitimate AMD graphics control panel"
    "AMDRSServ" = "AMD Radeon Settings Service - legitimate AMD component"

    # Printers/Scanners
    "HPPrintScanDoctorService" = "HP Print and Scan Doctor - legitimate HP diagnostic tool"
    "HPWMISVC" = "HP WMI Service - legitimate HP management component"

    # Antivirus/Security
    "MBAMService" = "Malwarebytes Anti-Malware Service - legitimate security software"
    "mbamtray" = "Malwarebytes System Tray - legitimate security software"
    "avgnt" = "Avira Antivirus Tray - legitimate security software"
    "avguard" = "Avira Real-Time Protection - legitimate security software"
    "bdagent" = "Bitdefender Agent - legitimate security software"
    "vsserv" = "Bitdefender Virus Shield - legitimate security software"
    "ekrn" = "ESET Kernel Service - legitimate security software"
    "egui" = "ESET GUI - legitimate security software"

    # Backup/Sync
    "CrashPlanService" = "CrashPlan Backup Service - legitimate backup software"
    "BackupService" = "Generic backup service - verify vendor"
    "Carbonite" = "Carbonite Backup - legitimate backup software"

    # VPN (legitimate)
    "openvpn" = "OpenVPN - legitimate VPN client"
    "vpnui" = "Cisco AnyConnect VPN UI - legitimate enterprise VPN"
    "vpnagent" = "Cisco AnyConnect VPN Agent - legitimate enterprise VPN"
    "NordVPN" = "NordVPN - legitimate consumer VPN"
    "ExpressVPN" = "ExpressVPN - legitimate consumer VPN"
    "Windscribe" = "Windscribe VPN - legitimate consumer VPN"

    # System utilities
    "AppleMobileDeviceService" = "Apple Mobile Device Service - iTunes/iPhone sync component"
    "iTunesHelper" = "iTunes Helper - legitimate Apple component"
    "GoodSync" = "GoodSync file synchronization - legitimate sync software"
    "SyncToy" = "Microsoft SyncToy - legitimate Microsoft sync utility"

    # Hardware monitoring
    "HWiNFO" = "HWiNFO hardware monitoring - legitimate system utility"
    "CoreTemp" = "Core Temp CPU monitor - legitimate system utility"
    "SpeedFan" = "SpeedFan hardware monitor - legitimate system utility"
    "AIDA64" = "AIDA64 system information - legitimate diagnostic tool"

    # Common ports
    "port_16992" = "Intel AMT HTTP port - used for remote management"
    "port_16993" = "Intel AMT HTTPS port - used for secure remote management"
    "port_16994" = "Intel AMT Redirection port"
    "port_16995" = "Intel AMT Redirection secure port"
    "port_5357" = "WSDAPI (Web Services for Devices) - Windows network discovery"
    "port_5985" = "WinRM HTTP - Windows Remote Management"
    "port_5986" = "WinRM HTTPS - Windows Remote Management (secure)"
    "port_3389" = "RDP - Remote Desktop Protocol (Windows built-in remote access)"
    "port_22" = "SSH - Secure Shell remote access"
    "port_23" = "Telnet - INSECURE remote access (should be disabled)"
    "port_5900" = "VNC - Virtual Network Computing remote desktop"
    "port_5800" = "VNC HTTP - VNC web interface"
}

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

$Script:Findings = [System.Collections.ArrayList]@()
$Script:LogFile = ""
$Script:ScanStartTime = $null

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-ProcessDescription {
    param(
        [System.Diagnostics.Process]$Process,
        [int]$Port = 0
    )

    $description = ""

    # First, try to get description from the executable's file metadata
    if ($Process -and $Process.Path) {
        try {
            $fileInfo = $Process.MainModule.FileVersionInfo
            if ($fileInfo.FileDescription -and $fileInfo.FileDescription.Trim()) {
                $description = $fileInfo.FileDescription.Trim()
                if ($fileInfo.CompanyName -and $fileInfo.CompanyName.Trim()) {
                    $description += " ($($fileInfo.CompanyName.Trim()))"
                }
            }
        } catch { }
    }

    # If no description from file, check our lookup table by process name
    if (-not $description -and $Process) {
        $procName = $Process.ProcessName
        foreach ($key in $Script:ProcessDescriptions.Keys) {
            if ($procName -match [regex]::Escape($key)) {
                $description = $Script:ProcessDescriptions[$key]
                break
            }
        }
    }

    # Also check if we have info about the specific port
    $portInfo = ""
    if ($Port -gt 0) {
        $portKey = "port_$Port"
        if ($Script:ProcessDescriptions.ContainsKey($portKey)) {
            $portInfo = $Script:ProcessDescriptions[$portKey]
        }
    }

    # Combine process and port info
    if ($description -and $portInfo) {
        return "$description | Port: $portInfo"
    } elseif ($description) {
        return $description
    } elseif ($portInfo) {
        return "Port: $portInfo"
    } else {
        return "Unknown - research this process"
    }
}

# ============================================================================
# OUTPUT FUNCTIONS - Color-coded console output
# ============================================================================

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     REMOTE ACCESS DETECTION & REMOVAL TOOL" -ForegroundColor Cyan
    Write-Host "     For IT Technicians - Tech Support Scam Cleanup" -ForegroundColor Gray
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")

    $timestamp = Get-Date -Format "HH:mm:ss"

    switch ($Type) {
        "Info"     { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host $Message -ForegroundColor White }
        "Success"  { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host "[OK] $Message" -ForegroundColor Green }
        "Warning"  { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host "[!] $Message" -ForegroundColor Yellow }
        "Error"    { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host "[X] $Message" -ForegroundColor Red }
        "Critical" { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host "[!!!] $Message" -ForegroundColor Red -BackgroundColor Black }
        "Found"    { Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray; Write-Host "[FOUND] $Message" -ForegroundColor Magenta }
    }
}

function Write-Finding {
    param($Finding)

    $riskColor = switch ($Finding.Risk) {
        "Critical" { "Red" }
        "High"     { "Red" }
        "Medium"   { "Yellow" }
        default    { "Gray" }
    }

    Write-Host ""
    Write-Host "  --------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [!] FOUND: " -NoNewline -ForegroundColor White
    Write-Host $Finding.Name -ForegroundColor $riskColor
    Write-Host "      Risk Level:    " -NoNewline -ForegroundColor Gray
    Write-Host $Finding.Risk -ForegroundColor $riskColor
    Write-Host "      Location Type: " -NoNewline -ForegroundColor Gray
    Write-Host $Finding.LocationType -ForegroundColor White
    Write-Host "      Path:          " -NoNewline -ForegroundColor Gray
    Write-Host $Finding.Path -ForegroundColor Cyan
    Write-Host "      Why Flagged:   " -NoNewline -ForegroundColor Gray
    Write-Host $Finding.Reason -ForegroundColor Yellow

    if ($Finding.AutoStart) {
        Write-Host "      Auto-Start:    " -NoNewline -ForegroundColor Gray
        Write-Host "YES" -ForegroundColor Red
        Write-Host "      Start Method:  " -NoNewline -ForegroundColor Gray
        Write-Host $Finding.AutoStartMethod -ForegroundColor White
        Write-Host "      Start Path:    " -NoNewline -ForegroundColor Gray
        Write-Host $Finding.AutoStartPath -ForegroundColor Cyan
    }
}

function Write-Log {
    param([string]$Message)

    if ($Script:LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $Script:LogFile -Value "[$timestamp] $Message"
    }
}

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

function Initialize-Scan {
    $Script:Findings = [System.Collections.ArrayList]@()
    $Script:ScanStartTime = Get-Date

    # Create log file in same directory as script (use PSScriptRoot for reliability)
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath }
    if (-not $scriptDir) { $scriptDir = Get-Location }

    # Include PC name in filename for easy identification
    $pcName = $env:COMPUTERNAME
    $dateStr = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $Script:LogFile = Join-Path $scriptDir "RAT-Scan-Log_$pcName`_$dateStr.txt"

    # Create log file immediately to confirm it works
    $header = @"
==========================================
REMOTE ACCESS SCAN LOG
==========================================
Computer Name: $env:COMPUTERNAME
User Account:  $env:USERNAME
Scan Date:     $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Scanner Ver:   $Script:CurrentVersion
Signatures:    $($Script:KnownRATs.Count) tools in database
==========================================

"@
    Set-Content -Path $Script:LogFile -Value $header -Force
    Write-Status "Log file: $Script:LogFile" "Info"
}

function Add-Finding {
    param(
        [string]$Name,
        [string]$Risk,
        [string]$LocationType,
        [string]$Path,
        [string]$Reason,
        [bool]$AutoStart = $false,
        [string]$AutoStartMethod = "",
        [string]$AutoStartPath = ""
    )

    $finding = [PSCustomObject]@{
        Name = $Name
        Risk = $Risk
        LocationType = $LocationType
        Path = $Path
        Reason = $Reason
        AutoStart = $AutoStart
        AutoStartMethod = $AutoStartMethod
        AutoStartPath = $AutoStartPath
    }

    [void]$Script:Findings.Add($finding)
    Write-Finding $finding
    Write-Log "FOUND: $Name | Risk: $Risk | Type: $LocationType | Path: $Path"
}

function Search-InstalledPrograms {
    Write-Host ""
    Write-Status "Scanning installed programs..." "Info"
    Write-Log "Scanning installed programs..."

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $installed = @()
    foreach ($path in $uninstallPaths) {
        try {
            $installed += Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, InstallLocation, UninstallString, Publisher
        } catch { }
    }

    foreach ($rat in $Script:KnownRATs) {
        foreach ($program in $installed) {
            if ($program.DisplayName -match [regex]::Escape($rat.Name)) {
                $installPath = if ($program.InstallLocation) { $program.InstallLocation } else { "Unknown" }
                Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Installed Program (Registry)" `
                    -Path $installPath -Reason $rat.Reason
            }
        }
    }

    Write-Status "Installed programs scan complete" "Success"
}

function Search-FileLocations {
    Write-Host ""
    Write-Status "Scanning file system locations..." "Info"
    Write-Log "Scanning file system locations..."

    foreach ($basePath in $Script:ScanPaths) {
        if (Test-Path $basePath) {
            foreach ($rat in $Script:KnownRATs) {
                # Search for folders matching the RAT name
                try {
                    $folders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match [regex]::Escape($rat.Name) }

                    foreach ($folder in $folders) {
                        Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "File System (Folder)" `
                            -Path $folder.FullName -Reason $rat.Reason
                    }
                } catch { }

                # Search for executables matching process names
                foreach ($procName in $rat.Processes) {
                    try {
                        $exes = Get-ChildItem -Path $basePath -Recurse -Filter "$procName.exe" -ErrorAction SilentlyContinue -Depth 3
                        foreach ($exe in $exes) {
                            Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "File System (Executable)" `
                                -Path $exe.FullName -Reason $rat.Reason
                        }
                    } catch { }
                }
            }
        }
    }

    Write-Status "File system scan complete" "Success"
}

function Search-RegistryPersistence {
    Write-Host ""
    Write-Status "Scanning registry for persistence mechanisms..." "Info"
    Write-Log "Scanning registry persistence..."

    # Check Run keys
    foreach ($regPath in $Script:RegistryRunKeys) {
        if (Test-Path $regPath) {
            try {
                $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }

                foreach ($prop in $props) {
                    foreach ($rat in $Script:KnownRATs) {
                        if ($prop.Name -match [regex]::Escape($rat.Name) -or $prop.Value -match [regex]::Escape($rat.Name)) {
                            Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Registry (Run Key)" `
                                -Path $prop.Value -Reason $rat.Reason `
                                -AutoStart $true -AutoStartMethod "Registry Run Key" -AutoStartPath "$regPath\$($prop.Name)"
                        }

                        # Also check against process names
                        foreach ($procName in $rat.Processes) {
                            if ($prop.Value -match [regex]::Escape($procName)) {
                                Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Registry (Run Key)" `
                                    -Path $prop.Value -Reason $rat.Reason `
                                    -AutoStart $true -AutoStartMethod "Registry Run Key" -AutoStartPath "$regPath\$($prop.Name)"
                            }
                        }
                    }
                }
            } catch { }
        }
    }

    # Check Services
    Write-Status "Checking Windows Services..." "Info"
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            foreach ($rat in $Script:KnownRATs) {
                if ($service.Name -match [regex]::Escape($rat.Name) -or
                    $service.DisplayName -match [regex]::Escape($rat.Name) -or
                    $service.PathName -match [regex]::Escape($rat.Name)) {

                    Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Windows Service" `
                        -Path $service.PathName -Reason $rat.Reason `
                        -AutoStart ($service.StartMode -eq "Auto") -AutoStartMethod "Windows Service" `
                        -AutoStartPath "Service: $($service.Name)"
                }

                foreach ($procName in $rat.Processes) {
                    if ($service.PathName -match [regex]::Escape($procName)) {
                        Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Windows Service" `
                            -Path $service.PathName -Reason $rat.Reason `
                            -AutoStart ($service.StartMode -eq "Auto") -AutoStartMethod "Windows Service" `
                            -AutoStartPath "Service: $($service.Name)"
                    }
                }
            }
        }
    } catch { }

    Write-Status "Registry persistence scan complete" "Success"
}

function Search-StartupFolders {
    Write-Host ""
    Write-Status "Scanning startup folders..." "Info"
    Write-Log "Scanning startup folders..."

    foreach ($startupPath in $Script:StartupPaths) {
        if (Test-Path $startupPath) {
            try {
                $items = Get-ChildItem -Path $startupPath -ErrorAction SilentlyContinue

                foreach ($item in $items) {
                    foreach ($rat in $Script:KnownRATs) {
                        if ($item.Name -match [regex]::Escape($rat.Name)) {
                            $targetPath = $item.FullName

                            # If it's a shortcut, get the target
                            if ($item.Extension -eq ".lnk") {
                                try {
                                    $shell = New-Object -ComObject WScript.Shell
                                    $shortcut = $shell.CreateShortcut($item.FullName)
                                    $targetPath = $shortcut.TargetPath
                                } catch { }
                            }

                            Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Startup Folder" `
                                -Path $targetPath -Reason $rat.Reason `
                                -AutoStart $true -AutoStartMethod "Startup Folder" -AutoStartPath $item.FullName
                        }
                    }
                }
            } catch { }
        }
    }

    Write-Status "Startup folder scan complete" "Success"
}

function Search-ScheduledTasks {
    Write-Host ""
    Write-Status "Scanning scheduled tasks..." "Info"
    Write-Log "Scanning scheduled tasks..."

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne "Disabled" }

        foreach ($task in $tasks) {
            foreach ($rat in $Script:KnownRATs) {
                if ($task.TaskName -match [regex]::Escape($rat.Name) -or
                    $task.TaskPath -match [regex]::Escape($rat.Name)) {

                    $action = ($task.Actions | Select-Object -First 1).Execute

                    Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Scheduled Task" `
                        -Path $action -Reason $rat.Reason `
                        -AutoStart $true -AutoStartMethod "Scheduled Task" -AutoStartPath "$($task.TaskPath)$($task.TaskName)"
                }
            }
        }
    } catch {
        Write-Status "Could not scan scheduled tasks (may need admin rights)" "Warning"
    }

    Write-Status "Scheduled tasks scan complete" "Success"
}

function Search-RunningProcesses {
    Write-Host ""
    Write-Status "Scanning running processes..." "Info"
    Write-Log "Scanning running processes..."

    try {
        $processes = Get-Process -ErrorAction SilentlyContinue

        foreach ($rat in $Script:KnownRATs) {
            foreach ($procName in $rat.Processes) {
                $found = $processes | Where-Object { $_.ProcessName -match [regex]::Escape($procName) }

                foreach ($proc in $found) {
                    try {
                        $path = $proc.Path
                        if (-not $path) { $path = "Path unavailable" }

                        Add-Finding -Name $rat.Name -Risk $rat.Risk -LocationType "Running Process" `
                            -Path $path -Reason "$($rat.Reason) - CURRENTLY RUNNING!"
                    } catch { }
                }
            }
        }
    } catch { }

    Write-Status "Process scan complete" "Success"
}

function Search-NetworkPorts {
    Write-Host ""
    Write-Status "Scanning network connections..." "Info"
    Write-Log "Scanning network connections..."

    # Known safe processes to exclude (Microsoft, browsers, common apps)
    $safeProcesses = @(
        # Microsoft/Windows
        "svchost", "System", "services", "lsass", "csrss", "wininit", "winlogon",
        "SearchIndexer", "SearchHost", "SearchApp", "StartMenuExperienceHost",
        "RuntimeBroker", "dllhost", "conhost", "dwm", "fontdrvhost", "sihost",
        "taskhostw", "explorer", "ShellExperienceHost", "ApplicationFrameHost",
        "SystemSettings", "SettingSyncHost", "backgroundTaskHost", "WmiPrvSE",
        "spoolsv", "msiexec", "TrustedInstaller", "WUDFHost", "dasHost",
        "SecurityHealthService", "SecurityHealthSystray", "MsMpEng", "NisSrv",
        "smartscreen", "UserOOBEBroker", "MusNotifyIcon", "MusNotification",
        "ctfmon", "TextInputHost", "WindowsTerminal", "OpenConsole",
        "Microsoft.Photos", "Video.UI", "Music.UI", "WinStore.App",
        "PhoneExperienceHost", "YourPhone", "OneDrive", "FileCoAuth",
        "Microsoft.SharePoint", "OUTLOOK", "EXCEL", "WINWORD", "POWERPNT",
        "Teams", "ms-teams", "msedge", "msedgewebview2", "MicrosoftEdgeUpdate",
        "OfficeClickToRun", "AppVShNotify", "officeclicktorun",

        # Browsers
        "chrome", "firefox", "brave", "opera", "vivaldi", "waterfox", "iexplore",

        # Common legitimate software
        "Dropbox", "Spotify", "Discord", "Slack", "Zoom", "WebexHost",
        "steam", "steamwebhelper", "EpicGamesLauncher",
        "Adobe", "AcroRd32", "Acrobat", "CCXProcess", "CCLibrary",
        "node", "npm", "python", "pythonw", "java", "javaw",
        "Code", "devenv", "notepad++", "sublime_text",
        "nvidia", "nvcontainer", "NVDisplay", "NVIDIA",
        "amd", "RadeonSoftware",
        "Intel", "igfx",
        "Realtek", "RtkAudUService",
        "sqlservr", "mysqld", "postgres",
        "nginx", "httpd", "apache",
        "git", "ssh", "putty"
    )

    $networkFindings = 0
    $suspiciousConnections = [System.Collections.ArrayList]@()
    $seenConnections = @{}  # Track unique connections to avoid duplicates

    try {
        $connections = Get-NetTCPConnection -State Listen, Established -ErrorAction SilentlyContinue
        $totalConnections = $connections.Count
        Write-Log "  TOTAL active connections: $totalConnections"

        # Build a lookup of process IDs to process info
        $processLookup = @{}
        foreach ($conn in $connections) {
            if (-not $processLookup.ContainsKey($conn.OwningProcess)) {
                try {
                    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $processLookup[$conn.OwningProcess] = $proc
                } catch {
                    $processLookup[$conn.OwningProcess] = $null
                }
            }
        }

        $uniqueProcesses = $processLookup.Values | Where-Object { $_ } | Select-Object -ExpandProperty ProcessName -Unique
        Write-Log "  Unique processes with connections: $($uniqueProcesses.Count)"

        # Filter and categorize connections
        foreach ($conn in $connections) {
            $process = $processLookup[$conn.OwningProcess]
            if (-not $process) { continue }

            $procName = $process.ProcessName

            # Skip known safe processes
            $isSafe = $false
            foreach ($safe in $safeProcesses) {
                if ($procName -match "^$([regex]::Escape($safe))") {
                    $isSafe = $true
                    break
                }
            }

            if ($isSafe) { continue }

            # This is a non-standard process with network activity
            $localPort = $conn.LocalPort
            $portInfo = "Local:$localPort"
            if ($conn.RemotePort -and $conn.RemotePort -ne 0) {
                $portInfo += " -> Remote:$($conn.RemotePort)"
            }
            if ($conn.RemoteAddress -and $conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "::" -and $conn.RemoteAddress -ne "127.0.0.1") {
                $portInfo += " ($($conn.RemoteAddress))"
            }

            # Create unique key to avoid duplicate entries
            $uniqueKey = "$procName-$localPort-$($conn.State)"
            if ($seenConnections.ContainsKey($uniqueKey)) { continue }
            $seenConnections[$uniqueKey] = $true

            # Check if it matches a known RAT
            $isKnownRAT = $false
            $ratMatch = $null

            foreach ($rat in $Script:KnownRATs) {
                foreach ($knownProc in $rat.Processes) {
                    if ($procName -match [regex]::Escape($knownProc)) {
                        $isKnownRAT = $true
                        $ratMatch = $rat
                        break
                    }
                }
                if (-not $isKnownRAT -and $procName -match [regex]::Escape($rat.Name)) {
                    $isKnownRAT = $true
                    $ratMatch = $rat
                }
                if ($isKnownRAT) { break }
            }

            if ($isKnownRAT) {
                # Known remote access tool - add as finding
                Add-Finding -Name $ratMatch.Name -Risk $ratMatch.Risk -LocationType "Active Network Connection ($($conn.State))" `
                    -Path "$procName.exe - $portInfo" -Reason "$($ratMatch.Reason) - Has active network connection!"
                $networkFindings++
            } else {
                # Unknown/suspicious - store full info for later
                $connObj = [PSCustomObject]@{
                    ProcessName = $procName
                    Process = $process
                    LocalPort = $localPort
                    PortInfo = $portInfo
                    State = $conn.State
                }
                [void]$suspiciousConnections.Add($connObj)
            }
        }

        # Log summary
        Write-Log ""
        Write-Log "  --- NETWORK SUMMARY ---"
        Write-Log "  Total connections: $totalConnections"
        Write-Log "  Known remote access tools found: $networkFindings"
        Write-Log "  Other non-standard connections: $($suspiciousConnections.Count)"

        if ($suspiciousConnections.Count -gt 0) {
            Write-Log ""
            Write-Log "  --- OTHER PROCESSES WITH NETWORK ACTIVITY ---"
            Write-Log "  (Not in safe list, but not known RATs - review if unfamiliar)"
            Write-Log ""
            foreach ($connObj in $suspiciousConnections) {
                $description = Get-ProcessDescription -Process $connObj.Process -Port $connObj.LocalPort
                Write-Log "    $($connObj.ProcessName).exe - $($connObj.PortInfo) [$($connObj.State)]"
                Write-Log "      -> $description"
                Write-Log ""
            }
        }

    } catch {
        Write-Status "Could not scan network connections" "Warning"
        Write-Log "  ERROR: Could not scan network connections - $_"
    }

    Write-Status "Network connection scan complete ($networkFindings remote access tools found)" "Success"
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

function Start-InteractiveCleanup {
    if ($Script:Findings.Count -eq 0) {
        Write-Host ""
        Write-Host "  No findings to clean up!" -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Yellow
    Write-Host "     INTERACTIVE CLEANUP MODE" -ForegroundColor Yellow
    Write-Host "  ======================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  You will be shown each finding one at a time." -ForegroundColor Gray
    Write-Host "  For each, you can choose to:" -ForegroundColor Gray
    Write-Host "    [R] Remove it    [S] Skip it    [I] More Info    [Q] Quit" -ForegroundColor White
    Write-Host ""

    # Group findings by software name
    $grouped = $Script:Findings | Group-Object -Property Name

    $current = 0
    $total = $grouped.Count

    foreach ($group in $grouped) {
        $current++

        Write-Host ""
        Write-Host "  ========================================================" -ForegroundColor Cyan
        Write-Host "  [$current/$total] $($group.Name)" -ForegroundColor Cyan
        Write-Host "  ========================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Found in $($group.Count) location(s):" -ForegroundColor White

        $locationNum = 0
        foreach ($finding in $group.Group) {
            $locationNum++
            Write-Host ""
            Write-Host "    Location $locationNum`: $($finding.LocationType)" -ForegroundColor Yellow
            Write-Host "    Path: $($finding.Path)" -ForegroundColor Cyan
            if ($finding.AutoStart) {
                Write-Host "    Auto-Start: $($finding.AutoStartMethod)" -ForegroundColor Red
                Write-Host "    Start Path: $($finding.AutoStartPath)" -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "  Risk Level: " -NoNewline -ForegroundColor Gray
        $riskColor = switch ($group.Group[0].Risk) {
            "Critical" { "Red" }
            "High"     { "Red" }
            "Medium"   { "Yellow" }
            default    { "Gray" }
        }
        Write-Host $group.Group[0].Risk -ForegroundColor $riskColor
        Write-Host "  Reason: $($group.Group[0].Reason)" -ForegroundColor Gray

        Write-Host ""
        Write-Host "  [R] Remove All Locations  [S] Skip  [I] More Info  [Q] Quit Cleanup" -ForegroundColor White
        $choice = Read-Host "  Your choice"

        switch ($choice.ToUpper()) {
            "R" {
                foreach ($finding in $group.Group) {
                    Remove-Finding $finding
                }
            }
            "S" {
                Write-Status "Skipped $($group.Name)" "Info"
                Write-Log "SKIPPED: $($group.Name)"
            }
            "I" {
                Show-DetailedInfo $group
                # After showing info, ask again
                Write-Host ""
                Write-Host "  [R] Remove All  [S] Skip" -ForegroundColor White
                $choice2 = Read-Host "  Your choice"
                if ($choice2.ToUpper() -eq "R") {
                    foreach ($finding in $group.Group) {
                        Remove-Finding $finding
                    }
                } else {
                    Write-Status "Skipped $($group.Name)" "Info"
                    Write-Log "SKIPPED: $($group.Name)"
                }
            }
            "Q" {
                Write-Host ""
                Write-Status "Cleanup cancelled by user" "Warning"
                Write-Log "Cleanup cancelled by user"
                return
            }
            default {
                Write-Status "Invalid choice - Skipping $($group.Name)" "Warning"
                Write-Log "SKIPPED (invalid choice): $($group.Name)"
            }
        }
    }

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Green
    Write-Host "     CLEANUP COMPLETE" -ForegroundColor Green
    Write-Host "  ======================================================" -ForegroundColor Green
}

function Remove-Finding {
    param($Finding)

    Write-Status "Attempting to remove: $($Finding.LocationType)" "Info"
    Write-Log "REMOVING: $($Finding.Name) | Type: $($Finding.LocationType) | Path: $($Finding.Path)"

    $success = $false

    try {
        switch -Wildcard ($Finding.LocationType) {
            "Running Process" {
                # Try to stop the process
                $procName = ($Finding.Path -split '\\')[-1] -replace '\.exe$', ''
                try {
                    Stop-Process -Name $procName -Force -ErrorAction Stop
                    Write-Status "Stopped process: $procName" "Success"
                    $success = $true
                } catch {
                    Write-Status "Could not stop process (may need admin rights)" "Error"
                }
            }

            "File System*" {
                if (Test-Path $Finding.Path) {
                    try {
                        Remove-Item -Path $Finding.Path -Recurse -Force -ErrorAction Stop
                        Write-Status "Removed: $($Finding.Path)" "Success"
                        $success = $true
                    } catch {
                        Write-Status "Could not remove file/folder (may be in use or need admin rights)" "Error"
                    }
                } else {
                    Write-Status "Path not found (may have been removed already)" "Warning"
                }
            }

            "Registry*" {
                if ($Finding.AutoStartPath -and (Test-Path $Finding.AutoStartPath -ErrorAction SilentlyContinue)) {
                    # It's a registry path
                    $regPath = Split-Path $Finding.AutoStartPath -Parent
                    $regName = Split-Path $Finding.AutoStartPath -Leaf
                    try {
                        Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction Stop
                        Write-Status "Removed registry entry: $regName" "Success"
                        $success = $true
                    } catch {
                        Write-Status "Could not remove registry entry (may need admin rights)" "Error"
                    }
                }
            }

            "Startup Folder" {
                if ($Finding.AutoStartPath -and (Test-Path $Finding.AutoStartPath)) {
                    try {
                        Remove-Item -Path $Finding.AutoStartPath -Force -ErrorAction Stop
                        Write-Status "Removed startup item: $($Finding.AutoStartPath)" "Success"
                        $success = $true
                    } catch {
                        Write-Status "Could not remove startup item" "Error"
                    }
                }
            }

            "Scheduled Task" {
                if ($Finding.AutoStartPath) {
                    try {
                        Unregister-ScheduledTask -TaskName (Split-Path $Finding.AutoStartPath -Leaf) -Confirm:$false -ErrorAction Stop
                        Write-Status "Removed scheduled task" "Success"
                        $success = $true
                    } catch {
                        Write-Status "Could not remove scheduled task (may need admin rights)" "Error"
                    }
                }
            }

            "Windows Service" {
                if ($Finding.AutoStartPath -match "Service: (.+)$") {
                    $serviceName = $Matches[1]
                    try {
                        Stop-Service -Name $serviceName -Force -ErrorAction Stop
                        sc.exe delete $serviceName | Out-Null
                        Write-Status "Stopped and removed service: $serviceName" "Success"
                        $success = $true
                    } catch {
                        Write-Status "Could not remove service (may need admin rights)" "Error"
                    }
                }
            }

            "Installed Program*" {
                Write-Status "Please uninstall through Programs and Features for safety" "Warning"
                Write-Status "Opening Programs and Features..." "Info"
                Start-Process "appwiz.cpl"
            }

            "Network Port*" {
                Write-Status "Network connections will close when the associated process is stopped" "Info"
            }

            default {
                Write-Status "Unknown location type - manual removal recommended" "Warning"
            }
        }
    } catch {
        Write-Status "Error during removal: $_" "Error"
    }

    if ($success) {
        Write-Log "REMOVED SUCCESSFULLY: $($Finding.Path)"
    } else {
        Write-Log "REMOVAL FAILED: $($Finding.Path)"
    }
}

function Show-DetailedInfo {
    param($Group)

    Write-Host ""
    Write-Host "  ==================== DETAILED INFO ====================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Software: $($Group.Name)" -ForegroundColor White
    Write-Host ""

    # Find matching RAT info
    $ratInfo = $Script:KnownRATs | Where-Object { $_.Name -eq $Group.Name } | Select-Object -First 1

    if ($ratInfo) {
        Write-Host "  Known Information:" -ForegroundColor Yellow
        Write-Host "    - Risk Level: $($ratInfo.Risk)" -ForegroundColor Gray
        Write-Host "    - Why Suspicious: $($ratInfo.Reason)" -ForegroundColor Gray
        Write-Host "    - Common Ports: $($ratInfo.Ports -join ', ')" -ForegroundColor Gray
        Write-Host "    - Process Names: $($ratInfo.Processes -join ', ')" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  All Found Locations:" -ForegroundColor Yellow
    foreach ($finding in $Group.Group) {
        Write-Host "    [$($finding.LocationType)]" -ForegroundColor Cyan
        Write-Host "      $($finding.Path)" -ForegroundColor Gray
        if ($finding.AutoStart) {
            Write-Host "      ^ Auto-starts via: $($finding.AutoStartMethod)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  =======================================================" -ForegroundColor Magenta
}

# ============================================================================
# MAIN MENU & EXECUTION
# ============================================================================

function Show-Results {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SCAN RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    # Also write summary to log
    Write-Log ""
    Write-Log "=========================================="
    Write-Log "SCAN RESULTS SUMMARY"
    Write-Log "=========================================="

    if ($Script:Findings.Count -eq 0) {
        Write-Host "  No remote access software detected!" -ForegroundColor Green
        Write-Host "  The system appears clean." -ForegroundColor Green
        Write-Log "No remote access software detected. System appears clean."
    } else {
        $grouped = $Script:Findings | Group-Object -Property Name

        Write-Host "  Found $($grouped.Count) suspicious program(s) in $($Script:Findings.Count) location(s):" -ForegroundColor Yellow
        Write-Log "Found $($grouped.Count) suspicious program(s) in $($Script:Findings.Count) location(s):"
        Write-Host ""

        foreach ($group in $grouped) {
            $riskColor = switch ($group.Group[0].Risk) {
                "Critical" { "Red" }
                "High"     { "Red" }
                "Medium"   { "Yellow" }
                default    { "Gray" }
            }
            Write-Host "    - $($group.Name) " -NoNewline -ForegroundColor White
            Write-Host "[$($group.Group[0].Risk)]" -NoNewline -ForegroundColor $riskColor
            Write-Host " in $($group.Count) location(s)" -ForegroundColor Gray

            Write-Log "  - $($group.Name) [$($group.Group[0].Risk)] in $($group.Count) location(s)"

            # Log each specific finding with full details
            foreach ($finding in $group.Group) {
                Write-Log "      Type: $($finding.LocationType)"
                Write-Log "      Path: $($finding.Path)"
                if ($finding.AutoStart) {
                    Write-Log "      Auto-Start: $($finding.AutoStartMethod) at $($finding.AutoStartPath)"
                }
            }
        }
    }

    $duration = (Get-Date) - $Script:ScanStartTime
    Write-Host ""
    Write-Host "  Scan completed in $([math]::Round($duration.TotalSeconds, 1)) seconds" -ForegroundColor Gray
    Write-Host "  Log saved to: $Script:LogFile" -ForegroundColor Gray
    Write-Host ""

    Write-Log ""
    Write-Log "Scan completed in $([math]::Round($duration.TotalSeconds, 1)) seconds"
    Write-Log "=========================================="
}

function Start-FullScan {
    Initialize-Scan

    Search-RunningProcesses
    Search-InstalledPrograms
    Search-FileLocations
    Search-RegistryPersistence
    Search-StartupFolders
    Search-ScheduledTasks
    Search-NetworkPorts

    Show-Results
    Write-Log "Scan completed. Found $($Script:Findings.Count) item(s)."
}

function Show-MainMenu {
    Write-Banner

    # Show signature info in header
    Write-Host "  Signatures: v$Script:CurrentVersion ($($Script:KnownRATs.Count) tools)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  What would you like to do?" -ForegroundColor White
    Write-Host ""
    Write-Host "    [1] Run Full Scan" -ForegroundColor Cyan
    Write-Host "    [2] Run Scan + Interactive Cleanup" -ForegroundColor Cyan
    Write-Host "    [3] View Last Scan Results" -ForegroundColor Cyan
    Write-Host "    [4] Update Signatures (from GitHub)" -ForegroundColor Yellow
    Write-Host "    [5] Signature Database Info" -ForegroundColor Cyan
    Write-Host "    [6] Compare Scan Logs (verify cleanup)" -ForegroundColor Green
    Write-Host "    [7] Add New Signature (found something new?)" -ForegroundColor Magenta
    Write-Host "    [8] Exit" -ForegroundColor Cyan
    Write-Host ""

    $choice = Read-Host "  Enter choice (1-8)"

    switch ($choice) {
        "1" {
            Start-FullScan
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "2" {
            Start-FullScan
            if ($Script:Findings.Count -gt 0) {
                Start-InteractiveCleanup
            }
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "3" {
            if ($Script:Findings.Count -eq 0) {
                Write-Host ""
                Write-Host "  No scan has been run yet. Run a scan first!" -ForegroundColor Yellow
            } else {
                Show-Results
            }
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "4" {
            Update-Signatures
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "5" {
            Show-SignatureInfo
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "6" {
            Compare-ScanLogs
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "7" {
            Add-NewSignature
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "8" {
            Write-Host ""
            Write-Host "  Goodbye! Stay safe out there." -ForegroundColor Green
            Write-Host ""
            exit
        }
        default {
            Write-Host ""
            Write-Host "  Invalid choice. Please enter 1-8." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-MainMenu
        }
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Set up script directory for signature file path
if (-not $PSScriptRoot) {
    $Script:SignatureFile = Join-Path (Get-Location) "signatures.json"
} else {
    $Script:SignatureFile = Join-Path $PSScriptRoot "signatures.json"
}

# Load signatures from JSON file (or fall back to built-in)
Write-Host ""
Write-Host "  Loading signature database..." -ForegroundColor Gray
if (Load-Signatures) {
    Write-Host "  Loaded $($Script:KnownRATs.Count) signatures (v$Script:CurrentVersion)" -ForegroundColor Green
} else {
    Write-Host "  Using built-in signatures ($($Script:KnownRATs.Count) tools)" -ForegroundColor Yellow
}
Start-Sleep -Milliseconds 500

# Check for admin rights and warn if not
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  NOTE: Running without Administrator rights." -ForegroundColor Yellow
    Write-Host "  Some features may be limited. For full functionality," -ForegroundColor Yellow
    Write-Host "  right-click and select 'Run as Administrator'." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Press any key to continue anyway..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

Show-MainMenu
