#Requires -Version 5.1
<#
.SYNOPSIS
    Signature Research Tool - Scans the web for new remote access tools and malware
.DESCRIPTION
    Searches security blogs, forums, and threat intel sources for new RATs and
    remote access tools. Helps keep your signature database up to date.
.NOTES
    Author: IT-Tools Project
    Version: 1.0
    Run this on YOUR PC (not customer PCs) to research new threats
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:SignatureFile = Join-Path $PSScriptRoot "signatures.json"
$Script:ResearchLogFile = Join-Path $PSScriptRoot "research-log.txt"

# Sources to search
$Script:Sources = @{
    # Security News & Blogs
    "BleepingComputer" = @{
        Type = "RSS"
        Url = "https://www.bleepingcomputer.com/feed/"
        SearchUrl = "https://www.bleepingcomputer.com/search/?q="
        Category = "Security News"
    }
    "The Hacker News" = @{
        Type = "RSS"
        Url = "https://feeds.feedburner.com/TheHackersNews"
        SearchUrl = "https://thehackernews.com/search?q="
        Category = "Security News"
    }
    "Krebs on Security" = @{
        Type = "RSS"
        Url = "https://krebsonsecurity.com/feed/"
        SearchUrl = "https://krebsonsecurity.com/?s="
        Category = "Security News"
    }
    "Malwarebytes Blog" = @{
        Type = "RSS"
        Url = "https://blog.malwarebytes.com/feed/"
        SearchUrl = "https://blog.malwarebytes.com/?s="
        Category = "Security News"
    }

    # Forums
    "Malwarebytes Forums" = @{
        Type = "Forum"
        Url = "https://forums.malwarebytes.com/forum/7-malware-removal-help/"
        SearchUrl = "https://forums.malwarebytes.com/search/?q="
        Category = "Forum"
    }
    "Reddit r/techsupport" = @{
        Type = "Reddit"
        Url = "https://www.reddit.com/r/techsupport/new/.json"
        SearchUrl = "https://www.reddit.com/r/techsupport/search.json?q="
        Category = "Forum"
    }
    "Reddit r/antivirus" = @{
        Type = "Reddit"
        Url = "https://www.reddit.com/r/antivirus/new/.json"
        SearchUrl = "https://www.reddit.com/r/antivirus/search.json?q="
        Category = "Forum"
    }
    "Reddit r/Scams" = @{
        Type = "Reddit"
        Url = "https://www.reddit.com/r/Scams/new/.json"
        SearchUrl = "https://www.reddit.com/r/Scams/search.json?q="
        Category = "Forum"
    }
    "Reddit r/malware" = @{
        Type = "Reddit"
        Url = "https://www.reddit.com/r/malware/new/.json"
        SearchUrl = "https://www.reddit.com/r/Malware/search.json?q="
        Category = "Forum"
    }

    # Threat Intelligence
    "abuse.ch URLhaus" = @{
        Type = "ThreatIntel"
        Url = "https://urlhaus.abuse.ch/api/"
        Category = "Threat Intel"
    }
    "Any.Run Blog" = @{
        Type = "RSS"
        Url = "https://any.run/cybersecurity-blog/feed/"
        SearchUrl = "https://any.run/cybersecurity-blog/?s="
        Category = "Threat Intel"
    }
    "Sophos News" = @{
        Type = "RSS"
        Url = "https://news.sophos.com/en-us/feed/"
        SearchUrl = "https://news.sophos.com/en-us/?s="
        Category = "Security News"
    }
}

# Keywords to search for
$Script:SearchKeywords = @(
    "remote access trojan"
    "RAT malware"
    "tech support scam"
    "remote support scam"
    "AnyDesk scam"
    "TeamViewer scam"
    "ScreenConnect malware"
    "remote desktop malware"
    "RMM abuse"
    "hidden VNC"
    "new RAT"
    "remote access tool abuse"
)

# FRST-specific keywords (for forum searches)
$Script:FRSTKeywords = @(
    "FRST remote access"
    "FRST anydesk"
    "FRST teamviewer"
    "FRST screenconnect"
    "FRST RAT"
    "Farbar remote"
    "FRST scam"
    "tech support scam FRST"
    "FRST connectwise"
    "FRST rustdesk"
    "FRST splashtop"
    "FRST ultraviewer"
)

# Known tool names to track
$Script:KnownToolNames = @(
    "AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise", "GoToAssist",
    "LogMeIn", "Supremo", "Splashtop", "UltraVNC", "TightVNC", "RealVNC",
    "Ammyy", "AeroAdmin", "RemotePC", "RustDesk", "DWService", "NetSupport",
    "SimpleHelp", "Atera", "Action1", "MeshCentral", "Parsec", "BeyondTrust",
    "Bomgar", "Zoho Assist", "ISL Online", "FleetDeck", "TacticalRMM"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Add-Content -Path $Script:ResearchLogFile -Value $logEntry
    Write-Host "  $Message"
}

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SIGNATURE RESEARCH TOOL" -ForegroundColor Cyan
    Write-Host "     Scan the web for new remote access threats" -ForegroundColor Gray
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-WebContent {
    param(
        [string]$Url,
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RemoteAccessScanner/1.0"
    )

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", $UserAgent)
        $content = $webClient.DownloadString($Url)
        return $content
    } catch {
        return $null
    }
}

# ============================================================================
# SEARCH FUNCTIONS
# ============================================================================

function Search-Reddit {
    param(
        [string]$Subreddit,
        [string]$Query
    )

    $results = @()

    try {
        $searchUrl = "https://www.reddit.com/r/$Subreddit/search.json?q=$([uri]::EscapeDataString($Query))&restrict_sr=1&sort=new&limit=25"
        $content = Get-WebContent -Url $searchUrl

        if ($content) {
            $json = $content | ConvertFrom-Json
            foreach ($post in $json.data.children) {
                $results += [PSCustomObject]@{
                    Title = $post.data.title
                    Url = "https://reddit.com$($post.data.permalink)"
                    Date = [DateTimeOffset]::FromUnixTimeSeconds($post.data.created_utc).DateTime
                    Source = "Reddit r/$Subreddit"
                    Score = $post.data.score
                }
            }
        }
    } catch {
        Write-Host "    Error searching r/$Subreddit`: $_" -ForegroundColor Red
    }

    return $results
}

function Search-RSS {
    param(
        [string]$FeedUrl,
        [string]$SourceName
    )

    $results = @()

    try {
        $content = Get-WebContent -Url $FeedUrl

        if ($content) {
            [xml]$xml = $content

            # Handle different RSS formats
            $items = $xml.rss.channel.item
            if (-not $items) { $items = $xml.feed.entry }

            foreach ($item in $items | Select-Object -First 20) {
                $title = $item.title
                if ($title -is [System.Xml.XmlElement]) { $title = $title.'#text' }

                $link = $item.link
                if ($link -is [System.Xml.XmlElement]) { $link = $link.href }

                $pubDate = $item.pubDate
                if (-not $pubDate) { $pubDate = $item.published }
                if (-not $pubDate) { $pubDate = $item.updated }

                $results += [PSCustomObject]@{
                    Title = $title
                    Url = $link
                    Date = $pubDate
                    Source = $SourceName
                    Score = 0
                }
            }
        }
    } catch {
        Write-Host "    Error fetching RSS from $SourceName`: $_" -ForegroundColor Red
    }

    return $results
}

function Search-AllSources {
    param([string]$Query)

    Write-Host ""
    Write-Host "  Searching for: $Query" -ForegroundColor Yellow
    Write-Host ""

    $allResults = @()

    # Search Reddit sources
    foreach ($source in $Script:Sources.GetEnumerator()) {
        if ($source.Value.Type -eq "Reddit") {
            $subreddit = $source.Key -replace "Reddit r/", ""
            Write-Host "    Searching $($source.Key)..." -ForegroundColor Gray
            $results = Search-Reddit -Subreddit $subreddit -Query $Query
            $allResults += $results
            Start-Sleep -Milliseconds 1000  # Rate limiting
        }
    }

    # Search RSS feeds (look for matches in recent posts)
    foreach ($source in $Script:Sources.GetEnumerator()) {
        if ($source.Value.Type -eq "RSS") {
            Write-Host "    Checking $($source.Key)..." -ForegroundColor Gray
            $results = Search-RSS -FeedUrl $source.Value.Url -SourceName $source.Key
            # Filter by query
            $filtered = $results | Where-Object { $_.Title -match $Query }
            $allResults += $filtered
            Start-Sleep -Milliseconds 500
        }
    }

    return $allResults
}

function Search-FRSTLogs {
    <#
    .SYNOPSIS
        Searches Bleeping Computer and Malwarebytes forums for FRST log analyses
        where experts identify remote access tools and malware
    #>

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     FRST LOG ANALYSIS SEARCH" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Searching malware removal forums for FRST log analyses..." -ForegroundColor Gray
    Write-Host "  Looking for expert-identified RATs and their signatures." -ForegroundColor Gray
    Write-Host ""

    $allResults = @()

    # Search Bleeping Computer forums
    Write-Host "  --- Bleeping Computer Forums ---" -ForegroundColor Yellow
    foreach ($keyword in $Script:FRSTKeywords) {
        Write-Host "    Searching: $keyword" -ForegroundColor Gray
        try {
            # BleepingComputer search URL
            $searchUrl = "https://www.bleepingcomputer.com/forums/index.php?app=core&module=search&do=search&fromMainBar=1&q=$([uri]::EscapeDataString($keyword))"

            # Also try Google site search as backup
            $googleUrl = "https://www.google.com/search?q=site:bleepingcomputer.com/forums+$([uri]::EscapeDataString($keyword))+FRST"

            $allResults += [PSCustomObject]@{
                Keyword = $keyword
                Source = "Bleeping Computer"
                SearchUrl = $searchUrl
                GoogleUrl = $googleUrl
            }
        } catch {
            Write-Host "      Error: $_" -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 500
    }

    # Search Malwarebytes forums
    Write-Host ""
    Write-Host "  --- Malwarebytes Forums ---" -ForegroundColor Yellow
    foreach ($keyword in $Script:FRSTKeywords) {
        Write-Host "    Searching: $keyword" -ForegroundColor Gray
        try {
            # Malwarebytes forum search
            $searchUrl = "https://forums.malwarebytes.com/search/?q=$([uri]::EscapeDataString($keyword))"

            $allResults += [PSCustomObject]@{
                Keyword = $keyword
                Source = "Malwarebytes Forums"
                SearchUrl = $searchUrl
                GoogleUrl = "https://www.google.com/search?q=site:forums.malwarebytes.com+$([uri]::EscapeDataString($keyword))+FRST"
            }
        } catch {
            Write-Host "      Error: $_" -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 500
    }

    # Search Reddit for FRST discussions
    Write-Host ""
    Write-Host "  --- Reddit FRST Discussions ---" -ForegroundColor Yellow
    $redditSubs = @("techsupport", "antivirus", "malware")
    foreach ($sub in $redditSubs) {
        Write-Host "    Searching r/$sub for FRST..." -ForegroundColor Gray
        $results = Search-Reddit -Subreddit $sub -Query "FRST remote access"
        foreach ($r in $results) {
            $allResults += [PSCustomObject]@{
                Title = $r.Title
                Url = $r.Url
                Date = $r.Date
                Source = "Reddit r/$sub"
                Type = "Discussion"
            }
        }
        Start-Sleep -Milliseconds 1500
    }

    # Display results and helpful links
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     FRST ANALYSIS RESOURCES" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  HOW TO USE THESE RESOURCES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open the links below in your browser" -ForegroundColor White
    Write-Host "  2. Look for threads where users post FRST logs" -ForegroundColor White
    Write-Host "  3. Read the EXPERT RESPONSES (from forum helpers)" -ForegroundColor White
    Write-Host "  4. Look for file paths, registry keys, process names" -ForegroundColor White
    Write-Host "     that experts identify as malicious" -ForegroundColor White
    Write-Host ""

    Write-Host "  WHAT TO LOOK FOR IN EXPERT RESPONSES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  File Paths (for installPaths):" -ForegroundColor Cyan
    Write-Host "    C:\Users\*\AppData\Roaming\[ToolName]" -ForegroundColor Gray
    Write-Host "    C:\Users\*\AppData\Local\[ToolName]" -ForegroundColor Gray
    Write-Host "    C:\ProgramData\[ToolName]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Registry Keys (for registryKeys):" -ForegroundColor Cyan
    Write-Host "    HKLM\SOFTWARE\[ToolName]" -ForegroundColor Gray
    Write-Host "    HKCU\SOFTWARE\[ToolName]" -ForegroundColor Gray
    Write-Host "    Run keys with suspicious entries" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Process/Service Names (for processes/services):" -ForegroundColor Cyan
    Write-Host "    Unusual .exe names in FRST process list" -ForegroundColor Gray
    Write-Host "    Services marked for removal by experts" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     QUICK SEARCH LINKS" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  BLEEPING COMPUTER:" -ForegroundColor Yellow
    Write-Host "  [1] FRST + Remote Access:" -ForegroundColor Cyan
    Write-Host "      https://www.bleepingcomputer.com/forums/f/22/virus-trojan-spyware-and-malware-removal-help/" -ForegroundColor Gray
    Write-Host "  [2] Search: site:bleepingcomputer.com FRST anydesk" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  MALWAREBYTES FORUMS:" -ForegroundColor Yellow
    Write-Host "  [3] Malware Removal Help:" -ForegroundColor Cyan
    Write-Host "      https://forums.malwarebytes.com/forum/7-malware-removal-help/" -ForegroundColor Gray
    Write-Host "  [4] Search: site:forums.malwarebytes.com FRST remote" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  GOOGLE SEARCHES (paste in browser):" -ForegroundColor Yellow
    Write-Host "  [5] site:bleepingcomputer.com FRST 'tech support scam'" -ForegroundColor Cyan
    Write-Host "  [6] site:forums.malwarebytes.com FRST anydesk OR teamviewer" -ForegroundColor Cyan
    Write-Host "  [7] site:bleepingcomputer.com FRST screenconnect connectwise" -ForegroundColor Cyan
    Write-Host ""

    # Show Reddit results if any
    $redditResults = $allResults | Where-Object { $_.Source -like "Reddit*" -and $_.Title }
    if ($redditResults.Count -gt 0) {
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host "     REDDIT FRST DISCUSSIONS FOUND" -ForegroundColor Cyan
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host ""

        $counter = 0
        foreach ($result in $redditResults | Select-Object -First 15) {
            $counter++
            Write-Host "  [$counter] $($result.Title)" -ForegroundColor Cyan
            Write-Host "      $($result.Source) | $($result.Date)" -ForegroundColor Gray
            Write-Host "      $($result.Url)" -ForegroundColor DarkGray
            Write-Host ""
        }
    }

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Yellow
    Write-Host "  TIP: When you find a new tool, use option [3] Add New" -ForegroundColor Yellow
    Write-Host "  Signature to add it to your database!" -ForegroundColor Yellow
    Write-Host "  ======================================================" -ForegroundColor Yellow

    Write-Log "FRST log search completed - found $($redditResults.Count) Reddit discussions"
}

function Search-ForNewThreats {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SCANNING FOR NEW THREATS" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This will search multiple sources for recent mentions of" -ForegroundColor Gray
    Write-Host "  remote access tools, RATs, and tech support scams." -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting threat research scan..."

    $allResults = @()

    # Search for each keyword
    foreach ($keyword in $Script:SearchKeywords) {
        Write-Host ""
        Write-Host "  --- Searching: '$keyword' ---" -ForegroundColor Yellow

        # Search Reddit
        $redditSubs = @("techsupport", "antivirus", "Scams", "malware")
        foreach ($sub in $redditSubs) {
            Write-Host "    Reddit r/$sub..." -ForegroundColor Gray
            $results = Search-Reddit -Subreddit $sub -Query $keyword
            foreach ($r in $results) {
                $r | Add-Member -NotePropertyName "Keyword" -NotePropertyValue $keyword -Force
            }
            $allResults += $results
            Start-Sleep -Milliseconds 1500  # Reddit rate limiting
        }
    }

    # Remove duplicates
    $uniqueResults = $allResults | Sort-Object Url -Unique | Sort-Object Date -Descending

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     SEARCH RESULTS" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Found $($uniqueResults.Count) unique results" -ForegroundColor White
    Write-Host ""

    # Display top results
    $counter = 0
    foreach ($result in $uniqueResults | Select-Object -First 20) {
        $counter++
        Write-Host "  [$counter] $($result.Title)" -ForegroundColor Cyan
        Write-Host "      Source: $($result.Source) | Date: $($result.Date)" -ForegroundColor Gray
        Write-Host "      URL: $($result.Url)" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Log results
    Write-Log "Found $($uniqueResults.Count) results"

    return $uniqueResults
}

function Search-SpecificTool {
    Write-Host ""
    $toolName = Read-Host "  Enter tool name to research (e.g., 'RustDesk')"

    if ([string]::IsNullOrWhiteSpace($toolName)) {
        Write-Host "  No tool name entered." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Researching: $toolName" -ForegroundColor Cyan
    Write-Host ""

    $allResults = @()

    # Search Reddit
    $redditSubs = @("techsupport", "antivirus", "Scams", "malware", "sysadmin")
    foreach ($sub in $redditSubs) {
        Write-Host "    Searching r/$sub..." -ForegroundColor Gray
        $results = Search-Reddit -Subreddit $sub -Query $toolName
        $allResults += $results
        Start-Sleep -Milliseconds 1500
    }

    # Search RSS feeds
    foreach ($source in $Script:Sources.GetEnumerator()) {
        if ($source.Value.Type -eq "RSS") {
            Write-Host "    Checking $($source.Key)..." -ForegroundColor Gray
            $results = Search-RSS -FeedUrl $source.Value.Url -SourceName $source.Key
            $filtered = $results | Where-Object { $_.Title -match $toolName }
            $allResults += $filtered
        }
    }

    $uniqueResults = $allResults | Sort-Object Url -Unique | Sort-Object Date -Descending

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     RESULTS FOR: $toolName" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    if ($uniqueResults.Count -eq 0) {
        Write-Host "  No results found for '$toolName'" -ForegroundColor Yellow
        Write-Host "  This could mean:" -ForegroundColor Gray
        Write-Host "    - It's a new/unknown tool" -ForegroundColor Gray
        Write-Host "    - It's spelled differently" -ForegroundColor Gray
        Write-Host "    - It hasn't been discussed recently" -ForegroundColor Gray
    } else {
        Write-Host "  Found $($uniqueResults.Count) results:" -ForegroundColor White
        Write-Host ""

        $counter = 0
        foreach ($result in $uniqueResults | Select-Object -First 15) {
            $counter++
            Write-Host "  [$counter] $($result.Title)" -ForegroundColor Cyan
            Write-Host "      $($result.Source) | $($result.Url)" -ForegroundColor Gray
            Write-Host ""
        }
    }

    Write-Host ""
    $addSig = Read-Host "  Would you like to add '$toolName' to your signatures? (Y/N)"
    if ($addSig -match "^[Yy]") {
        Add-SignatureInteractive -ToolName $toolName
    }
}

function Add-SignatureInteractive {
    param([string]$ToolName = "")

    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     ADD NEW SIGNATURE" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    if ([string]::IsNullOrWhiteSpace($ToolName)) {
        $ToolName = Read-Host "  Tool Name"
    }

    if ([string]::IsNullOrWhiteSpace($ToolName)) {
        Write-Host "  Name is required." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  Enter details for: $ToolName" -ForegroundColor Cyan
    Write-Host "  (Press Enter to skip optional fields)" -ForegroundColor Gray
    Write-Host ""

    # Risk level
    Write-Host "  Risk Level: [1] Critical [2] High [3] Medium [4] Low" -ForegroundColor Yellow
    $riskChoice = Read-Host "  Select (1-4)"
    $risk = switch ($riskChoice) {
        "1" { "Critical" }
        "2" { "High" }
        "3" { "Medium" }
        "4" { "Low" }
        default { "Medium" }
    }

    # Category
    Write-Host "  Category: [1] Remote Desktop [2] VNC [3] RMM [4] Malware" -ForegroundColor Yellow
    $catChoice = Read-Host "  Select (1-4)"
    $category = switch ($catChoice) {
        "1" { "Remote Desktop" }
        "2" { "VNC" }
        "3" { "RMM" }
        "4" { "Malware" }
        default { "Remote Desktop" }
    }

    $reason = Read-Host "  Why suspicious?"
    if (-not $reason) { $reason = "Remote access tool - verify legitimacy" }

    Write-Host ""
    Write-Host "  --- Process/Service Info (comma-separated) ---" -ForegroundColor Yellow
    $processes = Read-Host "  Process names (e.g., tool.exe, toolservice)"
    $services = Read-Host "  Service names"
    $ports = Read-Host "  Ports (e.g., 443, 8080)"

    Write-Host ""
    Write-Host "  --- Install Locations (comma-separated) ---" -ForegroundColor Yellow
    $paths = Read-Host "  Install paths (use %APPDATA%, %PROGRAMFILES%)"
    $regKeys = Read-Host "  Registry keys"

    $notes = Read-Host "  Notes"

    # Build signature
    $newSig = [ordered]@{
        name = $ToolName
        risk = $risk
        category = $category
        reason = $reason
        isLegitimate = ($risk -ne "Critical")
        processes = @($processes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        services = @($services -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        ports = @($ports -split ',' | ForEach-Object { if ($_ -match '\d+') { [int]$_.Trim() } } | Where-Object { $_ })
        installPaths = @($paths -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        registryKeys = @($regKeys -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        autoStartMethods = @()
        fileSignatures = @()
        notes = $notes
    }

    # Preview
    Write-Host ""
    Write-Host "  --- PREVIEW ---" -ForegroundColor Cyan
    Write-Host "  Name: $ToolName [$risk]" -ForegroundColor White
    Write-Host "  Category: $category" -ForegroundColor Gray
    Write-Host "  Processes: $($newSig.processes -join ', ')" -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "  Save this signature? (Y/N)"
    if ($confirm -notmatch "^[Yy]") {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    # Save to signatures.json
    try {
        $json = Get-Content $Script:SignatureFile -Raw | ConvertFrom-Json

        # Check for existing
        $existing = $json.signatures | Where-Object { $_.name -eq $ToolName }
        $changeType = if ($existing) { "Updated" } else { "Added" }
        if ($existing) {
            $json.signatures = @($json.signatures | Where-Object { $_.name -ne $ToolName })
        }

        $json.signatures += [PSCustomObject]$newSig

        # Bump version
        if ($json.version -match '^(\d+)\.(\d+)\.(\d+)$') {
            $json.version = "$($Matches[1]).$($Matches[2]).$([int]$Matches[3] + 1)"
        }

        # Update timestamp
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
            changes = @("$changeType signature: $ToolName [$risk]")
        }

        # Prepend new change to beginning of array
        $json.changeLog = @($changeEntry) + @($json.changeLog)

        $json | ConvertTo-Json -Depth 10 | Set-Content $Script:SignatureFile -Encoding UTF8

        Write-Host ""
        Write-Host "  Signature saved!" -ForegroundColor Green
        Write-Host "  New version: $($json.version)" -ForegroundColor White
        Write-Host "  Change: $changeType $ToolName" -ForegroundColor Cyan

        Write-Log "Added signature: $ToolName"

    } catch {
        Write-Host "  Error saving: $_" -ForegroundColor Red
    }
}

function Show-CurrentSignatures {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     CURRENT SIGNATURES" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        $json = Get-Content $Script:SignatureFile -Raw | ConvertFrom-Json

        Write-Host "  Version: $($json.version)" -ForegroundColor White
        Write-Host "  Last Updated: " -NoNewline -ForegroundColor Gray
        if ($json.lastUpdatedTime) {
            Write-Host $json.lastUpdatedTime -ForegroundColor Cyan
        } else {
            Write-Host $json.lastUpdated -ForegroundColor Cyan
        }
        Write-Host "  Total Signatures: $($json.signatures.Count)" -ForegroundColor White
        Write-Host ""

        # Show recent change log
        if ($json.changeLog -and $json.changeLog.Count -gt 0) {
            Write-Host "  --- RECENT CHANGES ---" -ForegroundColor Yellow
            $recentChanges = $json.changeLog | Select-Object -First 5
            foreach ($change in $recentChanges) {
                Write-Host "  v$($change.version) " -NoNewline -ForegroundColor White
                Write-Host "($($change.date))" -ForegroundColor Gray
                foreach ($item in $change.changes) {
                    Write-Host "    - $item" -ForegroundColor Gray
                }
            }
            Write-Host ""
        }

        # Show signatures by category
        Write-Host "  --- SIGNATURES BY CATEGORY ---" -ForegroundColor Yellow
        $grouped = $json.signatures | Group-Object -Property category
        foreach ($group in $grouped) {
            Write-Host "  $($group.Name) ($($group.Count)):" -ForegroundColor White
            foreach ($sig in $group.Group) {
                $color = switch ($sig.risk) {
                    "Critical" { "Red" }
                    "High" { "Red" }
                    "Medium" { "Yellow" }
                    default { "Green" }
                }
                Write-Host "    - $($sig.name) " -NoNewline -ForegroundColor Gray
                Write-Host "[$($sig.risk)]" -ForegroundColor $color
            }
        }
        Write-Host ""
    } catch {
        Write-Host "  Error reading signatures: $_" -ForegroundColor Red
    }
}

function Push-ToGitHub {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "     PUSH TO GITHUB" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This will upload the updated signatures.json" -ForegroundColor Gray
    Write-Host "  to your GitHub repository." -ForegroundColor Gray
    Write-Host ""

    # Check if git is available
    $gitAvailable = Get-Command git -ErrorAction SilentlyContinue

    if (-not $gitAvailable) {
        Write-Host "  Git is not installed." -ForegroundColor Yellow
        Show-ManualUploadInstructions
        return
    }

    Write-Host "  Git is installed." -ForegroundColor Green
    Write-Host ""

    # Change to script directory
    Push-Location $PSScriptRoot

    # Check if this folder is a git repository
    $isGitRepo = Test-Path ".git"

    if (-not $isGitRepo) {
        Write-Host "  This folder is not connected to GitHub yet." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Would you like to:" -ForegroundColor White
        Write-Host "    [1] Initialize git and connect to GitHub (recommended)" -ForegroundColor Cyan
        Write-Host "    [2] Upload manually through the website" -ForegroundColor Cyan
        Write-Host ""
        $choice = Read-Host "  Enter choice (1-2)"

        if ($choice -eq "1") {
            Write-Host ""
            Write-Host "  Initializing git repository..." -ForegroundColor Yellow

            # Initialize git
            $initResult = git init 2>&1
            Write-Host "  $initResult" -ForegroundColor Gray

            # Add remote
            Write-Host "  Connecting to GitHub..." -ForegroundColor Yellow
            $remoteResult = git remote add origin "https://github.com/domin0z/RemoteAccessScanner.git" 2>&1

            # Pull existing content first
            Write-Host "  Syncing with GitHub..." -ForegroundColor Yellow
            git fetch origin 2>&1 | Out-Null
            git branch -M main 2>&1 | Out-Null

            # Try to set upstream and pull
            git pull origin main --allow-unrelated-histories 2>&1 | Out-Null

            $isGitRepo = $true
        } else {
            Show-ManualUploadInstructions
            Pop-Location
            return
        }
    }

    # Now try to push
    Write-Host ""
    Write-Host "  Adding signatures.json to git..." -ForegroundColor Yellow
    $addResult = git add signatures.json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Error adding file: $addResult" -ForegroundColor Red
        Show-ManualUploadInstructions
        Pop-Location
        return
    }

    Write-Host "  Creating commit..." -ForegroundColor Yellow
    $commitMsg = "Updated signatures - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $commitResult = git commit -m $commitMsg 2>&1

    if ($commitResult -match "nothing to commit") {
        Write-Host ""
        Write-Host "  No changes to push - signatures.json is already up to date." -ForegroundColor Green
        Pop-Location
        return
    }

    if ($LASTEXITCODE -ne 0 -and $commitResult -notmatch "nothing to commit") {
        Write-Host "  Error creating commit: $commitResult" -ForegroundColor Red
        Show-ManualUploadInstructions
        Pop-Location
        return
    }

    Write-Host "  Pushing to GitHub..." -ForegroundColor Yellow
    $pushResult = git push -u origin main 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "  Push failed: $pushResult" -ForegroundColor Red
        Write-Host ""
        Write-Host "  This might be because:" -ForegroundColor Yellow
        Write-Host "    - You need to authenticate with GitHub" -ForegroundColor Gray
        Write-Host "    - The remote has changes you don't have locally" -ForegroundColor Gray
        Write-Host ""
        Show-ManualUploadInstructions
    } else {
        Write-Host ""
        Write-Host "  Successfully pushed to GitHub!" -ForegroundColor Green
        Write-Host "  Your changes are now live." -ForegroundColor White
        Write-Host ""
        Write-Host "  Scanners using option [4] will now get this update." -ForegroundColor Cyan
    }

    Pop-Location
}

function Show-ManualUploadInstructions {
    Write-Host ""
    Write-Host "  --- MANUAL UPLOAD INSTRUCTIONS ---" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open: https://github.com/domin0z/RemoteAccessScanner" -ForegroundColor White
    Write-Host "  2. Click on 'signatures.json'" -ForegroundColor White
    Write-Host "  3. Click the pencil icon (Edit this file)" -ForegroundColor White
    Write-Host "  4. Select all and delete the content" -ForegroundColor White
    Write-Host "  5. Open your local file and copy all content:" -ForegroundColor White
    Write-Host "     $Script:SignatureFile" -ForegroundColor Cyan
    Write-Host "  6. Paste into GitHub" -ForegroundColor White
    Write-Host "  7. Click 'Commit changes'" -ForegroundColor White
    Write-Host ""
    Write-Host "  TIP: Press Ctrl+A to select all, Ctrl+C to copy, Ctrl+V to paste" -ForegroundColor Gray
}

# ============================================================================
# MAIN MENU
# ============================================================================

function Show-MainMenu {
    Write-Banner

    Write-Host "  What would you like to do?" -ForegroundColor White
    Write-Host ""
    Write-Host "    [1] Scan for New Threats (search all sources)" -ForegroundColor Cyan
    Write-Host "    [2] Search FRST Log Analyses (BC & MB forums)" -ForegroundColor Yellow
    Write-Host "    [3] Research Specific Tool" -ForegroundColor Cyan
    Write-Host "    [4] Add New Signature Manually" -ForegroundColor Cyan
    Write-Host "    [5] View Current Signatures" -ForegroundColor Cyan
    Write-Host "    [6] Push Updates to GitHub" -ForegroundColor Yellow
    Write-Host "    [7] Exit" -ForegroundColor Cyan
    Write-Host ""

    $choice = Read-Host "  Enter choice (1-7)"

    switch ($choice) {
        "1" {
            Search-ForNewThreats
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "2" {
            Search-FRSTLogs
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "3" {
            Search-SpecificTool
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "4" {
            Add-SignatureInteractive
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "5" {
            Show-CurrentSignatures
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "6" {
            Push-ToGitHub
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu
        }
        "7" {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Green
            exit
        }
        default {
            Write-Host "  Invalid choice." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-MainMenu
        }
    }
}

# ============================================================================
# START
# ============================================================================

# Initialize log
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $Script:ResearchLogFile -Value "`n========== Research Session: $timestamp =========="

Show-MainMenu
