#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ReconBlock v1.0 - Advanced Reconnaissance and Brute Force Protection
.DESCRIPTION
    Enterprise-grade security automation with Telegram alerts
.AUTHOR
    Harshit Sharma
.VERSION
    1.0
#>

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   ReconBlock v1.0" -ForegroundColor Cyan
Write-Host "   Advanced Security Protection" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Installation confirmation
Write-Host "This will install ReconBlock security system on your computer." -ForegroundColor Yellow
Write-Host ""
Write-Host "Features:" -ForegroundColor White
Write-Host "  - Automatic brute force attack detection and blocking" -ForegroundColor Gray
Write-Host "  - Reconnaissance scan detection and blocking" -ForegroundColor Gray
Write-Host "  - Real-time IP blocking via Windows Firewall" -ForegroundColor Gray
Write-Host "  - Instant Telegram notifications on attacks" -ForegroundColor Gray
Write-Host "  - Automatic log rotation (max 5000 lines)" -ForegroundColor Gray
Write-Host "  - Scheduled monitoring every 5 minutes" -ForegroundColor Gray
Write-Host ""
Write-Host "Installation path: C:\ReconBlock" -ForegroundColor Gray
Write-Host ""

do {
    $confirmation = Read-Host "Do you want to proceed with installation? (Y/N)"
    $confirmation = $confirmation.ToUpper()
} while ($confirmation -ne 'Y' -and $confirmation -ne 'N')

if ($confirmation -eq 'N') {
    Write-Host ""
    Write-Host "Installation cancelled by user." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit
}

Write-Host ""
Write-Host "Starting installation..." -ForegroundColor Green
Write-Host ""

$InstallPath = "C:\ReconBlock"

# ====================================================================
# DETECTION SCRIPT (v1.2 - OPTIMIZED)
# ====================================================================

$detectionScript = @'
$ErrorActionPreference = "Continue"

# Configuration
$Config = @{
    BruteForceThreshold = 5
    ReconThreshold = 10
    TimeWindow = 10
    LogPath = "C:\ReconBlock\Logs\detection.log"
    BlocksLogPath = "C:\ReconBlock\Logs\blocks.log"
    WhitelistPath = "C:\ReconBlock\Config\whitelist.txt"
    TelegramConfigPath = "C:\ReconBlock\Config\telegram.json"
    MaxLogLines = 5000
}

# PERFORMANCE: Regex compiled once for reuse
$script:ipRegex = [regex]::new('\d+\.\d+\.\d+\.\d+', [System.Text.RegularExpressions.RegexOptions]::Compiled)

# ========================================
# FUNCTION DEFINITIONS (Must be before use!)
# ========================================

function Write-DetectionLog {
    param([string]$Message)
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $Config.LogPath -Value "$timestamp | $Message" -Force -ErrorAction Stop
    }
    catch {
        # Silent fail if logging fails - don't stop detection
    }
}

function Invoke-LogRotation {
    param([string]$LogPath, [int]$MaxLines = 5000)
    
    try {
        if (Test-Path $LogPath -PathType Leaf) {
            $lines = Get-Content $LogPath -ErrorAction SilentlyContinue
            if ($lines.Count -gt $MaxLines) {
                $lines[-$MaxLines..-1] | Set-Content $LogPath -Force
                Write-DetectionLog "Log rotated: $LogPath trimmed to $MaxLines lines"
            }
        }
    }
    catch {
        Write-DetectionLog "Log rotation error: $_"
    }
}

function Send-TelegramAlert {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('BruteForce', 'Reconnaissance')]
        [string]$AlertType,
        
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$IP,
        
        [Parameter(Mandatory=$true)]
        [int]$Count,
        
        [Parameter(Mandatory=$true)]
        [string]$Port
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Build message based on type
        if ($AlertType -eq 'BruteForce') {
            $icon = "[ALERT]¨"
            $title = "BRUTE FORCE ATTACK BLOCKED"
            $threatType = "Brute Force Attack"
            $portLabel = "Target Port"
            $countLabel = "Failed Login Attempts"
        }
        else {
            $icon = "🔍"
            $title = "RECONNAISSANCE ATTACK BLOCKED"
            $threatType = "Port Scanning / Reconnaissance"
            $portLabel = "Scanned Ports"
            $countLabel = "Scan Attempts"
        }
        
        $message = "$icon `<b>$title`</b>%0A%0A" +
                   "[!] `<b>Threat Type:`</b> $threatType%0A" +
                   "[X] `<b>Blocked IP:`</b> `<code>$IP`</code>%0A" +
                   "[P] `<b>${portLabel}:`</b> $Port%0A" +
                   "[#] `<b>${countLabel}:`</b> $Count%0A" +
                   "- `<b>Detection Time:`</b> $timestamp%0A%0A" +
                   "[OK] `<b>Status:`</b> IP automatically blocked via Windows Firewall"
        
        # PERFORMANCE: Set TLS once outside function calls
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        
        $uri = "https://api.telegram.org/bot$($TelegramConfig.BotToken)/sendMessage?chat_id=$($TelegramConfig.ChatID)`&text=$message`&parse_mode=html"
        Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 5 -ErrorAction Stop | Out-Null
        
        Write-DetectionLog "Telegram alert sent: $AlertType for $IP"
    }
    catch {
        Write-DetectionLog "Telegram alert failed: $_"
    }
}

function Send-WelcomeMessage {
    param([string]$ChatID)
    
    # Skip if telegram not configured
    if (-not $TelegramConfig -or -not $TelegramConfig.BotToken) {
        return
    }
    
    try {
        $message = "🛡️ `<b>ReconBlock Security Bot Activated`</b>%0A%0A" +
                   "[OK]✓ Your ReconBlock protection is now `<code>ACTIVE`</code>%0A%0A" +
                   "📋 You will receive alerts for:%0A" +
                   "   • Brute Force Attacks%0A" +
                   "   • Reconnaissance Scans%0A" +
                   "   • Blocked IPs%0A%0A" +
                   "⚡️ `<b>Protection Status:`</b> Running every 5 minutes"
        
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $uri = "https://api.telegram.org/bot$($TelegramConfig.BotToken)/sendMessage?chat_id=$ChatID`&text=$message`&parse_mode=html"
        Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 5 -ErrorAction Stop | Out-Null
    }
    catch { }
}

function Test-ValidIP {
    param([string]$IP)
    
    if (-not $IP -or $IP -eq '' -or $IP -eq '-') {
        return $false
    }
    
    # PERFORMANCE: Use compiled regex
    return $script:ipRegex.IsMatch($IP)
}

function Get-PublicIP {
    # Cache public IP to avoid repeated API calls
    if ($script:CachedPublicIP) {
        return $script:CachedPublicIP
    }
    
    try {
        $publicIP = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 3 -ErrorAction Stop).Trim()
        if ($publicIP -match '\d+\.\d+\.\d+\.\d+') {
            $script:CachedPublicIP = $publicIP
            Write-DetectionLog "Public IP detected and whitelisted: $publicIP"
            return $publicIP
        }
    }
    catch {
        # If can't get public IP, continue without it
    }
    
    return $null
}

function Test-WhitelistedIP {
    param([string]$IP)
    
    # Auto-whitelist localhost and loopback addresses
    $localhostIPs = @('127.0.0.1', '::1', 'localhost')
    if ($IP -in $localhostIPs) {
        return $true
    }
    
    # Auto-whitelist private IP ranges (RFC 1918)
    if ($IP -match '^10\.') { return $true }
    if ($IP -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($IP -match '^192\.168\.') { return $true }
    
    # Auto-whitelist system's own IPs
    try {
        $systemIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
        if ($IP -in $systemIPs) {
            return $true
        }
    }
    catch {
        # If can't get system IPs, continue
    }
    
    # Auto-whitelist system's public IP
    $publicIP = Get-PublicIP
    if ($publicIP -and $IP -eq $publicIP) {
        return $true
    }
    
    # Check manual whitelist file
    try {
        if (Test-Path $Config.WhitelistPath -PathType Leaf) {
            $manualWhitelist = @(Get-Content $Config.WhitelistPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' })
            if ($IP -in $manualWhitelist) {
                return $true
            }
        }
    }
    catch {
        # If can't read whitelist file, continue
    }
    
    return $false
}

function Block-MaliciousIP {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IP,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('BruteForce', 'Reconnaissance')]
        [string]$Type,
        
        [Parameter(Mandatory=$true)]
        [int]$Count,
        
        [Parameter(Mandatory=$false)]
        [string]$Port = "Multiple Ports"
    )
    
    # Validate IP format
    if (-not (Test-ValidIP -IP $IP)) {
        Write-DetectionLog "ERROR: Invalid IP format: $IP"
        return
    }
    
    try {
        $ruleName = "ReconBlock_${Type}_$($IP -replace '\.', '_')"
        
        # PERFORMANCE: Use -DisplayName exact match instead of wildcard
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if (-not $existingRule) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            # Create inbound and outbound block rules
            New-NetFirewallRule -DisplayName $ruleName `
                               -Direction Inbound `
                               -Action Block `
                               -RemoteAddress $IP `
                               -Description "Blocked $timestamp Count $Count" `
                               -Enabled True `
                               -Profile Any `
                               -ErrorAction Stop | Out-Null
                               
            New-NetFirewallRule -DisplayName "${ruleName}_Out" `
                               -Direction Outbound `
                               -Action Block `
                               -RemoteAddress $IP `
                               -Description "Blocked $timestamp Count $Count" `
                               -Enabled True `
                               -Profile Any `
                               -ErrorAction Stop | Out-Null
            
            # Format attack type
            $attackType = if ($Type -eq "BruteForce") {"Brute Force"} else {"Reconnaissance"}
            $portInfo = if ($Type -eq "BruteForce") {"3389 (RDP)"} else {$Port}
            
            # Write to blocks.log
            $logEntry = "$timestamp | BLOCKED | Type: $attackType | IP: $IP | Port: $portInfo | Attempts: $Count"
            Add-Content -Path $Config.BlocksLogPath -Value $logEntry -Force -ErrorAction Stop
            
            Write-DetectionLog "$attackType attack blocked: $IP (Port: $portInfo, Attempts: $Count)"
            
            # Send Telegram alert
            Send-TelegramAlert -AlertType $Type -IP $IP -Count $Count -Port $portInfo
        }
        else {
            Write-DetectionLog "IP $IP already blocked, skipping"
        }
    }
    catch {
        Write-DetectionLog "ERROR blocking $IP : $_"
    }
}

# =========================================
# INITIALIZATION
# =========================================

# Load telegram config if exists (optional)
$TelegramConfig = $null
try {
    if (Test-Path $Config.TelegramConfigPath -PathType Leaf) {
        $TelegramConfig = Get-Content $Config.TelegramConfigPath -ErrorAction Stop | ConvertFrom-Json
        Write-DetectionLog "Telegram config loaded: Chat ID $($TelegramConfig.ChatID)"
    }
}
catch {
    Write-DetectionLog "Telegram config not found or invalid - alerts disabled"
}

# Rotate logs before starting
Invoke-LogRotation -LogPath $Config.LogPath -MaxLines $Config.MaxLogLines
Invoke-LogRotation -LogPath $Config.BlocksLogPath -MaxLines $Config.MaxLogLines

Write-DetectionLog "=== Detection cycle started (v1.0) ==="

# PERFORMANCE: Set TLS once for all Telegram calls
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Brute Force Detection (Event ID 4625)
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue
    
    if ($events -and $events.Count -gt 0) {
        $cutoffTime = (Get-Date).AddMinutes(-$Config.TimeWindow)
        
        # PERFORMANCE: Filter once, not in pipeline
        $recentEvents = @($events | Where-Object { $_.TimeCreated -gt $cutoffTime })
        
        if ($recentEvents.Count -gt 0) {
            # PERFORMANCE: Use hashtable for grouping instead of Group-Object
            $ipCounts = @{}
            
            foreach ($event in $recentEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $ip = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
                    $username = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    
                    if ($ip -match '\d+\.\d+\.\d+\.\d+' -and -not (Test-WhitelistedIP -IP $ip)) {
                        # Group by IP only
                        if (-not $ipCounts.ContainsKey($ip)) {
                            $ipCounts[$ip] = @{ Count = 0; Usernames = @() }
                        }
                        $ipCounts[$ip].Count++
                        
                        # Track unique usernames for this IP
                        if ($username -and $username -notin $ipCounts[$ip].Usernames) {
                            $ipCounts[$ip].Usernames += $username
                        }
                    }
                }
                catch { continue }
            }
            
            # Block IPs with attack patterns
            foreach ($ip in $ipCounts.Keys) {
                $attempts = $ipCounts[$ip].Count
                $uniqueUsers = $ipCounts[$ip].Usernames.Count
                
                # Real brute force: 5+ attempts with 2+ usernames OR 10+ attempts total
                if (($attempts -ge 5 -and $uniqueUsers -ge 2) -or $attempts -ge 10) {
                    Block-MaliciousIP -IP $ip -Type "BruteForce" -Count $attempts -Port "3389 (RDP)"
                    Write-DetectionLog "Brute force: $ip - $attempts attempts on $uniqueUsers users"
                }
            }
        }
    }
}
catch {
    Write-DetectionLog "Brute Force detection error: $_"
}


# FIXED: Reconnaissance Detection (Event ID 5156 - Windows Filtering Platform)
try {
    $cutoffTime = (Get-Date).AddSeconds(-30)
    $reconEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=$cutoffTime} -MaxEvents 500 -ErrorAction SilentlyContinue
    
    if ($reconEvents) {
        $reconData = @{}
        
        foreach ($event in $reconEvents) {
            try {
                $xml = [xml]$event.ToXml()
                $sourceIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceAddress'}).'#text'
                $destPort = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestPort'}).'#text'
                $time = $event.TimeCreated
                
                if ($sourceIP -match '\d+\.\d+\.\d+\.\d+' -and -not (Test-WhitelistedIP -IP $sourceIP)) {
                    if (-not $reconData.ContainsKey($sourceIP)) {
                        $reconData[$sourceIP] = @{
                            UniquePorts = @()
                            TotalConnections = 0
                            FirstSeen = $time
                        }
                    }
                    
                    # Track unique ports
                    if ($destPort -and $destPort -notin $reconData[$sourceIP].UniquePorts) {
                        $reconData[$sourceIP].UniquePorts += $destPort
                    }
                    $reconData[$sourceIP].TotalConnections++
                }
            }
            catch { continue }
        }
        
        # Block IPs scanning multiple ports (real port scan behavior)
        foreach ($ip in $reconData.Keys) {
            $uniquePortCount = $reconData[$ip].UniquePorts.Count
            $totalConnections = $reconData[$ip].TotalConnections
            
            # Real reconnaissance: 5+ unique ports OR 15+ connections to different ports
            if ($uniquePortCount -ge 5 -or ($uniquePortCount -ge 3 -and $totalConnections -ge 15)) {
                $ports = $reconData[$ip].UniquePorts -join ", "
                Block-MaliciousIP -IP $ip -Type "Reconnaissance" -Count $uniquePortCount -Port "Ports: $ports"
                Write-DetectionLog "Reconnaissance detected: $ip scanned $uniquePortCount unique ports"
            }
        }
    }
}
catch {
    Write-DetectionLog "Reconnaissance detection error: $_"
}

Write-DetectionLog "=== Detection cycle completed ==="

# Send welcome message on first run (one-time only)
$welcomeFile = "C:\ReconBlock\Logs\welcome_sent.flag"
if (-not (Test-Path $welcomeFile -PathType Leaf)) {
    Send-WelcomeMessage -ChatID $TelegramConfig.ChatID
    try {
        New-Item -Path $welcomeFile -ItemType File -Force -ErrorAction Stop | Out-Null
        Write-DetectionLog "Welcome message sent to Chat ID: $($TelegramConfig.ChatID)"
    }
    catch {
        Write-DetectionLog "Failed to create welcome flag file: $_"
    }
}
'@

# ====================================================================
# MANAGEMENT SCRIPT (v1.0)
# ====================================================================

$managementScript = @'
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("view", "logs", "unblock", "stats", "status", "report", "whitelist", "telegram-bot")]
    [string]$Action = "view"
)

$ErrorActionPreference = "Continue"

Clear-Host
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   ReconBlock v1.0 Management Console" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

switch ($Action) {
    "view" {
        try {
            # Query all ReconBlock rules (both Inbound and Outbound)
            $rules = @(Get-NetFirewallRule -DisplayName "ReconBlock*" -ErrorAction SilentlyContinue)
            
            $bruteForceIPs = @()
            $reconIPs = @()
            
            foreach ($rule in $rules) {
                # Only process Inbound rules (skip _Out suffix rules)
                if ($rule.Direction -ne "Inbound") {
                    continue
                }
                
                if ($rule.DisplayName -match "ReconBlock_([^_]+)_(.+)") {
                    $type = $matches[1]
                    $ip = $matches[2] -replace "_", "."
                    $count = if ($rule.Description -match "Count (\d+)") {$matches[1]} else {"N/A"}
                    $datetime = if ($rule.Description -match "(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})") {$matches[1]} `
                                elseif ($rule.Description -match "(\d{4}-\d{2}-\d{2})") {$matches[1]} `
                                else {"Unknown"}
                    
                    if ($type -eq "BruteForce") {
                        $bruteForceIPs += [PSCustomObject]@{IP=$ip; Port="3389 (RDP)"; Attempts=$count; DateTime=$datetime}
                    } 
                    elseif ($type -eq "Reconnaissance") {
                        $reconIPs += [PSCustomObject]@{IP=$ip; Ports="Multiple Ports"; Attempts=$count; DateTime=$datetime}
                    }
                }
            }
            
            Write-Host "BRUTE FORCE ATTACKS" -ForegroundColor Red
            Write-Host "===================" -ForegroundColor Red
            Write-Host ""
            
            if ($bruteForceIPs.Count -gt 0) {
                foreach ($entry in $bruteForceIPs) {
                    Write-Host "  Blocked IP:      " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.IP)" -ForegroundColor White
                    Write-Host "  Target Port:     " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.Port)" -ForegroundColor White
                    Write-Host "  Failed Logins:   " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.Attempts)" -ForegroundColor White
                    Write-Host "  Attack Time:     " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.DateTime)" -ForegroundColor White
                    Write-Host "  Status:          " -NoNewline -ForegroundColor Yellow
                    Write-Host "BLOCKED" -ForegroundColor Red
                    Write-Host ""
                }
                Write-Host "  Total Brute Force Blocks: $($bruteForceIPs.Count)" -ForegroundColor Red
            } 
            else {
                Write-Host "  No brute force attacks detected" -ForegroundColor Green
            }
            
            Write-Host ""
            Write-Host "=========================================" -ForegroundColor Cyan
            Write-Host ""
            
            Write-Host "RECONNAISSANCE ATTACKS" -ForegroundColor Magenta
            Write-Host "======================" -ForegroundColor Magenta
            Write-Host ""
            
            if ($reconIPs.Count -gt 0) {
                foreach ($entry in $reconIPs) {
                    Write-Host "  Blocked IP:      " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.IP)" -ForegroundColor White
                    Write-Host "  Scanned Ports:   " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.Ports)" -ForegroundColor White
                    Write-Host "  Scan Attempts:   " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.Attempts)" -ForegroundColor White
                    Write-Host "  Attack Time:     " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($entry.DateTime)" -ForegroundColor White
                    Write-Host "  Status:          " -NoNewline -ForegroundColor Yellow
                    Write-Host "BLOCKED" -ForegroundColor Red
                    Write-Host ""
                }
                Write-Host "  Total Reconnaissance Blocks: $($reconIPs.Count)" -ForegroundColor Magenta
            } 
            else {
                Write-Host "  No reconnaissance attacks detected" -ForegroundColor Green
            }
            
            Write-Host ""
            Write-Host "=========================================" -ForegroundColor Cyan
            Write-Host ""
            
            $totalBlocks = $bruteForceIPs.Count + $reconIPs.Count
            Write-Host "SUMMARY" -ForegroundColor Cyan
            Write-Host "=======" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Total Blocked IPs:     $totalBlocks" -ForegroundColor White
            Write-Host "  Brute Force Blocks:    $($bruteForceIPs.Count)" -ForegroundColor Red
            Write-Host "  Reconnaissance Blocks: $($reconIPs.Count)" -ForegroundColor Magenta
            Write-Host "  Protection Status:     " -NoNewline -ForegroundColor White
            Write-Host "ACTIVE" -ForegroundColor Green
            Write-Host ""
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve blocked IPs: $_" -ForegroundColor Red
            Write-Host ""
        }
    }
    
    "logs" {
        try {
            if (Test-Path "C:\ReconBlock\Logs\blocks.log" -PathType Leaf) {
                Write-Host "Recent Blocks (Last 20):" -ForegroundColor Yellow
                Write-Host ""
                
                $logLines = Get-Content "C:\ReconBlock\Logs\blocks.log" -Tail 20 -ErrorAction Stop
                
                foreach ($line in $logLines) {
                    if ($line -match "Brute Force") {
                        Write-Host $line -ForegroundColor Red
                    } 
                    elseif ($line -match "Reconnaissance") {
                        Write-Host $line -ForegroundColor Magenta
                    } 
                    else {
                        Write-Host $line -ForegroundColor White
                    }
                }
            } 
            else {
                Write-Host "No log file found" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] Failed to read log file: $_" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    "unblock" {
        Write-Host "Enter IP address to unblock:" -ForegroundColor Yellow
        $ip = Read-Host
        
        # Validate IP format
        if ($ip -match '^\d+\.\d+\.\d+\.\d+$') {
            try {
                $escapedIP = $ip -replace '\.', '_'
                $rules = @(Get-NetFirewallRule -DisplayName "*$escapedIP*" -ErrorAction SilentlyContinue)
                
                if ($rules.Count -gt 0) {
                    foreach ($rule in $rules) {
                        Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop
                    }
                    Write-Host ""
                    Write-Host "[OK] IP $ip unblocked successfully ($($rules.Count) rules removed)" -ForegroundColor Green
                    
                    # Log the unblock action
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $logEntry = "$timestamp | UNBLOCKED | IP: $ip | Action: Manual unblock by administrator"
                    Add-Content -Path "C:\ReconBlock\Logs\blocks.log" -Value $logEntry -Force -ErrorAction SilentlyContinue
                } 
                else {
                    Write-Host ""
                    Write-Host "[WARNING] No firewall rules found for IP $ip" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host ""
                Write-Host "[ERROR] Failed to unblock IP: $_" -ForegroundColor Red
            }
        } 
        else {
            Write-Host ""
            Write-Host "[ERROR] Invalid IP address format (use: xxx.xxx.xxx.xxx)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    "stats" {
        try {
            $task = Get-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
            $taskInfo = Get-ScheduledTaskInfo -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
            $rules = @(Get-NetFirewallRule -DisplayName "ReconBlock*" -ErrorAction SilentlyContinue)
            $uniqueIPs = @($rules | Where-Object { $_.Direction -eq "Inbound" }).Count
            
            Write-Host "SYSTEM STATISTICS" -ForegroundColor Cyan
            Write-Host "=================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Total Firewall Rules:   $($rules.Count)" -ForegroundColor White
            Write-Host "  Unique Blocked IPs:     $uniqueIPs" -ForegroundColor White
            Write-Host "  Task Status:            $($task.State)" -ForegroundColor $(if($task.State -eq "Ready"){"Green"}else{"Red"})
            Write-Host "  Last Run Time:          $($taskInfo.LastRunTime)" -ForegroundColor White
            Write-Host "  Next Run Time:          $($taskInfo.NextRunTime)" -ForegroundColor White
            Write-Host "  Detection Interval:     5 minutes" -ForegroundColor White
            Write-Host "  Telegram Alerts:        Enabled [OK]" -ForegroundColor Green
            Write-Host "  Log Rotation:           Enabled [OK]" -ForegroundColor Green
            Write-Host "  Version:                1.0" -ForegroundColor Cyan
            Write-Host ""
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve statistics: $_" -ForegroundColor Red
            Write-Host ""
        }
    }
    
    "status" {
        try {
            $task = Get-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
            Write-Host "ReconBlock Protection Status: " -NoNewline
            if ($task -and $task.State -eq "Ready") {
                Write-Host "RUNNING" -ForegroundColor Green
            } 
            else {
                Write-Host "STOPPED" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "UNKNOWN (Error: $_)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    "report" {
        try {
            Write-Host "" 
            Write-Host "Generating Security Report (Last 12 Hours)..." -ForegroundColor Cyan
            Write-Host "This may take a few moments..." -ForegroundColor Gray
            Write-Host ""
            
            # Collect data from last 12 hours
            $cutoff = (Get-Date).AddHours(-12)
            $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $fileName = "Security_Report_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
            $reportsDir = "C:\ReconBlock\Reports"
            
            # Create Reports directory if it doesn't exist
            if (-not (Test-Path $reportsDir -PathType Container)) {
                New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
            }
            
            Write-Host "[+] Collecting brute force attempts..." -ForegroundColor Yellow
            
            # Detect public IP once (cache for performance)
            $publicIP = $null
            try {
                $publicIP = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 3 -ErrorAction Stop).Trim()
                if ($publicIP -and $publicIP -match '\d+\.\d+\.\d+\.\d+') {
                    Write-Host "    Detected public IP: $publicIP " -ForegroundColor Gray
                } else {
                    $publicIP = $null
                }
            }
            catch { 
                Write-Host "    Could not detect public IP (skipping auto-filter)" -ForegroundColor Yellow
                $publicIP = $null
            }
            
            # Collect Brute Force Data
            $bruteForceData = @()
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$cutoff} -MaxEvents 1000 -ErrorAction SilentlyContinue
                Write-Host "    Found $($events.Count) brute force events" -ForegroundColor Gray
                $attempts = @{}
                
                foreach ($event in $events) {
                    try {
                        $xml = [xml]$event.ToXml()
                        $ip = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
                        $username = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                        $time = $event.TimeCreated
                        
                        if ($ip -match '\d+\.\d+\.\d+\.\d+' -and $username) {
                            # Skip whitelisted IPs from report
                            if ($ip -eq '127.0.0.1' -or $ip -match '^10\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' -or $ip -match '^192\.168\.') {
                                continue
                            }
                            
                            # Skip public IP if detected
                            if ($publicIP -and $ip.Trim() -eq $publicIP) {
                                continue
                            }
                            
                            $key = "$ip|$username"
                            if (-not $attempts.ContainsKey($key)) {
                                $attempts[$key] = @{
                                    IP = $ip
                                    Username = $username
                                    Port = "3389 (RDP)"
                                    Count = 0
                                    FirstSeen = $time
                                    LastSeen = $time
                                }
                            }
                            $attempts[$key].Count++
                            if ($time -lt $attempts[$key].FirstSeen) { $attempts[$key].FirstSeen = $time }
                            if ($time -gt $attempts[$key].LastSeen) { $attempts[$key].LastSeen = $time }
                        }
                    }
                    catch { continue }
                }
                
                $bruteForceData = @($attempts.Values | Sort-Object -Property Count -Descending | Sort-Object -Property LastSeen -Descending)
            }
            catch {
                Write-Host "    [WARNING] Failed to collect brute force data" -ForegroundColor Yellow
            }
            
            Write-Host "[+] Collecting reconnaissance scans..." -ForegroundColor Yellow
            
            # Collect Reconnaissance Data  
            $reconData = @()
            try {
                $reconEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=$cutoff} -MaxEvents 2000 -ErrorAction SilentlyContinue
                Write-Host "    Found $($reconEvents.Count) reconnaissance events" -ForegroundColor Gray
                $scans = @{}
                
                foreach ($event in $reconEvents) {
                    try {
                        $xml = [xml]$event.ToXml()
                        $sourceIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceAddress'}).'#text'
                        $destPort = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestPort'}).'#text'
                        $time = $event.TimeCreated
                        
                        if ($sourceIP -match '\d+\.\d+\.\d+\.\d+') {
                            # Skip whitelisted IPs from report
                            if ($sourceIP -eq '127.0.0.1' -or $sourceIP -match '^10\.' -or $sourceIP -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' -or $sourceIP -match '^192\.168\.') {
                                continue
                            }
                            
                            # Skip public IP if detected (use cached value)
                            if ($publicIP -and $sourceIP.Trim() -eq $publicIP) {
                                continue
                            }
                            
                            if (-not $scans.ContainsKey($sourceIP)) {
                                $scans[$sourceIP] = @{
                                    IP = $sourceIP
                                    Ports = @()
                                    Count = 0
                                    FirstSeen = $null
                                    LastSeen = $null
                                }
                            }
                            
                            # Track unique ports
                            if ($destPort -and $destPort -notin $scans[$sourceIP].Ports) {
                                $scans[$sourceIP].Ports += $destPort
                            }
                            
                            $scans[$sourceIP].Count++
                            if ($null -eq $scans[$sourceIP].FirstSeen) {
                                $scans[$sourceIP].FirstSeen = $time
                            }
                            $scans[$sourceIP].LastSeen = $time
                        }
                    }
                    catch { continue }
                }
                
                # Only include IPs that meet reconnaissance threshold (real port scans)
                $filteredScans = $scans.Values | Where-Object {
                    $uniquePorts = $_.Ports.Count
                    $totalConn = $_.Count
                    # Same logic as detection: 5+ unique ports OR 3+ ports with 15+ connections
                    ($uniquePorts -ge 5) -or ($uniquePorts -ge 3 -and $totalConn -ge 15)
                }
                
                $reconData = @($filteredScans | Sort-Object {$_.Ports.Count} -Descending | Sort-Object -Property Count -Descending)
            }
            catch {
                Write-Host "    [WARNING] Failed to collect reconnaissance data" -ForegroundColor Yellow
            }
            
            Write-Host "[+] Collecting blocked IPs..." -ForegroundColor Yellow
            
            # Collect Blocked IPs
            $blockedIPs = @()
            try {
                $rules = Get-NetFirewallRule -DisplayName "ReconBlock*" -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq "Inbound" }
                foreach ($rule in $rules) {
                    if ($rule.DisplayName -match "ReconBlock_([^_]+)_(.+)") {
                        $type = $matches[1]
                        $ip = $matches[2] -replace "_", "."
                        $datetime = if ($rule.Description -match "(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})") {$matches[1]} else {"Unknown"}
                        $count = if ($rule.Description -match "Count (\d+)") {$matches[1]} else {"N/A"}
                        
                        $blockedIPs += [PSCustomObject]@{
                            IP = $ip
                            Reason = if ($type -eq "BruteForce") {"Brute Force Attack"} else {"Reconnaissance Scan"}
                            BlockTime = $datetime
                            Attempts = $count
                        }
                    }
                }
            }
            catch {
                Write-Host "    [WARNING] Failed to collect blocked IPs" -ForegroundColor Yellow
            }
            
            Write-Host "[+] Generating HTML report..." -ForegroundColor Yellow
            
            # Generate HTML Report
            $totalBruteForce = $bruteForceData.Count
            $totalRecon = $reconData.Count  
            $totalBlocked = $blockedIPs.Count
            $totalAttempts = ($bruteForceData | Measure-Object -Property Count -Sum).Sum
            if (-not $totalAttempts) { $totalAttempts = 0 }
            
            # Build brute force table rows
            $bruteForceRows = ""
            if ($totalBruteForce -gt 0) {
                foreach ($item in $bruteForceData) {
                    $bruteForceRows += @"
                    <tr>
                        <td><span class="ip-badge">$($item.IP)</span></td>
                        <td><span class="username">$($item.Username)</span></td>
                        <td>$($item.Port)</td>
                        <td><span class="count-badge">$($item.Count)</span></td>
                        <td>$($item.LastSeen.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    </tr>
"@
                }
            } else {
                $bruteForceRows = '<tr><td colspan="5" class="no-data">No brute force attempts in the last 12 hours</td></tr>'
            }
            
            # Build reconnaissance table rows
            $reconRows = ""
            if ($totalRecon -gt 0) {
                foreach ($item in $reconData) {
                    $portsStr = if ($item.Ports.Count -gt 0) { ($item.Ports -join ', ') } else { 'Unknown' }
                    if ($portsStr.Length -gt 50) { $portsStr = $portsStr.Substring(0, 47) + '...' }
                    $reconRows += @"
                    <tr>
                        <td><span class="ip-badge">$($item.IP)</span></td>
                        <td class="ports">$portsStr</td>
                        <td><span class="count-badge">$($item.Count)</span></td>
                        <td>$($item.LastSeen.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    </tr>
"@
                }
            } else {
                $reconRows = '<tr><td colspan="4" class="no-data">No reconnaissance scans in the last 12 hours</td></tr>'
            }
            
            # Build blocked IPs table rows
            $blockedRows = ""
            if ($totalBlocked -gt 0) {
                foreach ($item in $blockedIPs) {
                    $reasonClass = if ($item.Reason -like "*Brute*") { "reason-brute" } else { "reason-recon" }
                    $blockedRows += @"
                    <tr>
                        <td><span class="ip-badge">$($item.IP)</span></td>
                        <td><span class="$reasonClass">$($item.Reason)</span></td>
                        <td>$($item.BlockTime)</td>
                        <td><span class="count-badge">$($item.Attempts)</span></td>
                        <td><span class="status-blocked">BLOCKED</span></td>
                    </tr>
"@
                }
            } else {
                $blockedRows = '<tr><td colspan="5" class="no-data">No IPs currently blocked</td></tr>'
            }
            
            # Complete HTML with inline CSS
            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconBlock Security Report - $reportDate</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Roboto, 'Courier New', monospace; background: #0a0e27; min-height: 100vh; padding: 20px; color: #e0e0e0; }
        .container { max-width: 1600px; margin: 0 auto; }
        .brand-header { background: linear-gradient(135deg, #1a1f3a 0%, #0d1117 100%); border: 1px solid #00ff88; border-radius: 8px 8px 0 0; padding: 25px 40px; box-shadow: 0 0 30px rgba(0,255,136,0.3); text-align: center; position: relative; overflow: hidden; }
        .brand-header::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, #00ff88, #00d4ff, #ff00ff, #00ff88); animation: glow 3s linear infinite; }
        @keyframes glow { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .brand-logo { font-size: 42px; font-weight: 900; color: #00ff88; letter-spacing: 3px; margin-bottom: 5px; text-shadow: 0 0 20px rgba(0,255,136,0.8), 0 0 40px rgba(0,255,136,0.4); font-family: 'Courier New', monospace; }
        .brand-tagline { color: #00d4ff; font-size: 11px; text-transform: uppercase; letter-spacing: 4px; font-weight: 600; text-shadow: 0 0 10px rgba(0,212,255,0.6); }
        .report-header { background: #151b2e; border: 1px solid #2a3f5f; border-top: none; border-radius: 0 0 8px 8px; padding: 20px 40px; margin-bottom: 20px; box-shadow: 0 5px 20px rgba(0,0,0,0.5); }
        .report-title { color: #ffffff; font-size: 20px; font-weight: 700; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 2px; }
        .report-meta { display: flex; gap: 25px; flex-wrap: wrap; border-top: 1px solid #2a3f5f; padding-top: 12px; }
        .meta-item { display: flex; align-items: center; gap: 6px; color: #7a8aa0; font-size: 12px; font-family: 'Courier New', monospace; }
        .meta-label { font-weight: 700; color: #00d4ff; }
        .meta-value { color: #ffffff; font-weight: 600; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #1a1f3a 0%, #151b2e 100%); border: 1px solid; border-radius: 8px; padding: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); transition: all 0.3s ease; position: relative; overflow: hidden; }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; background: linear-gradient(90deg, transparent, currentColor, transparent); opacity: 0.6; }
        .stat-card:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(0,0,0,0.6); }
        .stat-card h3 { color: #7a8aa0; font-size: 10px; text-transform: uppercase; margin-bottom: 10px; font-weight: 700; letter-spacing: 1.5px; }
        .stat-value { font-size: 38px; font-weight: 900; line-height: 1; font-family: 'Courier New', monospace; text-shadow: 0 0 15px currentColor; }
        .stat-card.danger { border-color: #ff3366; color: #ff3366; }
        .stat-card.warning { border-color: #ffaa00; color: #ffaa00; }
        .stat-card.info { border-color: #00d4ff; color: #00d4ff; }
        .stat-card.success { border-color: #00ff88; color: #00ff88; }
        .section { background: #151b2e; border: 1px solid #2a3f5f; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow:0 4px 15px rgba(0,0,0,0.4); }
        .section h2 { color: #00ff88; font-size: 18px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #2a3f5f; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0,255,136,0.5); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0d1117; padding: 12px 14px; text-align: left; font-weight: 700; color: #00d4ff; border-bottom: 2px solid #00ff88; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        td { padding: 12px 14px; border-bottom: 1px solid #2a3f5f; color: #e0e0e0; font-size: 13px; font-family: 'Courier New', monospace; }
        tr:hover { background: rgba(0,255,136,0.05); }
        .ip-badge { background: rgba(0,212,255,0.15); padding: 4px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-weight: 700; color: #00d4ff; font-size: 12px; display: inline-block; border: 1px solid rgba(0,212,255,0.3); }
        .username { background: rgba(255,170,0,0.15); padding: 3px 8px; border-radius: 4px; font-weight: 600; color: #ffaa00; font-size: 12px; display: inline-block; border: 1px solid rgba(255,170,0,0.3); }
        .count-badge { background: rgba(255,51,102,0.15); padding: 3px 8px; border-radius: 4px; font-weight: 800; color: #ff3366; font-size: 12px; display: inline-block; border: 1px solid rgba(255,51,102,0.3); }
        .status-blocked { background: #ff3366; padding: 4px 10px; border-radius: 4px; font-weight: 700; color: #0a0e27; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; display: inline-block; box-shadow: 0 0 10px rgba(255,51,102,0.5); }
        .reason-brute { color: #ff3366; font-weight: 700; text-shadow: 0 0 8px rgba(255,51,102,0.4); }
        .reason-recon { color: #ffaa00; font-weight: 700; text-shadow: 0 0 8px rgba(255,170,0,0.4); }
        .no-data { text-align: center; color: #7a8aa0; font-style: italic; padding: 25px; font-size: 13px; }
        .ports { font-family: 'Courier New', monospace; font-size: 11px; color: #00ff88; background: rgba(0,255,136,0.1); padding: 3px 6px; border-radius: 3px; border: 1px solid rgba(0,255,136,0.2); }
        @media (max-width: 768px) { body { padding: 10px; } .brand-header, .report-header { padding: 15px; } .brand-logo { font-size: 32px; } .dashboard { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; } .stat-card { padding: 15px; } .stat-value { font-size: 28px; } .section { padding: 15px; } th, td { padding: 8px 6px; font-size: 11px; } }
        @media print { body { background: white; color: black; } .brand-header { background: #1a1f3a; } .section, .stat-card { box-shadow: none; border: 1px solid #ccc; } }

    </style>
</head>
<body>
    <div class="container">
        <div class="brand-header">
            <div class="brand-logo">&#128737; RECONBLOCK</div>
            <div class="brand-tagline">Advanced Security Protection System</div>
        </div>
        <div class="report-header">
            <div class="report-title">Security Report - Last 12 Hours</div>
            <div class="report-meta">
                <div class="meta-item"><span class="meta-label">Generated:</span> <span class="meta-value">$reportDate</span></div>
                <div class="meta-item"><span class="meta-label">Version:</span> <span class="meta-value">1.0</span></div>
                <div class="meta-item"><span class="meta-label">Status:</span> <span class="meta-value">Active</span></div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="stat-card danger">
                <h3>Brute Force Attacks</h3>
                <div class="stat-value">$totalBruteForce</div>
            </div>
            <div class="stat-card warning">
                <h3>Reconnaissance Scans</h3>
                <div class="stat-value">$totalRecon</div>
            </div>
            <div class="stat-card info">
                <h3>Total Attempts</h3>
                <div class="stat-value">$totalAttempts</div>
            </div>
            <div class="stat-card success">
                <h3>Blocked IPs</h3>
                <div class="stat-value">$totalBlocked</div>
            </div>
        </div>
        
        <div class="section">
            <h2>&#128680; Brute Force Attacks</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Username</th>
                        <th>Port</th>
                        <th>Attempts</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    $bruteForceRows
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>&#128269; Reconnaissance Scans</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>PORTS SCANNED</th>
                        <th>SCAN COUNT</th>
                        <th>TIMESTAMP</th>
                    </tr>
                </thead>
                <tbody>
                    $reconRows
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>&#128683; Currently Blocked IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Block Reason</th>
                        <th>Block Time</th>
                        <th>Attempts</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    $blockedRows
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"@
            
            # Save report
            $reportPath = Join-Path $reportsDir $fileName
            $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
            
            Write-Host "[+] Report saved: $reportPath" -ForegroundColor Green
            Write-Host "[+] Opening in browser..." -ForegroundColor Green
            
            # Open in default browser
            Start-Process $reportPath
            
            Write-Host ""
            Write-Host "[OK] Report generated successfully!" -ForegroundColor Green
            Write-Host ""
        }
        catch {
            Write-Host ""
            Write-Host "[ERROR] Failed to generate report: $_" -ForegroundColor Red
            Write-Host ""
        }
    }
    
    "telegram-bot" {
        Write-Host ""
        Write-Host "=========================================" -ForegroundColor Cyan
        Write-Host "   Telegram Bot Setup Wizard" -ForegroundColor Cyan
        Write-Host "=========================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "To get started, you'll need:" -ForegroundColor Yellow
        Write-Host "  1. Create a bot via @BotFather on Telegram"
        Write-Host "  2. Get your Chat ID from @userinfobot"
        Write-Host ""
        
        Write-Host "Enter your Bot Token (from @BotFather):" -ForegroundColor Yellow
        $botToken = Read-Host
        
        if (-not ($botToken -match '^\d+:[A-Za-z0-9_-]+$')) {
            Write-Host ""
            Write-Host "[ERROR] Invalid bot token format" -ForegroundColor Red
            Write-Host ""
            exit
        }
        
        Write-Host ""
        Write-Host "Enter your Chat ID (from @userinfobot):" -ForegroundColor Yellow
        $chatID = Read-Host
        
        if (-not ($chatID -match '^\d+$')) {
            Write-Host ""
            Write-Host "[ERROR] Invalid chat ID format (numbers only)" -ForegroundColor Red
            Write-Host ""
            exit
        }
        
        Write-Host ""
        Write-Host "Testing connection..." -ForegroundColor Yellow
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $testMessage = "[OK] ReconBlock Telegram Bot Configured Successfully!"
            $uri = "https://api.telegram.org/bot$botToken/sendMessage?chat_id=$chatID&text=$testMessage"
            $result = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 5 -ErrorAction Stop
            
            if ($result.ok) {
                $configDir = "C:\ReconBlock\Config"
                if (-not (Test-Path $configDir -PathType Container)) {
                    New-Item -Path $configDir -ItemType Directory -Force | Out-Null
                }
                
                $config = @{
                    BotToken = $botToken
                    ChatID = $chatID
                    Configured = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
                
                $config | ConvertTo-Json | Out-File "C:\ReconBlock\Config\telegram.json" -Encoding UTF8 -Force
                
                Write-Host ""
                Write-Host "[OK] Telegram bot configured successfully!" -ForegroundColor Green
                Write-Host ""
                Write-Host "Test message sent to your chat." -ForegroundColor Gray
                Write-Host "You will now receive alerts when attacks are detected." -ForegroundColor Gray
                Write-Host ""
            }
        }
        catch {
            Write-Host ""
            Write-Host "[ERROR] Failed to connect to Telegram" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            Write-Host ""
            Write-Host "Please check:" -ForegroundColor Yellow
            Write-Host "  - Bot token is correct"
            Write-Host "  - Chat ID is correct"
            Write-Host "  - You started a chat with the bot"
            Write-Host ""
        }
    }
}
'@

# ====================================================================
# INSTALLATION
# ====================================================================

try {
    Write-Host "[1/8] Creating directory structure..." -ForegroundColor Yellow
    $directories = @("$InstallPath", "$InstallPath\Scripts", "$InstallPath\Logs", "$InstallPath\Tools", "$InstallPath\Reports", "$InstallPath\Config")
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
    }
    Write-Host "  [OK] Directories created" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to create directories: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    Write-Host "[2/8] Creating detection engine..." -ForegroundColor Yellow
    $detectionScript | Out-File "$InstallPath\Detect.ps1" -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  [OK] Detection engine created (v1.0)" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to create detection engine: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    Write-Host "[3/8] Creating management console..." -ForegroundColor Yellow
    $managementScript | Out-File "$InstallPath\Manage.ps1" -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  [OK] Management console created (v1.0)" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to create management console: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    Write-Host "[4/8] Creating log files..." -ForegroundColor Yellow
    New-Item -ItemType File -Path "$InstallPath\Logs\blocks.log" -Force -ErrorAction Stop | Out-Null
    New-Item -ItemType File -Path "$InstallPath\Logs\detection.log" -Force -ErrorAction Stop | Out-Null
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "$InstallPath\Logs\blocks.log" -Value "$timestamp | SYSTEM | ReconBlock v1.0 initialized" -Force -ErrorAction Stop
    Add-Content -Path "$InstallPath\Logs\detection.log" -Value "$timestamp | SYSTEM | Detection engine v1.0 initialized" -Force -ErrorAction Stop
    Write-Host "  [OK] Log files initialized" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to create log files: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    Write-Host "[5/8] Configuring Windows Firewall..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -ErrorAction Stop
    netsh advfirewall set allprofiles state on | Out-Null
    Write-Host "  [OK] Firewall configured" -ForegroundColor Green
}
catch {
    Write-Host "  [WARNING] Firewall configuration may have failed: $_" -ForegroundColor Yellow
}

try {
    Write-Host "[6/8] Enabling security auditing..." -ForegroundColor Yellow
    auditpol /set /subcategory:"Logon" /failure:enable | Out-Null
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
    Write-Host "  [OK] Security auditing enabled" -ForegroundColor Green
}
catch {
    Write-Host "  [WARNING] Security auditing may have failed: $_" -ForegroundColor Yellow
}

try {
    Write-Host "[7/8] Creating scheduled task..." -ForegroundColor Yellow
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\Detect.ps1`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    
    Register-ScheduledTask -TaskName "ReconBlock-Detection" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Scheduled task created (runs every 5 minutes)" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to create scheduled task: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    Write-Host "[8/8] Starting protection service..." -ForegroundColor Yellow
    Start-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction Stop
    Start-Sleep -Seconds 2
    Write-Host "  [OK] Protection service started" -ForegroundColor Green
}
catch {
    Write-Host "  [WARNING] Failed to start service: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "   Installation Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

Write-Host "MANAGEMENT COMMANDS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  View blocked IPs:" -ForegroundColor Yellow
Write-Host "    rb view" -ForegroundColor White
Write-Host ""
Write-Host "  View recent logs:" -ForegroundColor Yellow
Write-Host "    rb logs" -ForegroundColor White
Write-Host ""
Write-Host "  Unblock an IP:" -ForegroundColor Yellow
Write-Host "    rb unblock" -ForegroundColor White
Write-Host ""
Write-Host "  View statistics:" -ForegroundColor Yellow
Write-Host "    rb stats" -ForegroundColor White
Write-Host ""
Write-Host "  Check status:" -ForegroundColor Yellow
Write-Host "    rb status" -ForegroundColor White
Write-Host ""
Write-Host "  Generate HTML report:" -ForegroundColor Yellow
Write-Host "    rb report" -ForegroundColor White
Write-Host ""

# Create easy command alias
Write-Host "[BONUS] Creating shortcut command 'rb'..." -ForegroundColor Cyan
$aliasScript = @"

# ReconBlock v1.0 Easy Management Alias
function rb {
    param([string]`$cmd = "view")
    & "C:\ReconBlock\Manage.ps1" -Action `$cmd
}
"@

try {
    $profilePath = $PROFILE.CurrentUserAllHosts
    $profileDir = Split-Path $profilePath -Parent
    
    if (-not (Test-Path $profileDir -PathType Container)) {
        New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    
    if (-not (Test-Path $profilePath -PathType Leaf)) {
        New-Item -Path $profilePath -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    
    $existingContent = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
    if (-not ($existingContent -match "function rb")) {
        Add-Content -Path $profilePath -Value $aliasScript -Force -ErrorAction Stop
        Write-Host "  [OK] Shortcut 'rb' created successfully!" -ForegroundColor Green
        Write-Host "  [INFO] Restart PowerShell to use 'rb' commands" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] Shortcut 'rb' already exists" -ForegroundColor Green
    }
}
catch {
    Write-Host "  [WARNING] Failed to create alias: $_" -ForegroundColor Yellow
}

Write-Host "" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "TELEGRAM NOTIFICATIONS (OPTIONAL)" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To enable Telegram alerts:" -ForegroundColor White
Write-Host ""
Write-Host "1. Create telegram.json in C:\ReconBlock\Config\" -ForegroundColor Gray
Write-Host "2. Add your bot token and chat ID:" -ForegroundColor Gray
Write-Host ""
Write-Host '   {' -ForegroundColor Cyan
Write-Host '     "BotToken": "YOUR_BOT_TOKEN",' -ForegroundColor Cyan
Write-Host '     "ChatID": "YOUR_CHAT_ID"' -ForegroundColor Cyan
Write-Host '   }' -ForegroundColor Cyan
Write-Host ""
Write-Host "Get bot token from @BotFather on Telegram" -ForegroundColor Gray
Write-Host "Get chat ID from @userinfobot on Telegram" -ForegroundColor Gray
Write-Host ""
Write-Host "Installation Path: $InstallPath" -ForegroundColor Gray
Write-Host ""

Read-Host "Press Enter to exit"







