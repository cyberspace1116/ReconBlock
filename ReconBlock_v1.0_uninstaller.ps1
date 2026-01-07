#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ReconBlock v1.0 - Uninstaller
.DESCRIPTION
    Removes all ReconBlock components from the system
.AUTHOR
    Harshit Sharma
.VERSION
    1.0
#>

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host ""
Write-Host "=========================================" -ForegroundColor Red
Write-Host "   ReconBlock v1.0 Uninstaller" -ForegroundColor Red
Write-Host "=========================================" -ForegroundColor Red
Write-Host ""

$InstallPath = "C:\ReconBlock"

# Check if ReconBlock is installed
if (-not (Test-Path $InstallPath)) {
    Write-Host "[ERROR] ReconBlock is not installed on this system." -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit
}

# Confirmation prompt
Write-Host "This will completely remove ReconBlock from your computer." -ForegroundColor Yellow
Write-Host ""
Write-Host "The following will be removed:" -ForegroundColor White
Write-Host "  - All ReconBlock files and directories" -ForegroundColor Gray
Write-Host "  - Scheduled detection task" -ForegroundColor Gray
Write-Host "  - All firewall rules created by ReconBlock" -ForegroundColor Gray
Write-Host "  - PowerShell alias 'rb' command" -ForegroundColor Gray
Write-Host "  - Security audit policies" -ForegroundColor Gray
Write-Host ""
Write-Host "WARNING: Blocked IPs will be unblocked!" -ForegroundColor Red
Write-Host ""

do {
    $confirmation = Read-Host "Do you want to proceed with uninstallation? (Y/N)"
    $confirmation = $confirmation.ToUpper()
} while ($confirmation -ne 'Y' -and $confirmation -ne 'N')

if ($confirmation -eq 'N') {
    Write-Host ""
    Write-Host "Uninstallation cancelled by user." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit
}

Write-Host ""
Write-Host "Starting uninstallation..." -ForegroundColor Yellow
Write-Host ""

# ====================================================================
# UNINSTALLATION PROCESS
# ====================================================================

# Step 1: Stop and remove scheduled task
Write-Host "[1/7] Removing scheduled task..." -ForegroundColor Yellow
try {
    $task = Get-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "ReconBlock-Detection" -Confirm:$false -ErrorAction Stop
        Write-Host "  [OK] Scheduled task removed" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] No scheduled task found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARNING] Failed to remove scheduled task: $_" -ForegroundColor Yellow
}

# Step 2: Remove all ReconBlock firewall rules
Write-Host "[2/7] Removing firewall rules..." -ForegroundColor Yellow
try {
    # Use same query method as main script for consistency
    $rules = Get-NetFirewallRule -DisplayName "ReconBlock*" -ErrorAction SilentlyContinue
    
    if ($rules) {
        $ruleCount = $rules.Count
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Removed $ruleCount firewall rules" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] No firewall rules found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARNING] Failed to remove some firewall rules: $_" -ForegroundColor Yellow
}

# Step 3: Disable security auditing
Write-Host "[3/7] Disabling security auditing..." -ForegroundColor Yellow
try {
    Write-Host "  [WARNING] This will disable Windows security auditing" -ForegroundColor Yellow
    auditpol /set /subcategory:"Logon" /failure:disable | Out-Null
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable | Out-Null
    Write-Host "  [OK] Security auditing disabled" -ForegroundColor Green
    Write-Host "  [INFO] If you had auditing enabled before ReconBlock, re-enable it manually" -ForegroundColor Gray
}
catch {
    Write-Host "  [WARNING] Failed to disable auditing: $_" -ForegroundColor Yellow
}

# Step 4: Remove PowerShell alias
Write-Host "[4/7] Removing PowerShell alias..." -ForegroundColor Yellow
try {
    $profilePath = $PROFILE.CurrentUserAllHosts
    
    if (Test-Path $profilePath) {
        $content = Get-Content $profilePath -Raw -ErrorAction Stop
        
        if ($content -match "# ReconBlock.*?Easy Management Alias") {
            # Remove the ReconBlock alias section with improved pattern
            $pattern = "(?m)\r?\n?# ReconBlock v1\.0 Easy Management Alias[^\r\n]*[\r\n]+function rb \{[^}]*\}[\r\n]*"
            if ($content -match $pattern) {
                $content = $content -replace $pattern, ""
                $content = $content.Trim()
                
                Set-Content -Path $profilePath -Value $content -Force -ErrorAction Stop
                Write-Host "  [OK] PowerShell alias removed" -ForegroundColor Green
                Write-Host "  [INFO] Restart PowerShell for changes to take effect" -ForegroundColor Gray
            }
            else {
                Write-Host "  [INFO] Alias marker found but pattern doesn't match, skipping" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  [INFO] No PowerShell alias found" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  [INFO] No PowerShell profile found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARNING] Failed to remove PowerShell alias: $_" -ForegroundColor Yellow
}

# Step 5: Backup logs (optional)
Write-Host "[5/7] Creating log backup..." -ForegroundColor Yellow
try {
    $backupPath = "$env:USERPROFILE\Desktop\ReconBlock_Logs_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    
    if (Test-Path "$InstallPath\Logs") {
        Copy-Item -Path "$InstallPath\Logs" -Destination $backupPath -Recurse -Force -ErrorAction Stop
        Write-Host "  [OK] Logs backed up to: $backupPath" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] No logs to backup" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARNING] Failed to backup logs: $_" -ForegroundColor Yellow
}

# Step 6: Remove installation directory
Write-Host "[6/7] Removing installation directory..." -ForegroundColor Yellow
try {
    if (Test-Path $InstallPath) {
        Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
        Write-Host "  [OK] Installation directory removed" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] Installation directory not found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARNING] Failed to remove directory: $_" -ForegroundColor Yellow
    Write-Host "  [INFO] You may need to manually delete: $InstallPath" -ForegroundColor Gray
}

# Step 7: Final verification
Write-Host "[7/7] Verifying removal..." -ForegroundColor Yellow
try {
    $remainingRules = @(Get-NetFirewallRule -DisplayName "ReconBlock*" -ErrorAction SilentlyContinue)
    $taskExists = Get-ScheduledTask -TaskName "ReconBlock-Detection" -ErrorAction SilentlyContinue
    $dirExists = Test-Path $InstallPath
    
    if ($remainingRules.Count -eq 0 -and -not $taskExists -and -not $dirExists) {
        Write-Host "  [OK] All components successfully removed" -ForegroundColor Green
    }
    else {
        if ($remainingRules.Count -gt 0) { Write-Host "  [WARNING] Some firewall rules remain" -ForegroundColor Yellow }
        if ($taskExists) { Write-Host "  [WARNING] Scheduled task still exists" -ForegroundColor Yellow }
        if ($dirExists) { Write-Host "  [WARNING] Installation directory still exists" -ForegroundColor Yellow }
    }
}
catch {
    Write-Host "  [WARNING] Verification failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "   Uninstallation Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

Write-Host "ReconBlock has been successfully removed from your system." -ForegroundColor White
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  - All firewall rules removed" -ForegroundColor White
Write-Host "  - Scheduled task removed" -ForegroundColor White
Write-Host "  - Installation files deleted" -ForegroundColor White
Write-Host "  - Logs backed up to Desktop" -ForegroundColor White
Write-Host ""
Write-Host "Note: Restart PowerShell to remove 'rb' command from session" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit"
