$outputFile = "C:\SecurityAssessmentReport.txt"
$outputLines = @()
$outputLines += "Security Assessment Report - $(Get-Date)"

Write-Output "Starting Security Assessment..."

# Scan for open ports
Write-Output "Scanning for open ports..."
$OpenPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object LocalAddress, LocalPort, State
$outputLines += "Open Ports:`n" + ($OpenPorts | Format-Table | Out-String)

# Check for users with administrative privileges
Write-Output "Checking for users with administrative privileges..."
$AdminUsers = Get-LocalGroupMember -Group "Administrators"
$outputLines += "Administrators Group Members:`n" + ($AdminUsers | Format-Table Name, PrincipalSource | Out-String)

# Retrieve password policies
Write-Output "Retrieving password policies..."
$PasswordPolicy = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $false } | Select-Object Name, PasswordRequired, PasswordNeverExpires
$outputLines += "Password Policies:`n" + ($PasswordPolicy | Format-Table | Out-String)

# Retrieve account lockout policies
Write-Output "Retrieving account lockout policies..."
$LockoutPolicy = net accounts | Out-String
$outputLines += "Account Lockout Policies:`n$LockoutPolicy"

# Check Windows Firewall status
Write-Output "Checking Windows Firewall status..."
$FirewallProfile = Get-NetFirewallProfile | Select-Object Name, Enabled
$outputLines += "Windows Firewall Status:`n" + ($FirewallProfile | Format-Table | Out-String)

# Check User Account Control (UAC) settings
Write-Output "Checking User Account Control (UAC) settings..."
$UAC = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$UACStatus = if ($UAC.EnabledLUA -eq 1) { "enabled" } else { "not enabled" }
$UACNotificationLevel = switch ($UAC.ConsentPromptBehaviorAdmin) {
    0 { "No prompt (Always allow)" }
    1 { "Prompt on secure desktop" }
    2 { "Prompt (default)" }
    3 { "Prompt for credentials on secure desktop" }
    default { "Unknown" }
}
$outputLines += "User Account Control (UAC) is $UACStatus. Notification Level: $UACNotificationLevel"

# Check BitLocker Status
Write-Output "Checking BitLocker Status..."
$BitLockerStatus = Get-BitLockerVolume
$outputLines += "BitLocker Status:`n" + ($BitLockerStatus | Select-Object MountPoint, VolumeStatus | Format-Table | Out-String)

# Check Remote Desktop settings
Write-Output "Checking Remote Desktop settings..."
$RDPStatus = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
if ($RDPStatus.fDenyTSConnections -eq 0) {
    $outputLines += "Remote Desktop is enabled."
} else {
    $outputLines += "Remote Desktop is disabled."
}

# Check application whitelisting (AppLocker)
Write-Output "Checking application whitelisting (AppLocker)..."
$AppLockerPolicy = Get-AppLockerPolicy -Effective
$outputLines += "AppLocker Policy:`n" + ($AppLockerPolicy | Format-Table | Out-String)

# Check for files with excessive permissions
Write-Output "Checking for files with excessive permissions..."
$ExcessivePermissions = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match "ReadOnly" -or $_.Attributes -match "Hidden" }
$outputLines += "Files with Excessive Permissions:`n" + ($ExcessivePermissions | Select-Object FullName, Attributes | Format-Table | Out-String)

# Check installed security updates
Write-Output "Checking installed security updates..."
$InstalledUpdates = Get-HotFix | Where-Object { $_.Description -like "*Security*" }
$outputLines += "Installed Security Updates:`n" + ($InstalledUpdates | Format-Table | Out-String)

# Check network configuration
Write-Output "Checking network configuration..."
$NetworkConfig = Get-DnsClientServerAddress
$outputLines += "Network Configuration:`n" + ($NetworkConfig | Format-Table | Out-String)

# Listing installed software
Write-Output "Listing installed software..."
$InstalledSoftware = Get-CimInstance -ClassName Win32_Product
$outputLines += "Installed Software:`n" + ($InstalledSoftware | Select-Object Name, Version | Format-Table | Out-String)

# Check for third-party antivirus software
Write-Output "Checking for third-party antivirus software..."
$Antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
$outputLines += "Third-Party Antivirus Software:`n" + ($Antivirus | Select-Object displayName, productState | Format-Table | Out-String)

# Reviewing Security event log
Write-Output "Reviewing Security event log..."
$SecurityLogs = Get-EventLog -LogName Security -Newest 10
$outputLines += "Security Event Log:`n" + ($SecurityLogs | Format-Table | Out-String)

# Checking remote management settings
Write-Output "Checking remote management settings..."
$WinRMStatus = Get-Service -Name WinRM
if ($WinRMStatus.Status -eq 'Running') {
    $outputLines += "WinRM is enabled."
} else {
    $outputLines += "WinRM is not enabled."
}

# Checking user account policies
Write-Output "Checking user account policies..."
$UserPolicies = Get-LocalUser | Select-Object Name, PasswordNeverExpires, UserMayChangePassword
$outputLines += "User Account Policies:`n" + ($UserPolicies | Format-Table | Out-String)

# Reviewing security group memberships
Write-Output "Reviewing security group memberships..."
$SensitiveGroups = Get-LocalGroup | Where-Object { $_.Name -eq 'Administrators' -or $_.Name -eq 'Remote Desktop Users' }
$outputLines += "Security Group Memberships:`n"
foreach ($group in $SensitiveGroups) {
    $outputLines += "$($group.Name):`n" + (Get-LocalGroupMember -Group $group.Name | Format-Table | Out-String)
}

# Write the final report to the output file
$outputLines | Out-File -FilePath $outputFile

Write-Output "Security Assessment Complete. Report saved to $outputFile"
