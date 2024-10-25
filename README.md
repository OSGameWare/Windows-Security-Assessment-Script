# Windows-Security-Assessment-Script
# Windows Security Assessment Script

## Description
A PowerShell script designed to perform a comprehensive security assessment on Windows systems. It checks various security aspects, including open ports, administrative users, password policies, firewall status, and more. The results are saved in a report located at `C:\SecurityAssessmentReport.txt`.

## Features
- Scan for open TCP ports.
- List users with administrative privileges.
- Retrieve password and account lockout policies.
- Check Windows Firewall and UAC status.
- Assess BitLocker encryption status.
- Evaluate Remote Desktop settings.
- Review application whitelisting (AppLocker).
- Identify files with excessive permissions.
- Check for installed security updates.
- Display network configuration.
- List installed software and third-party antivirus solutions.
- Review recent Security event log entries.
- Check remote management settings and user account policies.

## Usage
1. Download the script
2. Save the script as a .txt with a different name
3. Open the newly created .txt and save it as a .ps1
5. Open PowerShell with administrative privileges.
6. Execute the script.
7. Review the generated report at `C:\SecurityAssessmentReport.txt`.

## Requirements
- Windows PowerShell 5.1 or higher
- Administrative privileges
