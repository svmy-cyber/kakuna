# Function to display informational messages
function Write-Info {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    Write-Host "$Message" -ForegroundColor Cyan
}

# Function to display verification results with icons
function Write-Verify {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [bool]$IsEnabled
    )
    $color = if ($IsEnabled) { "Green" } else { "Red" }
    Write-Host "$($Message): $($Status)" -ForegroundColor $color
}

# Function to prompt the user for confirmation
function Prompt-User {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [string]$Benefits,
        [Parameter(Mandatory = $true)]
        [string]$Drawbacks
    )
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Host "Description: $Description" -ForegroundColor Cyan
    Write-Host "Benefits: $Benefits" -ForegroundColor Cyan
    Write-Host "Drawbacks: $Drawbacks" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    return (Read-Host "Proceed? (y/n)") -eq 'y'
}

# Function to execute a task
function Execute-Task {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [string]$Benefits,
        [Parameter(Mandatory = $true)]
        [string]$Drawbacks,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Verify
    )
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Info "Task: $Description"
    if ($ExecutionMode -eq 'verify') {
        & $Verify
    } elseif ($ExecutionMode -eq 'ask' -and -not (Prompt-User -Description $Description -Benefits $Benefits -Drawbacks $Drawbacks)) {
        Write-Info "Skipped: $Description"
    } else {
        & $Action | Out-Null
        Write-Info "Completed: $Description"
        & $Verify
    }
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 100
}

# Function to display section headers
function Write-Section {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "$Title" -ForegroundColor White -BackgroundColor DarkMagenta
    Write-Host "========================================" -ForegroundColor Magenta
}

# Execution mode prompt
Write-Host "Choose mode: automatic, ask for each, or verify (auto/ask/verify)" -ForegroundColor Yellow
$ExecutionMode = Read-Host
if ($ExecutionMode -notin @('auto', 'ask', 'verify')) {
    Write-Host "Invalid input. Run the script again and choose 'auto', 'ask', or 'verify'." -ForegroundColor Red
    exit
}

# Define restart flag
$global:restartRequired = $false

# System configuration tasks
$systemConfigTasks = @(
    @{
        Description = "Enable Application Whitelisting with AppLocker"
        Benefits = "Allows only trusted applications to execute, reducing malware execution risks."
        Drawbacks = "May require significant configuration to avoid blocking legitimate applications."
        Action = {
            # Initialize default AppLocker policies if none exist
            if (-not (Get-AppLockerPolicy -Local)) {
                New-AppLockerPolicy -Default | Set-AppLockerPolicy -Local | Out-Null
            }
        }
        Verify = {
            $applockerPolicy = Get-AppLockerPolicy -Local
            if ($applockerPolicy) {
                Write-Verify "Application Whitelisting with AppLocker" "Enabled" $true
            } else {
                Write-Verify "Application Whitelisting with AppLocker" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable BitLocker Drive Encryption"
        Benefits = "Protects data on the system from unauthorized access if the device is lost or stolen."
        Drawbacks = "Requires a TPM chip or password and may affect system performance slightly."
        Action = {
            Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -ne "On" } | ForEach-Object {
                Enable-BitLocker -MountPoint $_.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest | Out-Null
            }
        }
        Verify = {
            $allEncrypted = $true
            Get-BitLockerVolume | ForEach-Object {
                if ($_.ProtectionStatus -ne "On") { $allEncrypted = $false }
            }
            if ($allEncrypted) {
                Write-Verify "BitLocker Drive Encryption" "Enabled" $true
            } else {
                Write-Verify "BitLocker Drive Encryption" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Configure Audit Policies"
        Benefits = "Enables logging of critical events to detect suspicious activities."
        Drawbacks = "Generates additional logs, which may require more storage and attention."
        Action = {
            # Use exact subcategory names from your system
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
        }
        Verify = {
            $auditPolicies = auditpol /get /category:* | Where-Object { $_ -match "Success and Failure" }
            if ($auditPolicies) {
                Write-Verify "Audit Policies" "Configured" $true
            } else {
                Write-Verify "Audit Policies" "Not Configured" $false
            }
        }
    },
    @{
        Description = "Enable PowerShell Logging"
        Benefits = "Logs all PowerShell commands and activities to detect malicious scripts or unauthorized use."
        Drawbacks = "Generates verbose logs that may require more storage."
        Action = {
            # Create registry paths if they do not exist
            $psScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            if (-not (Test-Path $psScriptBlockPath)) {
                New-Item -Path $psScriptBlockPath -Force | Out-Null
            }
            Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Force | Out-Null

            $psTranscriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            if (-not (Test-Path $psTranscriptionPath)) {
                New-Item -Path $psTranscriptionPath -Force | Out-Null
            }
            Set-ItemProperty -Path $psTranscriptionPath -Name "EnableTranscripting" -Value 1 -Force | Out-Null
            Set-ItemProperty -Path $psTranscriptionPath -Name "IncludeInvocationHeader" -Value 1 -Force | Out-Null
        }
        Verify = {
            $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
            $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
            if ($scriptBlockLogging.EnableScriptBlockLogging -eq 1 -and $transcription.EnableTranscripting -eq 1) {
                Write-Verify "PowerShell Logging" "Enabled" $true
            } else {
                Write-Verify "PowerShell Logging" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Increase Log Retention Size"
        Benefits = "Prevents critical logs from being overwritten by increasing the retention size."
        Drawbacks = "Requires additional disk space for storing logs."
        Action = {
            try {
                wevtutil sl Security /ms:20971520 | Out-Null  # 20 GB for Security log
                wevtutil sl System /ms:10485760 | Out-Null   # 10 GB for System log
                wevtutil sl Application /ms:5242880 | Out-Null # 5 GB for Application log
            } catch {
                Write-Host "Failed to set log retention size. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Verify = {
            try {
                # Function to extract maxSize value
                function Get-LogMaxSize {
                    param ($LogName)
                    $output = wevtutil gl $LogName
                    foreach ($line in $output) {
                        if ($line -match '^\s*maxSize:\s*(\d+)') {
                            return [int]$matches[1]
                        }
                    }
                    return $null
                }
                $securityLogSize = Get-LogMaxSize -LogName 'Security'
                $systemLogSize = Get-LogMaxSize -LogName 'System'
                $applicationLogSize = Get-LogMaxSize -LogName 'Application'
                if ($securityLogSize -eq 20971520 -and $systemLogSize -eq 10485760 -and $applicationLogSize -eq 5242880) {
                    Write-Verify "Log Retention Size" "Configured" $true
                } else {
                    Write-Verify "Log Retention Size" "Not Configured" $false
                }
            } catch {
                Write-Verify "Log Retention Size" "Not Configured" $false
            }
        }
    },
    @{
        Description = "Enable Secure Boot"
        Benefits = "Prevents unauthorized or malicious software from loading during boot."
        Drawbacks = "Requires UEFI firmware and may need reconfiguration for dual-boot systems."
        Action = {
            Write-Info "Secure Boot must be enabled in the BIOS/UEFI settings. Please configure it manually."
        }
        Verify = {
            try {
                $secureBootStatus = Get-SecureBootPolicy
                if ($secureBootStatus.SecureBootEnabled) {
                    Write-Verify "Secure Boot" "Enabled" $true
                } else {
                    Write-Verify "Secure Boot" "Not Enabled" $false
                }
            } catch {
                Write-Verify "Secure Boot" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Disable IPv6 if not required"
        Benefits = "Reduces the attack surface by disabling an unused network protocol."
        Drawbacks = "May cause issues if IPv6 is required in the environment."
        Action = {
            $ipv6RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            # Ensure the registry path exists
            if (-not (Test-Path $ipv6RegPath)) {
                New-Item -Path $ipv6RegPath -Force | Out-Null
            }
            # Set the DisabledComponents value to disable IPv6
            Set-ItemProperty -Path $ipv6RegPath -Name "DisabledComponents" -Value 0xFF -Force | Out-Null
        }
        Verify = {
            try {
                $ipv6Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
                if ($ipv6Status.DisabledComponents -eq 0xFF) {
                    Write-Verify "IPv6" "Disabled" $true
                } else {
                    Write-Verify "IPv6" "Enabled" $false
                }
            } catch {
                Write-Verify "IPv6" "Enabled" $false
            }
        }
    },
    @{
        Description = "Enable and configure Windows Defender settings"
        Benefits = "Improves security by enabling real-time protection, behavior monitoring, and automatic updates."
        Drawbacks = "May slightly impact system performance."
        Action = {
            $defenderSettings = Get-MpPreference
            if ($defenderSettings.DisableRealtimeMonitoring -or $defenderSettings.DisableBehaviorMonitoring -or $defenderSettings.DisableOnAccessProtection -or $defenderSettings.DisableIOAVProtection -or $defenderSettings.SignatureDisableUpdateOnStartupWithoutEngine) {
                Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableOnAccessProtection $false -DisableIOAVProtection $false -SignatureDisableUpdateOnStartupWithoutEngine $false
                Start-MpWDOScan | Out-Null
            }
        }
        Verify = {
            $defenderSettings = Get-MpPreference
            if (-not $defenderSettings.DisableRealtimeMonitoring -and -not $defenderSettings.DisableBehaviorMonitoring -and -not $defenderSettings.DisableOnAccessProtection -and -not $defenderSettings.DisableIOAVProtection -and -not $defenderSettings.SignatureDisableUpdateOnStartupWithoutEngine) {
                Write-Verify "Windows Defender settings" "Enabled" $true
            } else {
                Write-Verify "Windows Defender settings" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable and configure Windows Firewall for all profiles"
        Benefits = "Provides a first line of defense against network-based attacks."
        Drawbacks = "May block legitimate network traffic if not configured properly."
        Action = {
            Get-NetFirewallProfile -Profile Domain,Public,Private | ForEach-Object {
                if ($_.Enabled -ne "True") { Set-NetFirewallProfile -Profile $_.Name -Enabled True | Out-Null }
            }
        }
        Verify = {
            $firewallProfiles = Get-NetFirewallProfile -Profile Domain,Public,Private
            $allEnabled = $true
            $firewallProfiles | ForEach-Object {
                if ($_.Enabled -ne "True") { $allEnabled = $false }
            }
            if ($allEnabled) {
                Write-Verify "Windows Firewall for all profiles" "Enabled" $true
            } else {
                Write-Verify "Windows Firewall for all profiles" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Set automatic security intelligence updates to every hour"
        Benefits = "Ensures the system has the latest security intelligence to detect threats."
        Drawbacks = "May slightly impact network performance."
        Action = {
            $taskName = "HourlySecurityIntelligenceUpdate"
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
            }
            $trigger = New-ScheduledTaskTrigger -Once -At "12:00AM" -RepetitionInterval (New-TimeSpan -Minutes 60) -RepetitionDuration (New-TimeSpan -Days 1)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Update-MpSignature"
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName $taskName -Description "Hourly Security Intelligence Update" | Out-Null
        }
        Verify = {
            $taskName = "HourlySecurityIntelligenceUpdate"
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Write-Verify "Automatic security intelligence updates" "Enabled" $true
            } else {
                Write-Verify "Automatic security intelligence updates" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Schedule hourly full virus scan at 10 past the hour"
        Benefits = "Ensures the system is scanned for malware every hour, providing regular and timely detection of threats."
        Drawbacks = "May impact system performance during scans, potentially causing slowdowns or interruptions in normal usage."
        Action = {
            $taskName = "TwelveHourlyFullVirusScanAt10Past"
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
            }
            
            # Create a script to run a full scan
            $scriptContent = "Start-MpScan -ScanType FullScan"
            $scriptPath = "$env:SystemRoot\Temp\TwelveHourlyFullVirusScanAt10Past.ps1"
            Set-Content -Path $scriptPath -Value $scriptContent
            
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
            $trigger = New-ScheduledTaskTrigger -Once -At "00:10AM" -RepetitionInterval (New-TimeSpan -Hours 12)
            
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            
            Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName $taskName -Description "Hourly full virus scan at 10 past the hour" | Out-Null
        }
        Verify = {
            $taskName = "TwelveHourlyFullVirusScanAt10Past"
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Write-Verify "Twelve Hourly full virus scan" "Enabled" $true
            } else {
                Write-Verify "Twelve Hourly full virus scan" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Set machine's primary DNS to 1.1.1.2 and secondary DNS to 1.0.0.2"
        Benefits = "Uses Cloudflare's DNS for Families to block malware DNS lookups."
        Drawbacks = "May limit access to some websites if they are incorrectly flagged as malicious."
        Action = {
            Get-NetAdapter | ForEach-Object {
                $interfaceAlias = $_.InterfaceAlias
                Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses ("1.1.1.2", "1.0.0.2") | Out-Null
            }
        }
        Verify = {
            $dnsSettings = Get-DnsClientServerAddress -AddressFamily IPv4
            $allCorrect = $true

            $expectedDns = @("1.1.1.2", "1.0.0.2")

            $dnsSettings | ForEach-Object {
                $interfaceAlias = $_.InterfaceAlias
                $actualDns = $_.ServerAddresses

                # Skip irrelevant or empty interfaces
                if (-not $actualDns) { return }
                if ($interfaceAlias -match "Loopback|vEthernet|Local Area Connection") { return }

                # Explicitly compare each DNS address
                $expectedMatch = ($actualDns | Sort-Object) -join "," -eq ($expectedDns | Sort-Object) -join ","
                if (-not $expectedMatch) {
                    $allCorrect = $false
                    Write-Host "Mismatch on interface: $interfaceAlias"
                    Write-Host "Expected: $($expectedDns -join ', '), Got: $($actualDns -join ', ')"
                }
            }

            if ($allCorrect) {
                Write-Verify "DNS settings" "Correct" $true
            } else {
                Write-Verify "DNS settings" "Not Correct" $false
            }
        }
    },
    @{
        Description = "Make the device non-bluetooth discoverable"
        Benefits = "Reduces the risk of unauthorized connections by making the device non-discoverable via Bluetooth."
        Drawbacks = "May impact the ability to pair new Bluetooth devices."
        Action = {
            # Disable Bluetooth discovery
            $btRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters"
            if (-not (Test-Path $btRegistryPath)) {
                New-Item -Path $btRegistryPath -Force | Out-Null
            }
            New-ItemProperty -Path $btRegistryPath -Name "DisableDiscovery" -Value 1 -Force | Out-Null
            
            # Restart Bluetooth service to apply changes
            Restart-Service bthserv -Force | Out-Null
        }
        Verify = {
            $btRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters"
            $discoveryStatus = Get-ItemProperty -Path $btRegistryPath -Name "DisableDiscovery"
            if ($discoveryStatus.DisableDiscovery -eq 1) {
                Write-Verify "Bluetooth discovery" "Disabled" $true
            } else {
                Write-Verify "Bluetooth discovery" "Enabled" $false
            }
        }
    },
    @{
        Description = "Improve the security of the device's time server usage"
        Benefits = "Ensures the system time is synchronized with reliable and secure time servers."
        Drawbacks = "None."
        Action = {
            $timeServer = "time.cloudflare.com"
            $secondaryTimeServer = "time.google.com"
            $w32TimeParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
            $w32TimeConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
            
            # Set the time servers
            Set-ItemProperty -Path $w32TimeParametersPath -Name "NtpServer" -Value "$timeServer,$secondaryTimeServer" -Force | Out-Null
            Set-ItemProperty -Path $w32TimeConfigPath -Name "MaxPosPhaseCorrection" -Value 3600 -Force | Out-Null
            Set-ItemProperty -Path $w32TimeConfigPath -Name "MaxNegPhaseCorrection" -Value 3600 -Force | Out-Null
            
            # Restart the Windows Time service to apply changes
            Restart-Service w32time -Force | Out-Null
            
            # Resync the time
            w32tm /resync | Out-Null
        }
        Verify = {
            $w32TimeParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
            $timeServerStatus = Get-ItemProperty -Path $w32TimeParametersPath -Name "NtpServer"
            if ($timeServerStatus.NtpServer -eq "time.cloudflare.com,time.google.com") {
                Write-Verify "Time server settings" "Correct" $true
            } else {
                Write-Verify "Time server settings" "Not Correct" $false
            }
        }
    },
    @{
        Description = "Install PSWindowsUpdate module"
        Benefits = "Allows managing Windows updates through PowerShell."
        Drawbacks = "None."
        Action = {
            if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck | Out-Null
            }
            Import-Module PSWindowsUpdate | Out-Null
        }
        Verify = {
            if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                Write-Verify "PSWindowsUpdate module" "Installed" $true
            } else {
                Write-Verify "PSWindowsUpdate module" "Not Installed" $false
            }
        }
    },
    @{
        Description = "Enable automatic updates for Windows"
        Benefits = "Ensures the system is always up to date with the latest security patches."
        Drawbacks = "May cause unexpected reboots if not configured properly."
        Action = {
            $WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            $WindowsUpdateAUPath = "$WindowsUpdatePath\AU"
            if (-not (Test-Path $WindowsUpdatePath)) {
                New-Item -Path $WindowsUpdatePath -Force | Out-Null
            }
            if (-not (Test-Path $WindowsUpdateAUPath)) {
                New-Item -Path $WindowsUpdateAUPath -Force | Out-Null
            }
            $updateSettings = Get-ItemProperty -Path $WindowsUpdateAUPath -ErrorAction SilentlyContinue
            if (!$updateSettings -or $updateSettings.AUOptions -ne 4) {
                New-ItemProperty -Path $WindowsUpdateAUPath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $WindowsUpdateAUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $WindowsUpdateAUPath -Name "ScheduledInstallDay" -Value 0 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $WindowsUpdateAUPath -Name "ScheduledInstallTime" -Value 3 -PropertyType DWORD -Force | Out-Null
            } else {
                Set-ItemProperty -Path $WindowsUpdateAUPath -Name "AUOptions" -Value 4 -Force | Out-Null
                Set-ItemProperty -Path $WindowsUpdateAUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force | Out-Null
                Set-ItemProperty -Path $WindowsUpdateAUPath -Name "ScheduledInstallDay" -Value 0 -Force | Out-Null
                Set-ItemProperty -Path $WindowsUpdateAUPath -Name "ScheduledInstallTime" -Value 3 -Force | Out-Null
            }
        }
        Verify = {
            $WindowsUpdateAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            $updateSettings = Get-ItemProperty -Path $WindowsUpdateAUPath
            if ($updateSettings.AUOptions -eq 4 -and $updateSettings.NoAutoRebootWithLoggedOnUsers -eq 1 -and $updateSettings.ScheduledInstallDay -eq 0 -and $updateSettings.ScheduledInstallTime -eq 3) {
                Write-Verify "Automatic updates" "Enabled" $true
            } else {
                Write-Verify "Automatic updates" "Not Enabled" $false
            }
        }
    }
)

# Security policies and features hardening tasks
$securityPoliciesTasks = @(
    @{
        Description = "Enable Windows Defender Cloud-Delivered Protection"
        Benefits = "Provides faster updates and enhanced detection capabilities."
        Drawbacks = "Requires an active internet connection."
        Action = {
            try {
                # Ensure PowerShell is running as administrator
                if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                    throw "This script must be run as Administrator."
                }

                # Check and temporarily disable Tamper Protection if enabled
                $tamperProtection = (Get-MpPreference).TamperProtection
                if ($tamperProtection -eq "Enabled") {
                    Set-MpPreference -DisableTamperProtection $true
                }

                # Check the status of the WinDefend service
                $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
                if ($defenderService -eq $null) {
                    throw "The Microsoft Defender Antivirus Service (WinDefend) is not installed on this system."
                } elseif ($defenderService.Status -ne "Running") {
                    Write-Host "Starting the Microsoft Defender Antivirus Service (WinDefend)..."
                    Start-Service -Name "WinDefend" -ErrorAction Stop
                }

                # Use PowerShell cmdlets to set preferences
                Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
                Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop

            } catch {
                Write-Host "Failed to apply settings. Error: $($_.Exception.Message)"
                throw $_
            }
        }
        Verify = {
            try {
                $defenderSettings = Get-MpPreference
                $expectedMapsReporting = 2
                $expectedSamplesConsent = 3

                $mapsCorrect = $defenderSettings.MAPSReporting -eq $expectedMapsReporting
                $samplesCorrect = $defenderSettings.SubmitSamplesConsent -eq $expectedSamplesConsent

                if ($mapsCorrect -and $samplesCorrect) {
                    Write-Verify "Windows Defender Cloud-Delivered Protection" "Enabled" $true
                } else {
                    Write-Host "MAPSReporting: Expected $expectedMapsReporting, Got $($defenderSettings.MAPSReporting)"
                    Write-Host "SubmitSamplesConsent: Expected $expectedSamplesConsent, Got $($defenderSettings.SubmitSamplesConsent)"
                    if ($defenderSettings.SubmitSamplesConsent -ne $expectedSamplesConsent) {
                        Write-Host "Check for Group Policy or Registry overrides for SubmitSamplesConsent."
                    }
                    Write-Verify "Windows Defender Cloud-Delivered Protection" "Not Enabled" $false
                }
            } catch {
                Write-Host "Verification failed. Error: $($_.Exception.Message)"
                throw $_
            }
        }
    },
    @{
        Description = "Configure User Account Control (UAC) settings"
        Benefits = "Enhances security by prompting for administrative permissions."
        Drawbacks = "May be inconvenient due to frequent prompts."
        Action = {
            $UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uacSettings = Get-ItemProperty -Path $UACPath
            if ($uacSettings.EnableLUA -ne 1 -or $uacSettings.ConsentPromptBehaviorAdmin -ne 2 -or $uacSettings.PromptOnSecureDesktop -ne 1) {
                Set-ItemProperty -Path $UACPath -Name "EnableLUA" -Value 1 | Out-Null
                Set-ItemProperty -Path $UACPath -Name "ConsentPromptBehaviorAdmin" -Value 2 | Out-Null
                Set-ItemProperty -Path $UACPath -Name "PromptOnSecureDesktop" -Value 1 | Out-Null
            }
        }
        Verify = {
            $UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uacSettings = Get-ItemProperty -Path $UACPath
            if ($uacSettings.EnableLUA -eq 1 -and $uacSettings.ConsentPromptBehaviorAdmin -eq 2 -and $uacSettings.PromptOnSecureDesktop -eq 1) {
                Write-Verify "UAC settings" "Enabled" $true
            } else {
                Write-Verify "UAC settings" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Configure Remote Desktop Protocol (RDP) settings"
        Benefits = "Prevents unauthorized remote access to the system."
        Drawbacks = "May block legitimate remote access if not configured properly."
        Action = {
            $RDPSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            $RDPTcpSettingsPath = "$RDPSettingsPath\WinStations\RDP-Tcp"
            $rdpSettings = Get-ItemProperty -Path $RDPSettingsPath
            if ($rdpSettings.fDenyTSConnections -ne 1) {
                Set-ItemProperty -Path $RDPSettingsPath -Name "fDenyTSConnections" -Value 1 | Out-Null
            }
            $rdpTcpSettings = Get-ItemProperty -Path $RDPTcpSettingsPath
            if ($rdpTcpSettings.UserAuthentication -ne 1) {
                Set-ItemProperty -Path $RDPTcpSettingsPath -Name "UserAuthentication" -Value 1 | Out-Null
            }
        }
        Verify = {
            $RDPSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            $RDPTcpSettingsPath = "$RDPSettingsPath\WinStations\RDP-Tcp"
            $rdpSettings = Get-ItemProperty -Path $RDPSettingsPath
            $rdpTcpSettings = Get-ItemProperty -Path $RDPTcpSettingsPath
            if ($rdpSettings.fDenyTSConnections -eq 1 -and $rdpTcpSettings.UserAuthentication -eq 1) {
                Write-Verify "RDP settings" "Correctly Configured" $true
            } else {
                Write-Verify "RDP settings" "Not Correctly Configured" $false
            }
        }
    },
    @{
        Description = "Enable Control Flow Guard (CFG)"
        Benefits = "Adds an additional layer of protection against control-flow hijacking attacks."
        Drawbacks = "May have a slight performance impact and compatibility issues with some applications."
        Action = {
            $cfgRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            if (-not (Test-Path $cfgRegPath)) {
                New-Item -Path $cfgRegPath -Force | Out-Null
            }
            New-ItemProperty -Path $cfgRegPath -Name "FeatureSettingsOverride" -Value 3 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $cfgRegPath -Name "FeatureSettingsOverrideMask" -Value 3 -PropertyType DWORD -Force | Out-Null
        }
        Verify = {
            $cfgRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            $cfgSettings = Get-ItemProperty -Path $cfgRegPath
            if ($cfgSettings.FeatureSettingsOverride -eq 3 -and $cfgSettings.FeatureSettingsOverrideMask -eq 3) {
                Write-Verify "Control Flow Guard (CFG)" "Enabled" $true
            } else {
                Write-Verify "Control Flow Guard (CFG)" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Address Space Layout Randomization (ASLR)"
        Benefits = "Increases the complexity of successful exploitation by randomizing memory addresses."
        Drawbacks = "May have a slight performance impact."
        Action = {
            $aslrRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            if (-not (Test-Path $aslrRegPath)) {
                New-Item -Path $aslrRegPath -Force | Out-Null
            }
            New-ItemProperty -Path $aslrRegPath -Name "MoveImages" -Value 1 -PropertyType DWORD -Force | Out-Null
        }
        Verify = {
            $aslrRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            $aslrSettings = Get-ItemProperty -Path $aslrRegPath
            if ($aslrSettings.MoveImages -eq 1) {
                Write-Verify "Address Space Layout Randomization (ASLR)" "Enabled" $true
            } else {
                Write-Verify "Address Space Layout Randomization (ASLR)" "Not Enabled" $false
            }
        }
    },
@{
    Description = "Enable Data Execution Prevention (DEP)"
    Benefits = "Protects against certain types of malware and exploits that attempt to execute code from data pages."
    Drawbacks = "May cause compatibility issues with some legacy applications."
    Action = {
        bcdedit /set nx AlwaysOn | Out-Null
    }
    Verify = {
        # Retrieve the DEP status using bcdedit
        $bcdOutput = bcdedit /enum

        # Parse the output to find the DEP (nx) setting
        $depStatus = $bcdOutput | Where-Object { $_ -match "nx" }

        # Check if the DEP setting contains 'AlwaysOn'
        if ($depStatus -and $depStatus -match "AlwaysOn") {
            Write-Verify "Data Execution Prevention (DEP)" "Enabled" $true
        } else {
            Write-Verify "Data Execution Prevention (DEP)" "Not Enabled" $false
        }
    }
}
,
@{
    Description = "Disable PowerShell 2.0"
    Benefits = "Reduces the risk of exploitation via an older and less secure version of PowerShell."
    Drawbacks = "None."
    Action = {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        $global:restartRequired = $true
    }
    Verify = {
        $psVersion = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2"
        if ($psVersion.State -eq "Disabled") {
            Write-Verify "PowerShell 2.0" "Disabled" $true
        } else {
            Write-Verify "PowerShell 2.0" "Enabled" $false
        }
    }
},
    @{
        Description = "Disable Telnet Client"
        Benefits = "Reduces the risk of exploitation by removing an old and insecure protocol."
        Drawbacks = "None."
        Action = {
            echo 'N' | Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -ErrorAction SilentlyContinue | Out-Null
            $global:restartRequired = $true
        }
        Verify = {
            $telnetClient = Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
            if ($telnetClient.State -eq "Disabled") {
                Write-Verify "Telnet Client" "Disabled" $true
            } else {
                Write-Verify "Telnet Client" "Enabled" $false
            }
        }
    },
@{
    Description = "Disable Windows Media Player"
    Benefits = "Reduces the attack surface by removing an application that could be targeted by exploits."
    Drawbacks = "None."
    Action = {
        Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        $global:restartRequired = $true
    }
    Verify = {
        $mediaPlayer = Get-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer"
        if ($mediaPlayer.State -eq "Disabled") {
            Write-Verify "Windows Media Player" "Disabled" $true
        } else {
            Write-Verify "Windows Media Player" "Enabled" $false
        }
    }
},
@{
    Description = "Disable Work Folders Client"
    Benefits = "Reduces the attack surface by removing an unnecessary feature."
    Drawbacks = "None."
    Action = {
        Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        $global:restartRequired = $true
    }
    Verify = {
        $workFolders = Get-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client"
        if ($workFolders.State -eq "Disabled") {
            Write-Verify "Work Folders Client" "Disabled" $true
        } else {
            Write-Verify "Work Folders Client" "Enabled" $false
        }
    }
},
    @{
        Description = "Disable Windows Subsystem for Linux"
        Benefits = "Reduces the attack surface by removing an unnecessary feature for most users."
        Drawbacks = "None."
        Action = {
            echo 'N' | Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue | Out-Null
            $global:restartRequired = $true
        }
        Verify = {
            $wsl = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux"
            if ($wsl.State -eq "Disabled") {
                Write-Verify "Windows Subsystem for Linux" "Disabled" $true
            } else {
                Write-Verify "Windows Subsystem for Linux" "Enabled" $false
            }
        }
    },
    @{
        Description = "Disable Remote Assistance"
        Benefits = "Reduces the risk of unauthorized remote access."
        Drawbacks = "Users will not be able to receive remote assistance."
        Action = {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Force | Out-Null
        }
        Verify = {
            $remoteAssistance = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
            if ($remoteAssistance.fAllowToGetHelp -eq 0) {
                Write-Verify "Remote Assistance" "Disabled" $true
            } else {
                Write-Verify "Remote Assistance" "Enabled" $false
            }
        }
    },
    @{
        Description = "Disable Windows Script Host"
        Benefits = "Prevents the execution of potentially malicious scripts."
        Drawbacks = "May prevent legitimate scripts from running."
        Action = {
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Force | Out-Null
        }
        Verify = {
            $wsh = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings"
            if ($wsh.Enabled -eq 0) {
                Write-Verify "Windows Script Host" "Disabled" $true
            } else {
                Write-Verify "Windows Script Host" "Enabled" $false
            }
        }
    }
)

# Application hardening tasks
$applicationHardeningTasks = @(
    @{
        Description = "Enable Enhanced Security Mode in Microsoft Edge"
        Benefits = "Enables extra security protections when browsing the web."
        Drawbacks = "May impact performance and compatibility with some websites."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "EnhancedSecurityMode" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $enhancedSecurity = Get-ItemProperty -Path $regPath -Name "EnhancedSecurityMode"
            if ($enhancedSecurity.EnhancedSecurityMode -eq 1) {
                Write-Verify "Enhanced Security Mode in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "Enhanced Security Mode in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Block third-party cookies in Microsoft Edge"
        Benefits = "Prevents tracking and improves privacy."
        Drawbacks = "May impact the functionality of some websites."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "BlockThirdPartyCookies" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $thirdPartyCookies = Get-ItemProperty -Path $regPath -Name "BlockThirdPartyCookies"
            if ($thirdPartyCookies.BlockThirdPartyCookies -eq 1) {
                Write-Verify "Block third-party cookies in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "Block third-party cookies in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enforce Automatic Updates in Microsoft Edge"
        Benefits = "Ensures that Microsoft Edge stays up to date with the latest security patches and features."
        Drawbacks = "Requires an active internet connection and may result in automatic restarts of Edge during updates."
        Action = {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                # Enable Edge updates and set policies
                New-ItemProperty -Path $regPath -Name "UpdateDefault" -Value 1 -PropertyType DWORD -Force | Out-Null # Enable updates
                New-ItemProperty -Path $regPath -Name "AutoUpdateCheckPeriodMinutes" -Value 43200 -PropertyType DWORD -Force | Out-Null # Check every 30 days
                New-ItemProperty -Path $regPath -Name "DefaultUpdatePolicy" -Value 1 -PropertyType DWORD -Force | Out-Null # Automatically update

                Write-Host "Automatic updates for Microsoft Edge have been successfully enforced." -ForegroundColor Green
            } catch {
                Write-Host "Failed to enforce automatic updates for Microsoft Edge. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Verify = {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
                $autoUpdate = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($autoUpdate.UpdateDefault -eq 1 -and $autoUpdate.AutoUpdateCheckPeriodMinutes -eq 43200 -and $autoUpdate.DefaultUpdatePolicy -eq 1) {
                    Write-Verify "Automatic Updates in Microsoft Edge" "Enforced" $true
                } else {
                    Write-Verify "Automatic Updates in Microsoft Edge" "Not Enforced" $false
                }
            } catch {
                Write-Verify "Automatic Updates in Microsoft Edge" "Not Enforced" $false
            }
        }
    },
    @{
        Description = "Enable SmartScreen Filter in Microsoft Edge"
        Benefits = "Protects against phishing and malware websites by using Microsoft’s SmartScreen filter."
        Drawbacks = "May send some browsing data to Microsoft for analysis."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $smartScreen = Get-ItemProperty -Path $regPath -Name "SmartScreenEnabled"
            if ($smartScreen.SmartScreenEnabled -eq 1) {
                Write-Verify "SmartScreen Filter in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "SmartScreen Filter in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Do Not Track in Microsoft Edge"
        Benefits = "Requests that websites do not track the user’s browsing activity."
        Drawbacks = "Websites may choose to ignore this request."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "EnableDoNotTrack" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $doNotTrack = Get-ItemProperty -Path $regPath -Name "EnableDoNotTrack"
            if ($doNotTrack.EnableDoNotTrack -eq 1) {
                Write-Verify "Do Not Track in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "Do Not Track in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable HTTPS-Only Mode in Microsoft Edge"
        Benefits = "Forces the browser to connect to websites using HTTPS, improving security by encrypting data."
        Drawbacks = "Some HTTP-only websites may not be accessible."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "HSTSEnforcementEnabled" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $httpsOnly = Get-ItemProperty -Path $regPath -Name "HSTSEnforcementEnabled"
            if ($httpsOnly.HSTSEnforcementEnabled -eq 1) {
                Write-Verify "HTTPS-Only Mode in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "HTTPS-Only Mode in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Potentially Unwanted App (PUA) protection in Microsoft Edge"
        Benefits = "Protects against the installation of potentially unwanted applications, which can include adware, cryptocurrency miners, and other unwanted software. This helps to maintain a cleaner and more secure browsing experience."
        Drawbacks = "May block some legitimate applications if they are flagged as potentially unwanted, potentially causing inconvenience if the user needs those applications."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "SmartScreenPUAEnabled" -Value 1 -PropertyType DWORD -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            $puaProtection = Get-ItemProperty -Path $regPath -Name "SmartScreenPUAEnabled"
            if ($puaProtection.SmartScreenPUAEnabled -eq 1) {
                Write-Verify "PUA protection in Microsoft Edge" "Enabled" $true
            } else {
                Write-Verify "PUA protection in Microsoft Edge" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Safe Browsing in Google Chrome"
        Benefits = "Protects against phishing and malware websites by using Google's Safe Browsing feature."
        Drawbacks = "May send some browsing data to Google for analysis."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "SafeBrowsingEnabled" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $safeBrowsing = Get-ItemProperty -Path $regPath -Name "SafeBrowsingEnabled"
            if ($safeBrowsing.SafeBrowsingEnabled -eq 1) {
                Write-Verify "Safe Browsing in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "Safe Browsing in Google Chrome" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Block third-party cookies in Google Chrome"
        Benefits = "Prevents tracking and improves privacy."
        Drawbacks = "May impact the functionality of some websites."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "BlockThirdPartyCookies" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $thirdPartyCookies = Get-ItemProperty -Path $regPath -Name "BlockThirdPartyCookies"
            if ($thirdPartyCookies.BlockThirdPartyCookies -eq 1) {
                Write-Verify "Block third-party cookies in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "Block third-party cookies in Google Chrome" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enforce Automatic Updates in Google Chrome"
        Benefits = "Ensures that Google Chrome stays up to date with the latest security patches and features."
        Drawbacks = "Requires an active internet connection and may result in automatic restarts of Chrome during updates."
        Action = {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Google\Update"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                # Enable Google Update and automatic updates for Chrome
                New-ItemProperty -Path $regPath -Name "AutoUpdateCheckPeriodMinutes" -Value 43200 -PropertyType DWORD -Force | Out-Null # Check every 30 days
                New-ItemProperty -Path $regPath -Name "DefaultUpdatePolicy" -Value 1 -PropertyType DWORD -Force | Out-Null # Automatically update
                New-ItemProperty -Path $regPath -Name "UpdateDefault" -Value 1 -PropertyType DWORD -Force | Out-Null # Enable all products to update

                Write-Host "Automatic updates for Google Chrome have been successfully enforced." -ForegroundColor Green
            } catch {
                Write-Host "Failed to enforce automatic updates for Google Chrome. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Verify = {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Google\Update"
                $autoUpdate = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($autoUpdate.AutoUpdateCheckPeriodMinutes -eq 43200 -and $autoUpdate.DefaultUpdatePolicy -eq 1 -and $autoUpdate.UpdateDefault -eq 1) {
                    Write-Verify "Automatic Updates in Google Chrome" "Enforced" $true
                } else {
                    Write-Verify "Automatic Updates in Google Chrome" "Not Enforced" $false
                }
            } catch {
                Write-Verify "Automatic Updates in Google Chrome" "Not Enforced" $false
            }
        }
    },
    @{
        Description = "Enable Do Not Track in Google Chrome"
        Benefits = "Requests that websites do not track the user’s browsing activity."
        Drawbacks = "Websites may choose to ignore this request."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "EnableDoNotTrack" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $doNotTrack = Get-ItemProperty -Path $regPath -Name "EnableDoNotTrack"
            if ($doNotTrack.EnableDoNotTrack -eq 1) {
                Write-Verify "Do Not Track in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "Do Not Track in Google Chrome" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable HTTPS-Only Mode in Google Chrome"
        Benefits = "Forces the browser to connect to websites using HTTPS, improving security by encrypting data."
        Drawbacks = "Some HTTP-only websites may not be accessible."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "ForceHTTPS" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $httpsOnly = Get-ItemProperty -Path $regPath -Name "ForceHTTPS"
            if ($httpsOnly.ForceHTTPS -eq 1) {
                Write-Verify "HTTPS-Only Mode in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "HTTPS-Only Mode in Google Chrome" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Password Leak Detection in Google Chrome"
        Benefits = "Alerts users if their passwords have been compromised in a data breach."
        Drawbacks = "May send some password data to Google for analysis."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "PasswordLeakDetectionEnabled" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $passwordLeakDetection = Get-ItemProperty -Path $regPath -Name "PasswordLeakDetectionEnabled"
            if ($passwordLeakDetection.PasswordLeakDetectionEnabled -eq 1) {
                Write-Verify "Password Leak Detection in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "Password Leak Detection in Google Chrome" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Site Isolation in Google Chrome"
        Benefits = "Provides additional security by isolating websites into separate processes."
        Drawbacks = "May increase memory usage."
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            New-ItemProperty -Path $regPath -Name "SitePerProcess" -Value 1 -Force | Out-Null
        }
        Verify = {
            $regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            $siteIsolation = Get-ItemProperty -Path $regPath -Name "SitePerProcess"
            if ($siteIsolation.SitePerProcess -eq 1) {
                Write-Verify "Site Isolation in Google Chrome" "Enabled" $true
            } else {
                Write-Verify "Site Isolation in Google Chrome" "Not Enabled" $false
            }
        }
    }
)

# System hardening tasks
$systemHardeningTasks = @(
    @{
        Description = "Disable unnecessary services"
        Benefits = "Reduces the number of potential entry points for attackers by disabling services that are not needed."
        Drawbacks = "May disable services required by some applications."
        Action = {
            $services = "WMPNetworkSvc", "DiagTrack", "Fax", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XblNetAuth", "MapsBroker", "RetailDemo", "RemoteAccess", "PrintNotify", "TabletInputService", "PhoneSvc", "wisvc"
            $services | ForEach-Object {
                $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
                if ($service -and $service.StartType -ne "Disabled") {
                    Set-Service -Name $_ -StartupType Disabled | Out-Null
                    Stop-Service -Name $_ -Force | Out-Null
                }
            }
        }
        Verify = {
            $services = "WMPNetworkSvc", "DiagTrack", "Fax", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XblNetAuth", "MapsBroker", "RetailDemo", "RemoteAccess", "PrintNotify", "TabletInputService", "PhoneSvc", "wisvc"
            $allDisabled = $true
            $services | ForEach-Object {
                $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
                if ($service -and $service.StartType -ne "Disabled") {
                    $allDisabled = $false
                }
            }
            if ($allDisabled) {
                Write-Verify "Unnecessary services" "Disabled" $true
            } else {
                Write-Verify "Unnecessary services" "Not Disabled" $false
            }
        }
    },
    @{
        Description = "Disable SMBv1 protocol"
        Benefits = "Prevents exploitation of known SMBv1 vulnerabilities."
        Drawbacks = "Older devices or software that require SMBv1 may stop functioning."
        Action = {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
            if ($smb1.State -ne "Disabled") { Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol | Out-Null }
        }
        Verify = {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
            if ($smb1.State -eq "Disabled") {
                Write-Verify "SMBv1 protocol" "Disabled" $true
            } else {
                Write-Verify "SMBv1 protocol" "Enabled" $false
            }
        }
    },
    @{
        Description = "Enable Attack Surface Reduction (ASR) rules"
        Benefits = "Enhances security by reducing the attack surface that attackers can exploit."
        Drawbacks = "May block legitimate actions or applications if not configured properly."
        Action = {
            # List of all ASR rule GUIDs
            $ASRRules = @(
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block executable content from email and webmail
                "75668C1F-73E0-4F1A-BD98-5B6D4D8CC0EF", # Block all Office applications from creating child processes
                "D4EB027C-9A5A-4F3B-9ED2-D9A321D1907D", # Block credential stealing from LSASS
                "3B576869-A4EC-4529-8536-B80A7769E899", # Block all Office applications from injecting code
                "D3E037E1-3EB8-44C8-A917-57927947596D", # Use advanced runtime analysis for Office macros
                "D1E49AAC-8F56-4280-B9BA-993A6D268512", # Block all Office applications from writing to executable files
                "DCB8D89E-DA2A-4CAD-94DB-2DFB8B0A1A91", # Block execution of potentially obfuscated scripts
                "C1DB55AB-C21A-4637-BB3F-A12568109D35", # Block untrusted and unsigned processes running from USB
                "D2D73854-7B3D-4359-9A02-B6AAB9D7B5C3", # Block Adobe Reader from creating child processes
                "D41D389B-76F5-467A-8A55-C8595FA5B0B1", # Block credential stealing via local security authority subsystem
                "1B88B5A8-8B9C-4859-BA6D-D2444A47D6E0", # Block persistence through WMI event subscription
                "3E75C209-6D46-4D13-B1B6-78B018F6B1E8", # Block exploitation of legacy processes
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block JavaScript and VBScript launching executable content
                "26190899-1602-49E8-8B27-EB1D0A1CE869", # Block Office communication applications from creating child processes
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"  # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
            )

            # Enable each ASR rule by setting it to Audit or Block mode
            $ASRRules | ForEach-Object {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions Enabled | Out-Null
            }
        }
        Verify = {
            # List of all ASR rule GUIDs
            $ASRRules = @(
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                "75668C1F-73E0-4F1A-BD98-5B6D4D8CC0EF",
                "D4EB027C-9A5A-4F3B-9ED2-D9A321D1907D",
                "3B576869-A4EC-4529-8536-B80A7769E899",
                "D3E037E1-3EB8-44C8-A917-57927947596D",
                "D1E49AAC-8F56-4280-B9BA-993A6D268512",
                "DCB8D89E-DA2A-4CAD-94DB-2DFB8B0A1A91",
                "C1DB55AB-C21A-4637-BB3F-A12568109D35",
                "D2D73854-7B3D-4359-9A02-B6AAB9D7B5C3",
                "D41D389B-76F5-467A-8A55-C8595FA5B0B1",
                "1B88B5A8-8B9C-4859-BA6D-D2444A47D6E0",
                "3E75C209-6D46-4D13-B1B6-78B018F6B1E8",
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
                "26190899-1602-49E8-8B27-EB1D0A1CE869",
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
            )

            # Check if all ASR rules are enabled
            $asrStatus = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
            $allEnabled = $true
            $ASRRules | ForEach-Object {
                if ($asrStatus -notcontains $_) {
                    $allEnabled = $false
                }
            }

            if ($allEnabled) {
                Write-Verify "Attack Surface Reduction (ASR) rules" "Enabled" $true
            } else {
                Write-Verify "Attack Surface Reduction (ASR) rules" "Not Enabled" $false
            }
        }
    },
    @{
        Description = "Disable Windows Remote Management (WinRM)"
        Benefits = "Reduces the risk of remote exploitation by disabling a service that allows remote management."
        Drawbacks = "None."
        Action = {
            Set-Service WinRM -StartupType Disabled
            Stop-Service WinRM -Force
        }
        Verify = {
            $winrmService = Get-Service -Name WinRM
            if ($winrmService.StartType -eq "Disabled") {
                Write-Verify "Windows Remote Management (WinRM)" "Disabled" $true
            } else {
                Write-Verify "Windows Remote Management (WinRM)" "Enabled" $false
            }
        }
    }
)

# Execute tasks in sections
Write-Section "System Configuration Tasks"
$systemConfigTasks | ForEach-Object {
    Execute-Task -Description $_.Description -Benefits $_.Benefits -Drawbacks $_.Drawbacks -Action $_.Action -Verify $_.Verify
}

Write-Section "Security Policies and Features Hardening Tasks"
$securityPoliciesTasks | ForEach-Object {
    Execute-Task -Description $_.Description -Benefits $_.Benefits -Drawbacks $_.Drawbacks -Action $_.Action -Verify $_.Verify
}

Write-Section "Application Hardening Tasks"
$applicationHardeningTasks | ForEach-Object {
    Execute-Task -Description $_.Description -Benefits $_.Benefits -Drawbacks $_.Drawbacks -Action $_.Action -Verify $_.Verify
}

Write-Section "System Hardening Tasks"
$systemHardeningTasks | ForEach-Object {
    Execute-Task -Description $_.Description -Benefits $_.Benefits -Drawbacks $_.Drawbacks -Action $_.Action -Verify $_.Verify
}

# Consolidated Summary of Completed Tasks
Write-Host "========================================" -ForegroundColor Green
Write-Host "Summary of Completed Tasks" -ForegroundColor White -BackgroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Combine all task sections for a unified summary
$allTasks = $systemConfigTasks + $securityPoliciesTasks + $applicationHardeningTasks + $systemHardeningTasks
$allTasks | ForEach-Object {
    Write-Info $_.Description
}

# Restart prompt if required
if ($global:restartRequired) {
    Write-Host "A restart is required to complete some of the changes." -ForegroundColor Yellow
    Write-Host "Please restart your system at your earliest convenience." -ForegroundColor Yellow
} else {
    Write-Host "No restart is required. All tasks completed successfully." -ForegroundColor Green
}
