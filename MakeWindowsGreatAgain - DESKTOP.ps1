# MakeWindowsGreatAgain Script, v0.1
# janvanderwijk.tech



# Disable Windows Telemetry in Windows 11

# Disable the Connected User Experiences and Telemetry service
Stop-Service -Name "DiagTrack" -Force
Set-Service -Name "DiagTrack" -StartupType Disabled

# Disable the diagnostic data services
Stop-Service -Name "diagnosticshub.standardcollector.service" -Force
Set-Service -Name "diagnosticshub.standardcollector.service" -StartupType Disabled

# Change privacy settings for telemetry
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -PropertyType DWord -Force

# Disable Feedback Frequency
New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -PropertyType DWord -Force

# Disable Compatibility Telemetry
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

# Disable Inventory Collector
schtasks /Change /TN "\Microsoft\Windows\WDI\SrvHost" /Disable
schtasks /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /Disable

# Disable Data Collection via Group Policy
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force

# Confirm changes
Write-Output "Telemetry settings have been successfully disabled."

# Disable Wi-Fi Sense in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable Wi-Fi Sense features
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowed" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedProviders" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWifiSenseHotspots" -Name "value" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToPaidWiFiServices" -Name "value" -Value 0

# Disable Wi-Fi Sense features for the current user
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowed" -Value 0
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseOpen" -Value 0

# Disable sharing of Wi-Fi networks with contacts
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseOpen" -Value 0

# Confirm changes
Write-Output "Wi-Fi Sense has been successfully disabled."

# Disable Activity History in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable Activity History collection for the current user
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityLog" -Name "PublishUserActivities" -Value 0
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityLog" -Name "UploadActivity" -Value 0

# Disable Activity History collection via Group Policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0

# Clear existing Activity History for the current user
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$activityPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform\L.$sid.activitycache"
if (Test-Path $activityPath) {
    Remove-Item -Path "$activityPath\*" -Recurse -Force
}

# Confirm changes
Write-Output "Activity History has been successfully disabled and existing activity logs have been cleared."


# Disable Location Tracking in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable location tracking for the current user
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String

# Disable location tracking via Group Policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Value 1

# Confirm changes
Write-Output "Location tracking has been successfully disabled."

# Disable HomeGroup in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable HomeGroup in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Function to stop and disable a service
function Disable-Service {
    param (
        [string]$ServiceName
    )
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force
        Set-Service -Name $ServiceName -StartupType Disabled
    }
}

# Stop and disable HomeGroup services if they exist
Disable-Service -ServiceName "HomeGroupListener"
Disable-Service -ServiceName "HomeGroupProvider"

# Remove HomeGroup registry settings
if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\HomeGroup") {
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\HomeGroup" -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path "HKLM:\Software\Microsoft\HomeGroup") {
    Remove-Item -Path "HKLM:\Software\Microsoft\HomeGroup" -Recurse -Force -ErrorAction SilentlyContinue
}

# Disable HomeGroup in Group Policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1

# Confirm changes
Write-Output "HomeGroup has been successfully disabled."


# Disable Storage Sense in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable Storage Sense via Group Policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense\Parameters" -Name "DisableStorageSense" -Value 1

# Disable Storage Sense in the current user's settings
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0

# Confirm changes
Write-Output "Storage Sense has been successfully disabled."

# Disable GameDVR in Windows

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable GameDVR for current user
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0

# Disable GameDVR and GameBar via Group Policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "GameDVR_Enabled" -Value 0

# Confirm changes
Write-Output "GameDVR has been successfully disabled."


# Set Services to Manual
# JSON string with servicenames
$json = @'
[

{
        "Name": "AJRouter",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "ALG",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppIDSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppMgmt",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppReadiness",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppVClient",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "AppXSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Appinfo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AssignedAccessManagerSvc",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "AudioEndpointBuilder",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AudioSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Audiosrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AxInstSV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BDESVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BFE",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BITS",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BTAGService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BcastDVRUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BluetoothUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BrokerInfrastructure",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Browser",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BthAvctpSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BthHFSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPUserSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "COMSysApp",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CaptureService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CertPropSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ClipSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ConsentUxUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CoreMessagingRegistrar",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CredentialEnrollmentManagerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CryptSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CscService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DPS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcomLaunch",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevQueryBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationBrokerSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicePickerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicesFlowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dhcp",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DiagTrack",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DialogBlockingService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "DispBrokerDesktopSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DisplayEnhancementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DmEnrollmentSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dnscache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DoSvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DsSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DsmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DusmSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EFS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EapHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EntAppSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EventLog",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EventSystem",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FDResPub",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Fax",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FontCache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FrameServer",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FrameServerMonitor",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "GraphicsPerfSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupListener",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupProvider",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HvHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IEEtwCollectorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IKEEXT",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InstallService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InventorySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IpxlatCfgSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "KeyIso",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "KtmRm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LSM",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanServer",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanWorkstation",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LicenseManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LxpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSDTC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSiSCSI",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MapsBroker",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "McpManagementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MessagingService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MicrosoftEdgeElevationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MixedRealityOpenXRSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MpsSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "MsKeyboardFilter",
        "StartupType": "Manual",
        "OriginalType": "Disabled"
      },
      {
        "Name": "NPSMSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NaturalAuthentication",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcbService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcdAutoSetup",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetSetupSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetTcpPortSharing",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "Netlogon",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Netman",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcCtnrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NlaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "OneSyncSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "P9RdrService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPAutoReg",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PeerDistSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PenService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PerfHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PhoneSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PimIndexMaintenanceSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PlugPlay",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PolicyAgent",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Power",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PrintNotify",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PrintWorkflowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ProfSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PushToInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "QWAVE",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasAuto",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasMan",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RemoteAccess",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RemoteRegistry",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RetailDemo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcEptMapper",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "RpcLocator",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SCPolicySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SCardSvr",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SDRSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SEMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SENS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SNMPTRAP",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SNMPTrap",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SSDPSRV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SamSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ScDeviceEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Schedule",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SecurityHealthService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Sense",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorDataService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SessionEnv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SgrmBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SharedAccess",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SharedRealitySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ShellHWDetection",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SmsRouter",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Spooler",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SstpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StateRepository",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "StiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StorSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SysMain",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SystemEventsBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TabletInputService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TapiSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TermService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TextInputManagementService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Themes",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TieringEngineService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBrokerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TokenBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrkWks",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TroubleshootingSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrustedInstaller",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UI0Detect",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UdkUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UevAgentService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "UmRdpService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UnistoreSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserDataSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserManager",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "UsoSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VGAuthService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VMTools",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VSS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VacSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VaultSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "W32Time",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WEPHOSTSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WFDSConMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WMPNetworkSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WManSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WPDBusEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSearch",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WaaSMedicSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WalletService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WarpJITSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WbioSrvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wcmsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WcsPlugInService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdNisSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiServiceHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiSystemHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WebClient",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wecsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WiaRpc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinDefend",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WinHttpAutoProxySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinRM",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Winmgmt",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WlanSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpcMonSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WpnService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpnUserService_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WwanSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XblAuthManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XblGameSave",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxGipSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxNetApiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "autotimesvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "bthserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "camsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "cbdhsvc_*",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "cloudidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dcsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "defragsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagnosticshub.standardcollector.service",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dmwappushservice",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dot3svc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "edgeupdate",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "edgeupdatem",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "embeddedmode",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fdPHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fhsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "gpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "hidserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "icssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "iphlpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "lfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lltdsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lmhosts",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "mpssvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "msiserver",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "netprofm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "nsi",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "p2pimsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "p2psvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "perceptionsimulation",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "pla",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "seclogon",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "shpamsvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "smphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "spectrum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "sppsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ssh-agent",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "svsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "swprv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "tiledatamodelsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "tzautoupdate",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "uhssvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "upnphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vds",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vm3dservice",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "vmicguestinterface",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicheartbeat",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmickvpexchange",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicrdv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicshutdown",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmictimesync",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvmsession",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wbengine",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wcncsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefusersvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wercplsupport",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wisvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlpasvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wmiApSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "workfolderssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wscsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wuauserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wudfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      }
    ]
'@

# Convert JSON-string to PowerShell-object
$services = ConvertFrom-Json -InputObject $json

foreach ($service in $services) {
    $serviceName = $service.Name

    # Controleer of de service bestaat
    $serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($serviceExists) {
        # Set startup to manual
        Set-Service -Name $serviceName -StartupType Manual
        Write-Output "Service '$serviceName' set to 'Manual'."
    } else {
        Write-Output "Service '$serviceName' does not exist."
    }
}

# Disable Bing Search in Windows Start Menu

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable Bing Search in the Start Menu
Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1

# Confirm changes
Write-Output "Bing Search has been successfully disabled in the Start Menu."


# Disable Taskbar Widgets in Windows 11

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable Widgets in the Taskbar
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0

# Restart Explorer to apply changes
Stop-Process -Name "explorer" -Force
Start-Process "explorer"

# Confirm changes
Write-Output "Taskbar widgets have been successfully disabled in Windows 11."


# Function to check if OneDrive is installed
function Is-OneDriveInstalled {
    $oneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    if (Test-Path $oneDrivePath) {
        return $true
    }
    return $false
}

# Function to uninstall OneDrive
function Uninstall-OneDrive {
    # Execute OneDrive setup with uninstall parameter
    $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-Not (Test-Path $oneDriveSetup)) {
        $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
    }
    if (Test-Path $oneDriveSetup) {
        Start-Process -FilePath $oneDriveSetup -ArgumentList "/uninstall" -NoNewWindow -Wait
        Write-Output "OneDrive has been successfully uninstalled."
    } else {
        Write-Output "OneDriveSetup.exe not found. Unable to uninstall OneDrive."
    }
}

# Check if OneDrive is installed and uninstall it if true
if (Is-OneDriveInstalled) {
    Write-Output "OneDrive is installed. Proceeding with uninstallation."
    Uninstall-OneDrive
} else {
    Write-Output "OneDrive is not installed."
}
# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Set registry value to enable classic context menus
$registryPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "(Default)" -Value "" -Type String

# Restart Explorer to apply changes
Stop-Process -Name "explorer" -Force
Start-Process "explorer"

# Confirm changes
Write-Output "Classic context menus have been successfully enabled on the desktop."

# Disable IPv6 in Windows 11

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Set registry value to disable IPv6
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Set-RegistryValue -Path $registryPath -Name "DisabledComponents" -Value 0xFFFFFFFF -Type DWord

# Restart the computer to apply changes
Write-Output "IPv6 has been disabled. A system restart is required for the changes to take effect."

# Uncomment the following line to automatically restart the computer
# Restart-Computer -Force

# Function to execute a command and return the output
function Execute-Command {
    param (
        [string]$Command
    )
    $process = Start-Process -FilePath "powershell" -ArgumentList "-Command $Command" -NoNewWindow -PassThru -Wait -ErrorAction Stop
    return $process.StandardOutput.ReadToEnd()
}


# Function to execute a command and return the output
function Execute-Command {
    param (
        [string]$Command
    )
    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $Command" -NoNewWindow -PassThru -Wait -RedirectStandardOutput -RedirectStandardError -ErrorAction Stop
    return $process.StandardOutput.ReadToEnd()
}

# Function to execute a command and return the output
function Execute-Command {
    param (
        [string]$Command
    )
    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $Command" -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt"
    $output = Get-Content -Path "stdout.txt"
    return $output
}

# Add the Ultimate Performance power plan
Execute-Command "powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61"

# Get the GUID of the Ultimate Performance power plan
$ultimatePerfGUID = (powercfg /list | Select-String "Topprestaties" -Context 0,1 | Select-String -Pattern "\:").Line.Split(":")[-1].Trim()

# Set the Ultimate Performance power plan as active
if ($ultimatePerfGUID) {
    Execute-Command "powercfg -setactive $ultimatePerfGUID"
    Write-Output "Ultimate Performance power plan has been added and set as the active power plan."
} else {
    Write-Output "Failed to retrieve the GUID of the Ultimate Performance power plan."
}

# Cleanup
Remove-Item "stdout.txt", "stderr.txt"

# Disable SearchBox WebSuggestions
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Path to the registry key for disabling search box web suggestions
$registryPath = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"

# Set the registry value to disable web suggestions in the search box
Set-RegistryValue -Path $registryPath -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord

# Confirm changes
Write-Output "Search box web suggestions have been disabled."

# Enable F8 RecoveryOption At Boot
function Execute-Command {
    param (
        [string]$Command
    )
    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $Command" -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt"
    $output = Get-Content -Path "stdout.txt"
    $errorOutput = Get-Content -Path "stderr.txt"
    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $errorOutput"
    }
    return $output
}

try {
    # Enable F8 legacy boot menu
    Execute-Command "bcdedit /set {default} bootmenupolicy legacy"
    Write-Output "Legacy Boot Recovery (F8) has been enabled."
} catch {
    Write-Error "An error occurred: $_"
} finally {
    # Cleanup
    Remove-Item "stdout.txt", "stderr.txt" -ErrorAction SilentlyContinue
}

# Uninstall Bogus Microsoft stuff
$appsToRemove = @(
    "3D Viewer",
    "Bing Search",
    "Clipchamp",
    "Copilot",
    "Cortana",
    "Dev Home",
    "Feedback Hub",
    "Mail and Calendar",
    "Maps",
    "Math Input Panel",
    "Movies & TV",
    "News",
    "Office 365",
    "OneNote",
    "Outlook for Windows",
    "Paint 3D",
    "People",
    "Power Automate",
    "Quick Assist",
    "Skype",
    "Solitaire Collection",
    "Steps Recorder",
    "Sticky Notes",
    "Teams",
    "Tips",
    "To Do",
    "Voice Recorder",
    "Weather",
    "Windows Media Player",
    "Xbox",
    "Your Phone"
)

# Function to uninstall an app
function Uninstall-App {
    param (
        [string]$AppName
    )
    try {
        $package = Get-AppxPackage -Name "*$AppName*" -ErrorAction Stop
        Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
        Write-Output "Successfully uninstalled $AppName"
    } catch {
        Write-Warning "Failed to uninstall $AppName or it is not installed."
    }
}

# Loop through each app and attempt to uninstall it
foreach ($app in $appsToRemove) {
    Uninstall-App -AppName $app
}

# Additional commands to uninstall certain system features
function Disable-Feature {
    param (
        [string]$FeatureName
    )
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
        Write-Output "Successfully disabled $FeatureName"
    } catch {
        Write-Warning "Failed to disable $FeatureName or it is not available."
    }
}

$featuresToDisable = @(
    "MathRecognizer",
    "WindowsMediaPlayer"
)

foreach ($feature in $featuresToDisable) {
    Disable-Feature -FeatureName $feature
}

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Disable system sounds
$registryPath = "HKCU:\AppEvents\Schemes"
Set-RegistryValue -Path $registryPath -Name "(Default)" -Value ".None" -Type String

# Disable Windows startup sound
$startupSoundRegistryPath = "HKCU:\AppEvents\Schemes\Apps\.Default\WindowsLogon\.Current"
Set-RegistryValue -Path $startupSoundRegistryPath -Name "(Default)" -Value "" -Type String

# Confirm changes
Write-Output "System sounds and Windows startup sound have been disabled."

# Optionally restart the system to apply changes
# Restart-Computer -Force

# Get the devic# Enable write caching on the boot drive

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# Get the device ID of the boot drive
$bootDevice = (Get-WmiObject -Query "SELECT * FROM Win32_LogicalDisk WHERE DeviceID='C:'").DeviceID

if ($null -eq $bootDevice) {
    Write-Error "Could not determine the boot drive."
    exit
}

# Get the disk number of the boot drive
$bootDisk = (Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$bootDevice'} WHERE ResultClass=Win32_DiskPartition").DiskIndex

if ($null -eq $bootDisk) {
    Write-Error "Could not determine the boot disk number."
    exit
}

# Path to the registry key for disk settings
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Disk"

# Enable write caching on the boot drive by setting the 'EnableWriteCache' registry value
Set-RegistryValue -Path "$registryPath\Parameters" -Name "EnableWriteCache" -Value 1 -Type DWord

# Confirm changes
Write-Output "Write caching has been enabled on the boot drive."

# Get the temp directory
$tempPath = [System.IO.Path]::GetTempPath()

# Get all files in the temp directory and subdirectories
$tempFiles = Get-ChildItem -Path $tempPath -Recurse -File

foreach ($file in $tempFiles) {
    try {
        # Try to delete the file
        Remove-Item -Path $file.FullName -ErrorAction Stop
    } catch {
        # Suppress the error and continue
        continue
    }
}

# Get all directories in the temp directory and subdirectories
$tempDirs = Get-ChildItem -Path $tempPath -Recurse -Directory

foreach ($dir in $tempDirs) {
    try {
        # Try to delete the directory
        Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
    } catch {
        # Suppress the error and continue
        continue
    }
}

Write-Output "Temp directory cleanup completed."

# Disable Last Access Time stamp
try {
    Start-Process -FilePath "fsutil.exe" -ArgumentList "behavior set disableLastAccess 1" -NoNewWindow -Wait
    Write-Output "Successfully disabled Last Access Time stamp update."
} catch {
    Write-Error "Failed to disable Last Access Time stamp update. Error: $_"
}

