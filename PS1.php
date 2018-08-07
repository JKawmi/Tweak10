<?php

header("Content-type: text/plain");
header("Content-Disposition: attachment; filename=Tweak10.ps1");

$content = '#######################' . "\r\n" . '# Script for Windows 10' . "\r\n" . '# Created by Tweak10' . "\r\n" . '#######################' . "\r\n\r\n" . "# Ask For Elevated Permissions if Required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]\"Administrator\")) {
	Start-Process powershell.exe \"-NoProfile -ExecutionPolicy Bypass -File `\"\$PSCommandPath`\" \$PSCommandArgs\" -WorkingDirectory \$pwd -Verb RunAs
	Exit
}" . "\r\n" . "\r\n";

if(isset($_GET['regBackup'])) {
	$content .= "# Make A Backup Of The Registery...
Write-Output 'Making A Backup Of The Registery...'
\$date = (Get-Date).ToString('dd_MM_yyyy_HH_mm_ss')
Write-Output 'Performing a registry backup...'
New-Item -ItemType Directory -Path \$env:SYSTEMDRIVE\RegistryBackup\\\$date | Out-Null
\$RegistryTrees = ('HKLM', 'HKCU', 'HKCR', 'HKU')
Foreach (\$Item in \$RegistryTrees) {
	reg export \$Item \$env:SYSTEMDRIVE\RegistryBackup\\\$date\\\$Item.reg | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['disableTelemetry'])) {
    $content .= "# Disable Telemetry
Write-Output 'Disabling Telemetry...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0
Stop-Service 'DiagTrack' -WarningAction SilentlyContinue
Set-Service 'DiagTrack' -StartupType Disabled
Stop-Service 'diagnosticshub.standardcollector.service' -WarningAction SilentlyContinue
Set-Service 'diagnosticshub.standardcollector.service' -StartupType Disabled
Stop-Service 'dmwappushservice' -WarningAction SilentlyContinue
Set-Service 'dmwappushservice' -StartupType Disabled
\$tasks = @(
    'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser', 'Microsoft\Windows\Application Experience\ProgramDataUpdater', 'Microsoft\Windows\Autochk\Proxy', 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
)
Foreach (\$task in \$tasks) {
    schtasks /Change /TN \$task /Disable | Out-Null
}" . "\r\n\r\n";
}


if(isset($_GET['disableWiFiSense'])) {
    $content .= "# Disable Wi-Fi Sense
Write-Output 'Disabling Wi-Fi Sense...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting')) {
	New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'Value' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots')) {
	New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'Value' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config')) {
	New-Item -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Type Dword -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFISenseAllowed' -Type Dword -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableBing'])) {
    $content .= "# Disable web search in Start Menu
Write-Output 'Disabling web search in Start Menu...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'CortanaConsent' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'CortanaConsent' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'CortanaConsent' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search' -Name 'AllowCloudSearch' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Experience\AllowCortana' -Name 'value' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableLocationTracking'])) {
    $content .= "# Disable location tracking
Write-Output 'Disabling location tracking...'


If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['restrictP2P'])) {
    $content .= "# Disable peer 2 peer windows updates
Write-Output 'Disabling peer 2 peer windows updates...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization' -Name 'SystemSettingsDownloadMode' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAutologger'])) {
    $content .= "# Disable AutoLogger and tracking services
Write-Output 'Disabling AutoLogger and tracking services...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAdvertisingID'])) {
    $content .= "# Disable Advertising ID
Write-Output 'Disabling Advertising ID...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy')) {
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo')) {
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableWebsiteLang'])) {
    $content .= "# Disable websites acces to language list
Write-Output 'Disabling websites access to language list...'
Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableAppLocation'])) {
    $content .= "# Disable apps access to location
Write-Output 'Disabling apps access to location...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'Value' -Type String -Value 'Deny'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppCamera'])) {
    $content .= "# Disable apps access to camera
Write-Output 'Disabling apps access to camera...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}' -Name 'Value' -Type String -Value 'Deny'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppNoti'])) {
    $content .= "# Disable apps access to notifications
Write-Output 'Disabling apps access to notifications...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppSpeech'])) {
    $content .= "# Disable apps access to speech, inkning & typing
Write-Output 'Disabling app access to speech, inkning & typing...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAppAccount'])) {
    $content .= "# Disable apps access to account info
Write-Output 'Disabling apps access to account info...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}' -Name 'Value' -Type String -Value 'Deny'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppCalendar'])) {
    $content .= "# Disable apps access to calendar
Write-Output 'Disabling apps access to calendar...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableFeedback'])) {
    $content .= "# Disable feedback
Write-Output 'Disabling feedback...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Force | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1
\$tasks = @(
    'Microsoft\Windows\Feedback\Siuf\DmClient', 'Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
)
Foreach (\$task in \$tasks) {
    schtasks /Change /TN \$task /Disable | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['disableBackgroundApps'])) {
    $content .= "# Disable backgroud apps
Write-Output 'Disabling background apps...'
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Exclude 'Microsoft.Windows.Cortana*' | Foreach {
	Set-ItemProperty -Path \$_.PsPath -Name 'Disabled' -Type DWord -Value 1
	Set-ItemProperty -Path \$_.PsPath -Name 'DisabledByUser' -Type DWord -Value 1
}" . "\r\n\r\n";
}

if(isset($_GET['disableAppDiagnostics'])) {
    $content .= "# Disable apps access to diagnostics
Write-Output 'Disabling apps access to diagnostics...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableSharedExpierence'])) {
    $content .= "# Disable shared expierence
Write-Output 'Disabling shared experiences...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableCdp' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableMmx' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableHandwriteSharing'])) {
    $content .= "# Disable sharing of handwriting data
Write-Output 'Disabling sharing of handwriting data...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1
If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' -Name 'Enabled' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableProblemRecorder'])) {
    $content .= "# Disable problem steps recorder
Write-Output 'Disabling problem steps recorder...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat' -Name 'DisableUAR' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableBiometrics'])) {
    $content .= "# Disable biometrics
Write-Output 'Disabling biometrics...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Name 'Enabled' -Type DWord -Value 0
Stop-Service 'WbioSrvc' -WarningAction SilentlyContinue
Set-Service 'WbioSrvc' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableBluetoothAds'])) {
    $content .= "# Disable advertisment via bluetooth
Write-Output 'Disabling advertisment via bluetooth...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' -Name 'AllowAdvertising' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableCEIP'])) {
    $content .= "# Disable Customer Experience Improvement Program
Write-Output 'Disabling Customer Experience Improvement Program...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient' | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
\$tasks = @(
    'Microsoft\Windows\Customer Experience Improvement Program\Consolidator', 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
)
Foreach (\$task in \$tasks) {
    schtasks /Change /TN \$task /Disable | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['disableAIT'])) {
    $content .= "# Disable Application Impact Telemetry
Write-Output 'Disabling Application Impact Telemetry...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableACPI'])) {
    $content .= "# Disable Inventory Collector
Write-Output 'Disabling Inventory Collector...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1
if (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1" . "\r\n\r\n"; 
}

if(isset($_GET['disableExperimentation'])) {
    $content .= "# Disable experimentation on your PC
Write-Output 'Disabling experimentation on your PC...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' -Name 'AllowExperimentation' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation' -Name 'value' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableWin10Tips'])) {
    $content .= "# Disable Windows 10 tips
Write-Output 'Disabling Windows 10 tips...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SoftLandingEnabled' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableSyncNoti'])) {
    $content .= "# Disable File Explorer advertising
Write-Output 'Disabling File Explorer advertising'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSyncProviderNotifications' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['enableDarkMode'])) {
    $content .= "# Enable dark mode
Write-Output 'Enabling dark mode...'
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')) {
    New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'Append Completion' -Type String -Value 'yes'" . "\r\n\r\n";
}

if(isset($_GET['jpgQuality'])) {
    $content .= "# Disable wallpaper quality reduction
Write-Output 'Disabling wallpaper quality reduction...'
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'JPEGImportQuality' -Type DWord -Value 100" . "\r\n\r\n";
}

if(isset($_GET['disableLockScreen'])) {
    $content .= "# Disable lock screen
Write-Output 'Disabling lock screen...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreen' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['hideSearch'])) {
    $content .= "# Hide Cortana/Search box
Write-Output 'Hiding Cortana/Search Box...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['hideTaskView'])) {
    $content .= "# Hide task view button
Write-Output 'Hiding task view button...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['showHiddenFiles'])) {
    $content .= "# Show hidden files
Write-Output 'Showing hidden files...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['showExtensions'])) {
    $content .= "# Show known file extension
Write-Output 'Showing known file extensions...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['smallTaskBar'])) {
    $content .= "# Use smaller task buttons
Write-Output 'Using smaller task buttons...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarSmallIcons' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['defaultView'])) {
    $content .= "# Changing default explorer view to 'this PC'
Write-Output 'Changing default explorer view to this PC...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['showPCShortcut'])) {
    $content .= "# Show 'This PC' shortcut on desktop
Write-Output 'Showing This PC shortcut on desktop...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['showUserFolder'])) {
    $content .= "# Show User Folder on desktop
Write-Output 'Showing 'User Folder' on desktop...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['useBestAppearance'])) {
    $content .= "# Adjust for best appearance
Write-Output 'Adjusting for best appearance...'
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -PropertyType DWORD -Value 1 -Force 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableWindowsWelcome'])) {
    $content .= "If ([System.Environment]::OSVersion.Version.Build -gt 15063) { # Apply Only For Creators Update Or Newer
# Disable Windows welcome screen after an update
Write-Output 'Disabling Windows welcome screen after an update...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-310093Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Type DWord -Value 1
}" . "\r\n\r\n";
}

if(isset($_GET['enableBlueLight'])) {
    $content .= "If ([System.Environment]::OSVersion.Version.Build -gt 15002) { # Apply Only For Creators Update Or Newer
# Enable and configure Night Light
Write-Output 'Enabling and configure Night Light...'
If (!(Test-Path 'HKU:')) {
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
\$LightBlueValue = [byte[]](0x02, 0x00, 0x00, 0x00, 0x9c, 0x5c, 0x44, 0x32, 0x0a, 0xa4, 0xd2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x43, 0x42, 0x01, 0x00, 0x02, 0x01, 0xc2, 0x0a, 0x00, 0xca, 0x14, 0x0e, 0x15, 0x2e, 0x1e, 0x00, 0xca, 0x1e, 0x0e, 0x07, 0x00, 0xcf, 0x28, 0xaa, 0x3a, 0xca, 0x32, 0x0e, 0x10, 0x2e, 0x3b, 0x00, 0xca, 0x3c, 0x0e, 0x07, 0x2e, 0x13, 0x00, 0x00)
\$LightBluePatch = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\\$\$windows.data.bluelightreduction.settings\Current'
Set-ItemProperty -Path \$LightBluePatch -Name 'Data' -Value \$LightBlueValue
}" . "\r\n\r\n";
}

if(isset($_GET['hidePeopleIcon'])) {
    $content .= "# Hide People icon
Write-Output 'Hiding People icon...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['hide3D'])) {
    $content .= "# Hide 3D Objects from 'This PC'
Write-Output 'Hiding 3D Objects from This PC...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'
If (!(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag')) {
    New-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'" . "\r\n\r\n";
}

if(isset($_GET['unPinApps'])) {
    $content .= "# Unpin everything from the start menu
Write-Output 'Unpinning everything from the start menu...'
If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
    Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount' -Include '*.group' -Recurse | ForEach-Object {
        \$data = (Get-ItemProperty -Path '\$(\$_.PsPath)\Current' -Name 'Data').Data -Join ','
        \$data = \$data.Substring(0, \$data.IndexOf(',0,202,30') + 9) + ',0,202,80,0,0'
        Set-ItemProperty -Path '\$(\$_.PsPath)\Current' -Name 'Data' -Type Binary -Value \$data.Split(',')
    }
} ElseIf ([System.Environment]::OSVersion.Version.Build -eq 17134) {
    \$key = Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount' -Recurse | Where-Object { \$_ -like '*start.tilegrid`\$windows.data.curatedtilecollection.tilecollection\Current' }
    \$data = (Get-ItemProperty -Path \$key.PSPath -Name 'Data').Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
    Set-ItemProperty -Path \$key.PSPath -Name 'Data' -Type Binary -Value \$data}" . "\r\n\r\n";
}

if(isset($_GET['DisableActivityHistory'])) {
    $content .= "# Disable Activity History
Write-Output 'Disabling Activity History...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableMapUpdate'])) {
    $content .= "# Disable automatic maps update
Write-Output 'Disabling automatic maps update...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value 0

Set-ItemProperty -Path 'HKLM:\SYSTEM\Maps' -Name 'AutoUpdateEnabled' -Type DWord -Value 0
Get-Service -Name MapsBroker | Set-Service -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableErrorReport'])) {
    $content .= "# Disable error reporting
Write-Output 'Disabling error reporting...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 00000001
Stop-Service 'WerSvc' -WarningAction SilentlyContinue
Set-Service 'WerSvc' -StartupType Disabled
schtasks /Change /TN 'Microsoft\Windows\Windows Error Reporting\QueueReporting' /Disable | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['lowerUAC'])) {
    $content .= "# Lower the UAC level
Write-Output 'Lowering the UAC Level...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableIAS'])) {
    $content .= "# Disable administrative shares 
Write-Output 'Disabling administrative shares...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableSMB'])) {
    $content .= "# Disable SMB 1.0 protocol
Write-Output 'Disabling SMB 1.0 protocol...'
	Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Client' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n"; 
}

if(isset($_GET['disableUpdateRestart'])) {
    $content .= "# Disable automatic restart after a Windows update
Write-Output 'Disabling automatic restart after a Windows update...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUPowerManagement' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AutomaticMaintenanceEnabled' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Type DWord -Value 3
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AllowMUUpdateService' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableRemoteAssistance'])) {
    $content .= "# Disable remote assistance
Write-Output 'Disabling remote assistance...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Type DWord -Value 0
Get-Service -Name RemoteAccess | Set-Service -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableRemoteDesktop'])) {
    $content .= "# Disable remote desktop
Write-Output 'Disabling remote desktop...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1
Disable-NetFirewallRule -Name 'RemoteDesktop*'" . "\r\n\r\n";
}

if(isset($_GET['disableDriverUD'])) {
    $content .= "# Disable automatic drivers update
Write-Output 'Disabling automatic drivers update...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontPromptForWindowsUpdate' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontSearchWindowsUpdate' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DriverUpdateWizardWuSearchEnabled' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['installnet35'])) {
    $content .= "# Install .NET 3.5
Write-Output 'Installing .NET 3.5...'
Dism /online /Enable-Feature /FeatureName:NetFx3 /quiet /norestart" . "\r\n\r\n";
}

if(isset($_GET['disableSuper'])) {
    $content .= "# Disable Superfetch serice
Write-Output 'Disable Superfetch service...'
Stop-Service 'SysMain' -WarningAction SilentlyContinue
Set-Service 'SysMain' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableFast'])) {
    $content .= "# Disable 'Fast Startup'
Write-Output 'Disabling Fast Startup...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAutoPlay'])) {
    $content .= "# Disable Autoplay and Autorun
Write-Output 'Disabling Autoplay and Autorun...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableSticky'])) {
    $content .= "# Disable 'Sticky Keys' prompts
Write-Output 'Disabling Sticky Keys prompt...'
Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Type String -Value '506'" . "\r\n\r\n";
}

if(isset($_GET['enableNumlock'])) {
    $content .= "# Enable NumLock after startup
Write-Output 'Enabling NumLock after startup...'
If (!(Test-Path 'HKU:')) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
Set-ItemProperty -Path 'HKU:\.DEFAULT\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type DWord -Value 2147483650
Set-ItemProperty -Path 'HKU:\S-1-5-19\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type DWord -Value 2147483650
Set-ItemProperty -Path 'HKU:\S-1-5-20\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type DWord -Value 2147483650
Add-Type -AssemblyName System.Windows.Forms
If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
    \$wsh = New-Object -ComObject WScript.Shell
    \$wsh.SendKeys('{NUMLOCK}')
}" . "\r\n\r\n";
}

if(isset($_GET['disableWMP'])) {
    $content .= "# Disable Windows Media Player
Write-Output 'Disabling Windows Media Player...'
Disable-WindowsOptionalFeature -Online -FeatureName 'WindowsMediaPlayer' -NoRestart -WarningAction SilentlyContinue | Out-Null
Stop-Service 'WMPNetworkSvc' -WarningAction SilentlyContinue
Set-Service 'WMPNetworkSvc' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableWFC'])) {
    $content .= "# Disable 'Work Folders Client'
Write-Output 'Disabling Work Folders Client...'
Disable-WindowsOptionalFeature -Online -FeatureName 'WorkFolders-Client' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableXPS'])) {
    $content .= "# Disable XPS serives
Write-Output 'Disabling XPS...'
Disable-WindowsOptionalFeature -Online -FeatureName 'Printing-XPSServices-Features' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableIE11'])) {
    $content .= "# Disable Internet Explorer 11
Write-Output 'Disabling Internet Explorer 11...'
\$ProcessArch = 'Internet-Explorer-Optional-' + \$env:PROCESSOR_ARCHITECTURE
Disable-WindowsOptionalFeature -Online -FeatureName \$ProcessArch -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['setHighPerformance'])) {
    $content .= "# Set Power Plan to High Performance
Write-Output 'Setting Power Plan to High Performance...'
\$HighPerf = powercfg -l | Foreach-Object{if(\$_.contains('High performance')) {\$_.split()[3]}}
\$CurrPlan = $(powercfg -getactivescheme).split()[3]
if (\$CurrPlan -ne \$HighPerf) {powercfg -setactive \$HighPerf}" . "\r\n\r\n";
}

if(isset($_GET['updateHosts'])) {
    $content .= "# Update Hosts file
Write-Output 'Updating Hosts file...'
If (!(Test-Path \"C:\Windows\System32\drivers\\etc\hosts.OLD\")) {
	Remove-Item -Path \"C:\Windows\System32\drivers\\etc\hosts.OLD\"  2>&1 | Out-Null
}
\$url = 'http://winhelp2002.mvps.org/hosts.txt'
\$output = \"C:\Users\\\$env:username\Desktop\hosts\"
Invoke-WebRequest \$url -OutFile \$output
Rename-Item \"C:\Windows\System32\drivers\\etc\hosts\" hosts.OLD 2>&1 | Out-Null
Move-Item \"C:\Users\\\$env:username\Desktop\\hosts\" -Destination \"C:\Windows\System32\drivers\\etc\hosts\" -Force 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['optoutDEP'])) {
    $content .= "# Opt out of 'Data Execution Prevention'
Write-Output 'Opting out of Data Execution Prevention...'
bcdedit /set `{current`} nx OptOut | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['enableF8'])) {
    $content .= "# 
Write-Output 'Enabling F8 Boot Menu Options...'
bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableHibernation'])) {
    $content .= "# Disable Hibernation
Write-Output 'Disabling Hibernation...'
powercfg -h off" . "\r\n\r\n";
}

if(isset($_GET['disableOneDrive'])) {
    $content .= "# Disable OneDrive
Write-Output 'Disabling OneDrive...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['uninstallOneDrive'])) {
    $content .= "# Uninstall OneDrive
Write-Output \"Uninstalling OneDrive...\"
Stop-Process -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
Start-Sleep -s 3
\$onedrive = \"\$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe\"
If (!(Test-Path \$onedrive)) {
    \$onedrive = \"\$env:SYSTEMROOT\System32\OneDriveSetup.exe\"
}
Start-Process \$onedrive \"/uninstall\" -NoNewWindow -Wait
Start-Sleep -s 3
Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
Start-Sleep -s 3
Remove-Item -Path \"\$env:USERPROFILE\OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path \"\$env:LOCALAPPDATA\Microsoft\OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path \"\$env:PROGRAMDATA\Microsoft OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path \"\$env:SYSTEMDRIVE\OneDriveTemp\" -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path \"HKCR:\")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path \"HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path \"HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Recurse -ErrorAction SilentlyContinue" . "\r\n\r\n";
}

if(isset($_GET['enableWSL'])) {
    $content .= "# Insatll Linux Subsystem
Write-Output 'Installing Linux Subsystem...'
If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Type DWord -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Type DWord -Value 1
    Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -NoRestart -WarningAction SilentlyContinue | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['enableStorage'])) {
    $content .= "# Enable Storage Sense
Write-Output 'Enabling Storage Sense...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy')) {
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '04' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '08' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '32' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 'StoragePoliciesNotified' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['setDNS'])) {
    $content .= "# Set the DNS to CloudFlare DNS
Write-Output 'Setting the DNS to CloudFlare DNS...'
Set-DnsClientServerAddress -InterfaceIndex 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15, 17, 18, 19, 20 -ServerAddresses ('1.1.1.1','1.0.0.1') 2>&1 | Out-Null
ipconfig.exe /flushdns 2>&1 | Out-Null
ipconfig.exe /renew 2>&1 | Out-Null" . "\r\n\r\n";
}

if ($_GET['newPCName'] <> "") {
    $content .= "# Rename the PC 
Write-Output 'Renaming the PC...'
Rename-Computer -NewName " . $_GET['newPCName'] . " 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['installChoco'])) {
    $content .= "# Install Chocolatey
Write-Output 'Installing Chocolatey...'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 | Out-Null" . "\r\n\r\n";
}

if($_GET['installPrograms'] <> "") {
	$programsToInstall = rtrim($_GET['installPrograms'],' ');
    $content .= "# Install Programs
Write-Output 'Installing Programs...'
choco install " . $programsToInstall . " -y" . "\r\n\r\n";
}

if(isset($_GET['chocoTask'])) {
    $content .= "# Create a scheduled task for chocolatey
Write-Output 'Creating a scheduled task for chocolatey'
\$chocoCmd = Get-Command -Name 'choco' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object -ExpandProperty Source
if (\$chocoCmd -eq \$null) {
	break
}
\$A = New-ScheduledTaskAction -Execute \$chocoCmd -Argument 'upgrade all -y'
\$T = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At 1pm
\$P = New-ScheduledTaskPrincipal 'SYSTEM'
\$S = New-ScheduledTaskSettingsSet -StartWhenAvailable
\$D = New-ScheduledTask -Action \$A -Principal \$P -Trigger \$T -Settings \$S
Register-ScheduledTask Choco -InputObject \$D -Force
" . "\r\n\r\n";
}

if(isset($_GET['disableSuggestions'])) {
    $content .= "# Disable silent installation and suggestion of windows app
Write-Output 'Disabling silent installation and suggestion of windows app...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338393Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353698Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent')) {
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAppPrompt'])) {
    $content .= "# Disable 'You have new apps that can open this type of file' prompt
Write-Output 'Disabling You have new apps that can open this type of file prompt...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name 'NoNewAppAlert' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableStorePrompt'])) {
    $content .= "# Disable 'Look for an app in the store' prompt
Write-Output 'Disabling Look for an app in the store prompt...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name 'NoUseStoreOpenWith' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableDVR'])) {
    $content .= "# Disable Xbox DVR
Write-Output 'Disabling Xbox DVR...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['uninstallApps'])) {
    $content .= "# Uninstall preinstalled Apps
Write-Output 'Uninstalling preinstalled Apps...'
\$windowsApps = @('2414FC7A.Viber', '41038Axilesoft.ACGMediaPlayer', '46928bounde.EclipseManager', '4DF9E0F8.Netflix', '64885BlueEdge.OneCalendar', '7EE7776C.LinkedInforWindows', '828B5831.HiddenCityMysteryofShadows', '89006A2E.AutodeskSketchBook', '9E2F88E3.Twitter', 'A278AB0D.DisneyMagicKingdoms', 'A278AB0D.MarchofEmpires', 'ActiproSoftwareLLC.562882FEEB491', 'AdobeSystemsIncorporated.AdobePhotoshopExpress', 'CAF9E577.Plex', 'D52A8D61.FarmVille2CountryEscape', 'D5EA27B7.Duolingo-LearnLanguagesforFree', 'DB6EA5DB.CyberLinkMediaSuiteEssentials', 'DolbyLaboratories.DolbyAccess', 'Drawboard.DrawboardPDF', 'E046963F.LenovoCompanion', 'Facebook.Facebook', 'flaregamesGmbH.RoyalRevolt2', 'GAMELOFTSA.Asphalt8Airborne', 'KeeperSecurityInc.Keeper', 'king.com.BubbleWitch3Saga', 'king.com.CandyCrushSaga', 'king.com.CandyCrushSodaSaga', 'LenovoCorporation.LenovoID', 'LenovoCorporation.LenovoSettings', 'Microsoft.3DBuilder', 'Microsoft.AppConnector', 'Microsoft.BingFinance', 'Microsoft.BingNews', 'Microsoft.BingSports', 'Microsoft.BingTranslator', 'Microsoft.BingWeather', 'Microsoft.CommsPhone', 'Microsoft.ConnectivityStore', 'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.Messaging', 'Microsoft.Microsoft3DViewer', 'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftPowerBIForWindows', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.MicrosoftStickyNotes', 'Microsoft.MinecraftUWP', 'Microsoft.MSPaint', 'Microsoft.NetworkSpeedTest', 'Microsoft.Office.OneNote', 'Microsoft.Office.Sway', 'Microsoft.OneConnect', 'Microsoft.People', 'Microsoft.Print3D', 'Microsoft.RemoteDesktop', 'Microsoft.SkypeApp', 'Microsoft.Wallet', 'Microsoft.Windows.Photos', 'Microsoft.WindowsAlarms', 'Microsoft.WindowsCamera', 'microsoft.windowscommunicationsapps', 'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.WindowsPhone', 'Microsoft.WindowsSoundRecorder', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'PandoraMediaInc.29680B314EFC2', 'SpotifyAB.SpotifyMusic', 'WinZipComputing.WinZipUniversal', 'XINGAG.XING');
Foreach (\$app in \$windowsApps) {
    Get-AppxPackage \$app | Remove-AppxPackage;
}" . "\r\n\r\n";
}

if(isset($_GET['deleteTemp'])) {
    $content .= "# Delete temp files
Write-Output 'Deleting temp files...'
\$tempfolders = @('C:\Windows\Temp\*', 'C:\Documents and Settings\*\Local Settings\temp\*', 'C:\Users\*\Appdata\Local\Temp\*', 'C:\Users\$env:username\Desktop\Programs\')
Remove-Item -Path \$tempfolders -force -recurse 2>&1 | Out-Null
function Delete() {
    \$Invocation = (Get-Variable MyInvocation -Scope 1).Value
    \$Path =  \$Invocation.MyCommand.Path
    Remove-Item \$Path
}" . "\r\n\r\n";
}

if(!isset($_GET['restartPC'])) {
    $content .= "# Finishing
Write-Output 'Press any key to continue...'
\$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')";
} else {
	$content .= "# Restart the PC
Write-Output 'Press any key to restart your PC...'
\$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Output 'Restarting the PC...'
Restart-Computer";
}


echo $content;