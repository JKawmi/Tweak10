<?php

header("Content-type: text/plain");
header("Content-Disposition: attachment; filename=Tweak10.ps1");

$content = '#######################' . "\r\n" . '# Script for Windows 10' . "\r\n" . '# Created by Tweak10' . "\r\n" . '#######################' . "\r\n\r\n" . "# Ask For Elevated Permissions if Required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]\"Administrator\")) {
	Start-Process powershell.exe \"-NoProfile -ExecutionPolicy Bypass -File `\"\$PSCommandPath`\"\" -Verb RunAs
	Exit
}" . "\r\n" . "\r\n";

if(isset($_GET['regBackup'])) {
	$content .= "# Make A Backup Of The Registery...
Write-Host 'Making A Backup Of The Registery...'
\$date = (Get-Date).ToString('dd_MM_yyyy_HH_mm_ss')
Write-Host 'Performing a registry backup...'
New-Item -ItemType Directory -Path \$env:SYSTEMDRIVE\RegistryBackup\\\$date | Out-Null
\$RegistryTrees = ('HKLM', 'HKCU', 'HKCR', 'HKU')
Foreach (\$Item in \$RegistryTrees) {
	reg export \$Item \$env:SYSTEMDRIVE\RegistryBackup\\\$date\\\$Item.reg | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['disableTelemetry'])) {
    $content .= "# Disable Telemetry
Write-Host 'Disabling Telemetry...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Stop-Service 'DiagTrack' -WarningAction SilentlyContinue
Set-Service 'DiagTrack' -StartupType Disabled
Stop-Service 'diagnosticshub.standardcollector.service' -WarningAction SilentlyContinue
Set-Service 'diagnosticshub.standardcollector.service' -StartupType Disabled
Stop-Service 'dmwappushservice' -WarningAction SilentlyContinue
Set-Service 'dmwappushservice' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableWiFiSense'])) {
    $content .= "# Disable Wi-Fi Sense
Write-Host 'Disabling Wi-Fi Sense...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Force | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config')) {
		New-Item -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'value' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'value' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFISenseAllowed' -Type Dword -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableBing'])) {
    $content .= "# Disable web search in Start Menu
Write-Host 'Disabling web search in Start Menu...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWebOverMeteredConnections' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchPrivacy' -Type DWord -Value 3
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Experience\AllowCortana' -Name 'value' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'DeviceHistoryEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'HistoryViewEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaEnabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableLocationTracking'])) {
    $content .= "# Disable location tracking
Write-Host 'Disabling location tracking...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['restrictP2P'])) {
    $content .= "# Disable peer 2 peer windows updates
Write-Host 'Disabling peer 2 peer windows updates...'
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
Write-Host 'Disabling AutoLogger and tracking services...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' -Name 'Start' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAdvertisingID'])) {
    $content .= "# Disable Advertising ID
Write-Host 'Disabling Advertising ID...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value 0
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy')) {
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableWebsiteLang'])) {
    $content .= "# Disable websites acces to language list
Write-Host 'Disabling websites access to language list...'
Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableAppLaunchTracking'])) {
    $content .= "# Disable app launch tracking
Write-Host 'Disabling app launch tracking...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAppLocation'])) {
    $content .= "# Disable apps access to location
Write-Host 'Disabling apps access to location...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppCamera'])) {
    $content .= "# Disable apps access to camera
Write-Host 'Disabling apps access to camera...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppMic'])) {
    $content .= "# Disable apps access to microphone
Write-Host 'Disabling Apps access to microphone...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppNoti'])) {
    $content .= "# Disable apps access to notifications
Write-Host 'Disabling apps access to notifications...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppSpeech'])) {
    $content .= "# Disable apps access to speech, inkning & typing
Write-Host 'Disabling app access to speech, inkning & typing...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAppAccount'])) {
    $content .= "# Disable apps access to account info
Write-Host 'Disabling apps access to account info...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppContacts'])) {
    $content .= "# Disable apps access to contacts
Write-Host 'Disabling apps access to contacts...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppCalendar'])) {
    $content .= "# Disable apps access to calendar
Write-Host 'Disabling apps access to calendar...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppCall'])) {
    $content .= "# Disable apps access to call history
Write-Host 'Disabling apps access to call history...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppEmail'])) {
    $content .= "# Disable apps access to email
Write-Host 'Disabling apps access to email...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppTasks'])) {
    $content .= "# Disable apps access to tasks
Write-Host 'Disabling apps access to tasks...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppMessaging'])) {
    $content .= "# Disable apps access to messaging
Write-Host 'Disabling apps access to messaging...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppRadios'])) {
    $content .= "# Disable apps access to radio
Write-Host 'Disabling apps access to radio...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableAppOther'])) {
    $content .= "# Disable apps access to other devices
Write-Host 'Disabling apps access to other devices...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableFeedback'])) {
    $content .= "# Disable feedback
Write-Host 'Disabling feedback...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Force | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableBackgroundApps'])) {
    $content .= "# Disable backgroud apps
Write-Host 'Disabling background apps...'
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Exclude 'Microsoft.Windows.Cortana*' | ForEach-Object {
	Set-ItemProperty -Path \$_.PsPath -Name 'Disabled' -Type DWord -Value 1
	Set-ItemProperty -Path \$_.PsPath -Name 'DisabledByUser' -Type DWord -Value 1
}" . "\r\n\r\n";
}

if(isset($_GET['disableAppDiagnostics'])) {
    $content .= "# Disable apps access to diagnostics
Write-Host 'Disabling apps access to diagnostics...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}' -Name 'Value' -Type String -Value 'Deny'" . "\r\n\r\n";
}

if(isset($_GET['disableSharedExpierence'])) {
    $content .= "# Disable shared expierence
Write-Host 'Disabling shared experiences...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' -Name 'RomeSdkChannelUserAuthzPolicy' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' -Name 'NearShareChannelUserAuthzPolicy ' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' -Name 'CdpSessionUserAuthzPolicy ' -Type DWord -Value 1
If (!(Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage')) {
    New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage' | Out-Null
}
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage' -Name 'CdpSessionUserAuthzPolicy ' -Type DWord -Value 1" . "\r\n\r\n"; 
}

if(isset($_GET['disableHandwriteSharing'])) {
    $content .= "# Disable sharing of handwriting data
Write-Host 'Disabling sharing of handwriting data...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' -Name 'Enabled' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableProblemRecorder'])) {
    $content .= "# Disable problem steps recorder
Write-Host 'Disabling problem steps recorder...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat' -Name 'DisableUAR' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableBiometrics'])) {
    $content .= "# Disable biometrics
Write-Host 'Disabling biometrics...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Name 'Enabled' -Type DWord -Value 0
Stop-Service 'WbioSrvc' -WarningAction SilentlyContinue
Set-Service 'WbioSrvc' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableBluetoothAds'])) {
    $content .= "# Disable advertisment via bluetooth
Write-Host 'Disabling advertisment via bluetooth...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' -Name 'AllowAdvertising' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableCEIP'])) {
    $content .= "# Disable Customer Experience Improvement Program
Write-Host 'Disabling Customer Experience Improvement Program...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' | Out-Null
}
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient' | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
\$tasks = @(
    'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser', 'Microsoft\Windows\Application Experience\ProgramDataUpdater', 'Microsoft\Windows\Autochk\Proxy',
    'Microsoft\Windows\Customer Experience Improvement Program\Consolidator', 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip', 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
)
foreach (\$task in \$tasks) {
    schtasks /Change /TN \$task /Disable | Out-Null
}" . "\r\n\r\n"; 
}

if(isset($_GET['disableAIT'])) {
    $content .= "# Disable Application Impact Telemetry
Write-Host 'Disabling Application Impact Telemetry...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableACPI'])) {
    $content .= "# Disable Inventory Collector
Write-Host 'Disabling Inventory Collector...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
if (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1" . "\r\n\r\n"; 
}

if(isset($_GET['disableExperimentation'])) {
    $content .= "# Disable experimentation on your PC
Write-Host 'Disabling experimentation on your PC...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation' -Name 'value' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableWin10Tips'])) {
    $content .= "# Disable Windows 10 tips
Write-Host 'Disabling Windows 10 tips...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SoftLandingEnabled' -Type DWord -Value 0" . "\r\n\r\n"; 
}

if(isset($_GET['disableSyncNoti'])) {
    $content .= "# Disable File Explorer advertising
Write-Host 'Disabling File Explorer advertising'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSyncProviderNotifications' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['enableDarkMode'])) {
    $content .= "# Enable dark mode
Write-Host 'Enabling dark mode...'
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')) {
    New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'Append Completion' -Type String -Value 'yes'" . "\r\n\r\n";
}

if(isset($_GET['jpgQuality'])) {
    $content .= "# Disable wallpaper quality reduction
Write-Host 'Disabling wallpaper quality reduction...'
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'JPEGImportQuality' -Type DWord -Value 100" . "\r\n\r\n";
}

if(isset($_GET['disableLockScreen'])) {
    $content .= "# Disable lock screen
Write-Host 'Disabling lock screen...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreen' -Type DWord -Value 1
If ([System.Environment]::OSVersion.Version.Build -gt 14392) { # Apply Only For Redstone 1 Or Newer
    \$service = New-Object -com Schedule.Service
    \$service.Connect()
    \$task = \$service.NewTask(0)
    \$task.Settings.DisallowStartIfOnBatteries = \$false
    \$trigger = \$task.Triggers.Create(9)
    \$trigger = \$task.Triggers.Create(11)
    \$trigger.StateChange = 8
    \$action = \$task.Actions.Create(0)
    \$action.Path = 'reg.exe'
    \$action.Arguments = 'add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f'
    \$service.GetFolder('\').RegisterTaskDefinition('Disable LockScreen', \$task, 6, 'NT AUTHORITY\SYSTEM', \$null, 4) | Out-Null
}" . "\r\n\r\n";
}

if(isset($_GET['hideSearch'])) {
    $content .= "# Hide Cortana/Search box
Write-Host 'Hiding Cortana/Search Box...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['hideTaskView'])) {
    $content .= "# Hide task view button
Write-Host 'Hiding task view button...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['showHiddenFiles'])) {
    $content .= "# Show hidden files
Write-Host 'Showing hidden files...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['showExtensions'])) {
    $content .= "# Show known file extension
Write-Host 'Showing known file extensions...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['smallTaskBar'])) {
    $content .= "# Use smaller task buttons
Write-Host 'Using smaller task buttons...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarSmallIcons' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['defaultView'])) {
    $content .= "# Changing default explorer view to 'this PC'
Write-Host 'Changing default explorer view to this PC...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['showPCShortcut'])) {
    $content .= "# Show 'This PC' shortcut on desktop
Write-Host 'Showing This PC shortcut on desktop...'
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
    $content .= "# Show 'User Folder' on desktop
Write-Host 'Showing 'User Folder' on desktop...'
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
Write-Host 'Adjusting for best appearance...'
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -PropertyType DWORD -Value 1 -Force 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableWindowsWelcome'])) {
    $content .= "If ([System.Environment]::OSVersion.Version.Build -gt 15063) { # Apply Only For Creators Update Or Newer
# Disable Windows welcome screen after an update
Write-Host 'Disabling Windows welcome screen after an update...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-310093Enabled' -Type DWord -Value 0
}" . "\r\n\r\n";
}

if(isset($_GET['enableBlueLight'])) {
    $content .= "If ([System.Environment]::OSVersion.Version.Build -gt 15002) { # Apply Only For Creators Update Or Newer
# Enable and configure Night Light
Write-Host 'Enabling and configure Night Light...'
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
Write-Host 'Hiding People icon...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableWindowsSpotlight'])) {
    $content .= "# Disable Windows Spotlight
Write-Host 'Disabling Windows Spotlight...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenEnabled' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenOverlayEnabled' -Type DWord -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['hide3D'])) {
    $content .= "# Hide 3D Objects from 'This PC'
Write-Host 'Hiding 3D Objects from This PC...'
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'
If (!(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag')) {
    New-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value 'Hide'" . "\r\n\r\n";
}

if(isset($_GET['enableEmoji'])) {
    $content .= "# Enable Emoji picker
Write-Host 'Enabling Emoji picker...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Input\Settings' -Name 'EnableExpressiveInputShellHotkey' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['hideFrequentlyUsed'])) {
    $content .= "# Hide recent used files and frequently used folders
Write-Host 'Hiding recent used files and frequently used folders...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowRecent' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['unPinApps'])) {
    $content .= "# Unpin everything from the start menu
Write-Host 'Unpinning everything from the start menu...'
((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object{\$_.Name -gt 0}).Verbs() | Where-Object{\$_.Name.replace('&','') -match 'From \"Start\" UnPin|Unpin from Start'} | Foreach-Object{\$_.DoIt()}" . "\r\n\r\n";
}

if(isset($_GET['disableMapUpdate'])) {
    $content .= "# Disable automatic maps update
Write-Host 'Disabling automatic maps update...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\Maps' -Name 'AutoUpdateEnabled' -Type DWord -Value 0
Get-Service -Name MapsBroker | Set-Service -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableErrorReport'])) {
    $content .= "# Disable error reporting
Write-Host 'Disabling error reporting...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 00000001
Stop-Service 'WerSvc' -WarningAction SilentlyContinue
Set-Service 'WerSvc' -StartupType Disabled
schtasks /Change /TN 'Microsoft\Windows\Windows Error Reporting\QueueReporting' /Disable | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['lowerUAC'])) {
    $content .= "# Lower the UAC level
Write-Host 'Lowering the UAC Level...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableIAS'])) {
    $content .= "# Disable administrative shares 
Write-Host 'Disabling administrative shares...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableSMB'])) {
    $content .= "# Disable SMB 1.0 protocol
Write-Host 'Disabling SMB 1.0 protocol...'
	Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Client' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n"; 
}

if(isset($_GET['disableUpdateRestart'])) {
    $content .= "# Disable automatic restart after a Windows update
Write-Host 'Disabling automatic restart after a Windows update...'
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

if(isset($_GET['disableHomeGroup'])) {
    $content .= "# Disable Home Groups services
Write-Host 'Disabling Home Groups Services...'
Stop-Service 'HomeGroupListener' -WarningAction SilentlyContinue
Set-Service 'HomeGroupListener' -StartupType Disabled
Stop-Service 'HomeGroupProvider' -WarningAction SilentlyContinue
Set-Service 'HomeGroupProvider' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableRemoteAssistance'])) {
    $content .= "# Disable remote assistance
Write-Host 'Disabling remote assistance...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Type DWord -Value 0
Get-Service -Name RemoteAccess | Set-Service -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableRemoteDesktop'])) {
    $content .= "# Disable remote desktop
Write-Host 'Disabling remote desktop...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableDriverUD'])) {
    $content .= "# Disable automatic drivers update
Write-Host 'Disabling automatic drivers update...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\PolicyManager\default\Update' -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\MICROSOFT\Windows\CurrentVersion\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['installnet35'])) {
    $content .= "# Install .NET 3.5
Write-Host 'Installing .NET 3.5...'
Dism /online /Enable-Feature /FeatureName:NetFx3 /quiet /norestart" . "\r\n\r\n";
}

if(isset($_GET['disableSuper'])) {
    $content .= "# Disable Superfetch serice
Write-Host 'Disable Superfetch service...'
Stop-Service 'SysMain' -WarningAction SilentlyContinue
Set-Service 'SysMain' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableFast'])) {
    $content .= "# Disable 'Fast Startup'
Write-Host 'Disabling Fast Startup...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['disableAutoPlay'])) {
    $content .= "# Disable Autoplay and Autorun
Write-Host 'Disabling Autoplay and Autorun...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
    New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableSticky'])) {
    $content .= "# Disable 'Sticky Keys' prompts
Write-Host 'Disabling Sticky Keys prompt...'
Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Type String -Value '506'" . "\r\n\r\n";
}

if(isset($_GET['enableNumlock'])) {
    $content .= "# Enable NumLock after startup
Write-Host 'Enabling NumLock after startup...'
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
Write-Host 'Disabling Windows Media Player...'
Disable-WindowsOptionalFeature -Online -FeatureName 'WindowsMediaPlayer' -NoRestart -WarningAction SilentlyContinue | Out-Null
Stop-Service 'WMPNetworkSvc' -WarningAction SilentlyContinue
Set-Service 'WMPNetworkSvc' -StartupType Disabled" . "\r\n\r\n";
}

if(isset($_GET['disableWFC'])) {
    $content .= "# Disable 'Work Folders Client'
Write-Host 'Disabling Work Folders Client...'
Disable-WindowsOptionalFeature -Online -FeatureName 'WorkFolders-Client' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableXPS'])) {
    $content .= "# Disable XPS serives
Write-Host 'Disabling XPS...'
Disable-WindowsOptionalFeature -Online -FeatureName 'Printing-XPSServices-Features' -NoRestart -WarningAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName 'Xps-Foundation-Xps-Viewer' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableIE11'])) {
    $content .= "# Disable Internet Explorer 11
Write-Host 'Disabling Internet Explorer 11...'
Disable-WindowsOptionalFeature -Online -FeatureName 'internet-explorer-optional-amd64' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['setHighPerformance'])) {
    $content .= "# Set Power Plan to High Performance
Write-Host 'Setting Power Plan to High Performance...'
\$HighPerf = powercfg -l | ForEach-Object{if(\$_.contains('High performance')) {\$_.split()[3]}}
\$CurrPlan = $(powercfg -getactivescheme).split()[3]
if (\$CurrPlan -ne \$HighPerf) {powercfg -setactive \$HighPerf}" . "\r\n\r\n";
}

if(isset($_GET['updateHosts'])) {
    $content .= "# Update Hosts file
Write-Host 'Updating Hosts file...'
If (!(Test-Path \"C:\Windows\System32\drivers\\etc\hosts.OLD\")) {
	Remove-Item \"C:\Windows\System32\drivers\\etc\HOSTS.OLD\"  2>&1 | Out-Null
}
\$url = 'http://winhelp2002.mvps.org/hosts.txt'
\$output = \"C:\Users\\\$env:username\Desktop\hosts\"
Invoke-WebRequest \$url -OutFile \$output
Rename-Item \"C:\Windows\System32\drivers\\etc\hosts\" HOSTS.OLD 2>&1 | Out-Null
Move-Item \"C:\Users\\\$env:username\Desktop\\hosts\" -Destination \"C:\Windows\System32\drivers\\etc\hosts\" 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['optoutDEP'])) {
    $content .= "# Opt out of 'Data Execution Prevention'
Write-Host 'Opting out of Data Execution Prevention...'
bcdedit /set `{current`} nx OptOut | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['enableF8'])) {
    $content .= "# 
Write-Host 'Enabling F8 Boot Menu Options...'
bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['enableHibernation'])) {
    $content .= "# Enable Hibernation
Write-Host 'Enabling Hibernation...'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Power' -Name 'HibernteEnabled' -Type Dword -Value 1
If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Type Dword -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableOneDrive'])) {
    $content .= "# Disable OneDrive
Write-Host 'Disabling OneDrive...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['uninstallOneDrive'])) {
    $content .= "# Uninstall OneDrive
Write-Host \"Uninstalling OneDrive...\"
Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
Start-Sleep -s 3
\$onedrive = \"\$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe\"
If (!(Test-Path \$onedrive)) {
    \$onedrive = \"\$env:SYSTEMROOT\System32\OneDriveSetup.exe\"
}
Start-Process \$onedrive \"/uninstall\" -NoNewWindow -Wait
Start-Sleep -s 3
Stop-Process -Name explorer -ErrorAction SilentlyContinue
Start-Sleep -s 3
Remove-Item \"\$env:USERPROFILE\OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item \"\$env:LOCALAPPDATA\Microsoft\OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item \"\$env:PROGRAMDATA\Microsoft OneDrive\" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item \"\$env:SYSTEMDRIVE\OneDriveTemp\" -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path \"HKCR:\")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path \"HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path \"HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Recurse -ErrorAction SilentlyContinue" . "\r\n\r\n";
}

if(isset($_GET['enableWSL'])) {
    $content .= "# Insatll Linux Subsystem
Write-Host 'Installing Linux Subsystem...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Type DWord -Value 1
Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -NoRestart -WarningAction SilentlyContinue | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['enableStorage'])) {
    $content .= "# Enable Storage Sense
Write-Host 'Enabling Storage Sense...'
If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy')) {
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['installChoco'])) {
    $content .= "# Install Chocolatey
Write-Host 'Installing Chocolatey...'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 2>&1 | Out-Null" . "\r\n\r\n";
}

if($_GET['installPrograms'] <> "") {
	$programsToInstall = rtrim($_GET['installPrograms'],' ');
    $content .= "# Install Programs
Write-Host 'Installing Programs...'
choco install " . $programsToInstall . " -y" . "\r\n\r\n";
}

if(isset($_GET['chocoTask'])) {
    $content .= "# Create a scheduled task for chocolatey
Write-Host 'Creating a scheduled task for chocolatey'
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

if(isset($_GET['setDNS'])) {
    $content .= "# Set the DNS to google DNS
Write-Host 'Setting the DNS to google DNS...'
Set-DnsClientServerAddress -InterfaceIndex 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15, 17, 18, 19, 20 -ServerAddresses ('8.8.8.8','8.8.4.4') 2>&1 | Out-Null
ipconfig.exe /flushdns 2>&1 | Out-Null
ipconfig.exe /renew 2>&1 | Out-Null" . "\r\n\r\n";
}

if ($_GET['newPCName'] <> "") {
    $content .= "# Rename the PC 
Write-Host 'Renaming the PC...'
Rename-Computer -NewName " . $_GET['newPCName'] . " 2>&1 | Out-Null" . "\r\n\r\n";
}

if(isset($_GET['disableSuggestions'])) {
    $content .= "# Disable silent installation and suggestion of windows app
Write-Host 'Disabling silent installation and suggestion of windows app...'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338393Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent')) {
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableAppPrompt'])) {
    $content .= "# Disable 'You have new apps that can open this type of file' prompt
Write-Host 'Disabling You have new apps that can open this type of file prompt...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name 'NoNewAppAlert' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableStorePrompt'])) {
    $content .= "# Disable 'Look for an app in the store' prompt
Write-Host 'Disabling Look for an app in the store prompt...'
If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer')) {
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name 'NoUseStoreOpenWith' -Type DWord -Value 1" . "\r\n\r\n";
}

if(isset($_GET['disableDVR'])) {
    $content .= "# Disable Xbox DVR
Write-Host 'Disabling Xbox DVR...'
If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Type DWord -Value 0" . "\r\n\r\n";
}

if(isset($_GET['uninstallApps'])) {
    $content .= "# Uninstall default Microsoft applications
Write-Host 'Uninstalling default Microsoft applications...'
\$windowsApps = @('Microsoft.3DBuilder', 'Microsoft.BingFinance', 'Microsoft.BingNews', 'Microsoft.BingSports', 'Microsoft.BingWeather', 'Microsoft.Getstarted', 'Microsoft.MicrosoftOfficeHub', 
'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.Office.OneNote', 'Microsoft.People', 'Microsoft.SkypeApp', 'Microsoft.Windows.Photos', 'Microsoft.WindowsAlarms', 'Microsoft.WindowsCamera', 
'microsoft.windowscommunicationsapps', 'Microsoft.WindowsMaps', 'Microsoft.WindowsPhone', 'Microsoft.WindowsSoundRecorder', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'Microsoft.AppConnector', 
'Microsoft.ConnectivityStore', 'Microsoft.Office.Sway', 'Microsoft.Messaging', 'Microsoft.CommsPhone', 'Microsoft.MicrosoftStickyNotes', 'Microsoft.OneConnect', 'Microsoft.WindowsFeedbackHub', 
'Microsoft.MinecraftUWP', 'Microsoft.MicrosoftPowerBIForWindows', 'Microsoft.NetworkSpeedTest', 'Microsoft.MSPaint', 'Microsoft.Microsoft3DViewer', 'Microsoft.RemoteDesktop', '9E2F88E3.Twitter', 
'king.com.CandyCrushSodaSaga', '4DF9E0F8.Netflix', 'Drawboard.DrawboardPDF', 'D52A8D61.FarmVille2CountryEscape', 'GAMELOFTSA.Asphalt8Airborne', 'flaregamesGmbH.RoyalRevolt2', 
'AdobeSystemsIncorporated.AdobePhotoshopExpress', 'ActiproSoftwareLLC.562882FEEB491', 'D5EA27B7.Duolingo-LearnLanguagesforFree', 'Facebook.Facebook', '46928bounde.EclipseManager', 
'A278AB0D.MarchofEmpires', 'KeeperSecurityInc.Keeper', 'king.com.BubbleWitch3Saga', '89006A2E.AutodeskSketchBook', 'CAF9E577.Plex', 'king.com.CandyCrushSaga', 'A278AB0D.DisneyMagicKingdoms',
'828B5831.HiddenCityMysteryofShadows', 'Microsoft.GetHelp', 'Microsoft.Wallet');
foreach(\$app in \$windowsApps) {
    Get-AppxPackage \$app | Remove-AppxPackage;
}" . "\r\n\r\n";
}

if(isset($_GET['deleteTemp'])) {
    $content .= "# Delete temp files
Write-Host 'Deleting temp files...'
\$tempfolders = @('C:\Windows\Temp\*', 'C:\Windows\Prefetch\*', 'C:\Documents and Settings\*\Local Settings\temp\*', 'C:\Users\*\Appdata\Local\Temp\*', 'C:\Users\$env:username\Desktop\Programs\')
Remove-Item \$tempfolders -force -recurse 2>&1 | Out-Null
function Delete() {
    \$Invocation = (Get-Variable MyInvocation -Scope 1).Value
    \$Path =  \$Invocation.MyCommand.Path
    Remove-Item \$Path
}" . "\r\n\r\n";
}

if(!isset($_GET['restartPC'])) {
    $content .= "# Finishing
Write-Host 'Press any key to continue...' -ForegroundColor Black -BackgroundColor White
\$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')";
} else {
	$content .= "# Restart the PC
Write-Host 'Press any key to restart your PC...' -ForegroundColor Black -BackgroundColor White
\$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host 'Restarting the PC...'
Restart-Computer";
}


echo $content;
