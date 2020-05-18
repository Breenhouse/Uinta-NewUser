# Updated 1/28/2020

# A lot of this code adopted from: https://github.com/Sycnex/Windows10Debloater

# ------------------------

# This will run the script as admin.
# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
# Check to see if we are currently running as an administrator
if ($myWindowsPrincipal.IsInRole($adminRole)) {
    # We are running as an administrator, so change the title and background colour to indicate this
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + '(Elevated)'
    Clear-Host
} 
else {
    # We are not running as an administrator, so relaunch as administrator
    # Create a new process object that starts PowerShell
    $newProcess = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
    # Specify the current script path and name as a parameter with added scope and support for scripts with spaces in its path
    $newProcess.Arguments = '-ExecutionPolicy Bypass -File "' + $script:MyInvocation.MyCommand.Path + '"'
    # Indicate that the process should be elevated
    $newProcess.Verb = 'runas'
    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess)
    # Exit from the current, unelevated, process
    exit
}

# ------------------------
	
$host.UI.RawUI.WindowTitle = "Uinta - New User"

Write-Host '######################'
Write-Host '# Uinta Technologies #'
Write-Host '######################'
Write-Host '

For this script to run correctly, you MUST be logged in as target user.

This script:
* Debloats Windows
* Turns off background apps
* Disables background telemetry
'

Pause

Clear-Host

# ------------------------

# Debloat Windows

Clear-Host
Write-Host 'Removing default Microsoft apps...'

$apps = @(
    #Unnecessary Windows 10 AppX Apps
    "*Microsoft.BingNews*"
    "*Microsoft.GetHelp*"
    "*Microsoft.Getstarted*"
    "*Microsoft.Messaging*"
    "*Microsoft.Microsoft3DViewer*"
    "*Microsoft.MicrosoftOfficeHub*"
    #"*Microsoft.MicrosoftSolitaireCollection*"
    "*Microsoft.NetworkSpeedTest*"
    "*Microsoft.Office.Sway*"
    "*Microsoft.OneConnect*"
    "*Microsoft.People*"
    "*Microsoft.Print3D*"
    "*Microsoft.SkypeApp*"
    "*Microsoft.WindowsAlarms*"
    #"*Microsoft.WindowsCamera*"
    "*microsoft.windowscommunicationsapps*"
    "*Microsoft.WindowsFeedbackHub*"
    "*Microsoft.WindowsMaps*"
    #"*Microsoft.WindowsSoundRecorder*"
    "*Microsoft.Xbox.TCUI*"
    "*Microsoft.XboxApp*"
    "*Microsoft.XboxGameOverlay*"
    "*Microsoft.XboxIdentityProvider*"
    "*Microsoft.XboxSpeechToTextOverlay*"
    #"*Microsoft.ZuneMusic*"
    #"*Microsoft.ZuneVideo*"

    # non-Microsoft
    "9E2F88E3.Twitter"
    "PandoraMediaInc.29680B314EFC2"
    "Flipboard.Flipboard"
    "ShazamEntertainmentLtd.Shazam"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.*"
    "king.com.CandyCrushFriends"
    "ClearChannelRadioDigital.iHeartRadio"
    "4DF9E0F8.Netflix"
    "6Wunderkinder.Wunderlist"
    "Drawboard.DrawboardPDF"
    "2FE3CB00.PicsArt-PhotoStudio"
    "D52A8D61.FarmVille2CountryEscape"
    "TuneIn.TuneInRadio"
    "GAMELOFTSA.Asphalt8Airborne"
    "TheNewYorkTimes.NYTCrossword"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "Facebook.Facebook"
    "flaregamesGmbH.RoyalRevolt2"
    "Playtika.CaesarsSlotsFreeCasino"
    "A278AB0D.MarchofEmpires"
    "SlingTVLLC.SlingTV"
    "C27EB4BA.DropboxOEM"
    "5A894077.McAfeeSecurity"
    "SpotifyAB.SpotifyMusic"

    #Sponsored Windows 10 AppX Apps
    #Add sponsored/featured apps to remove in the "*AppName*" format
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"
)

foreach ($app in $apps) {
    echo "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage

    Get-AppXProvisionedPackage -Online |
        where DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

Clear-Host


# ------------------------

#Turns off background apps in Windows 10
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /t REG_DWORD /d 1 /f
Clear-Host

# ------------------------

# Disable telemetry

#Creates a PSDrive to be able to access the 'HKCR' tree
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

#Disables Windows Feedback Experience
Write-Host "Disabling Windows Feedback Experience program"
$Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
If (Test-Path $Advertising) {
    Set-ItemProperty $Advertising Enabled -Value 0
}

#Stops Cortana from being used as part of your Windows Search Function
Write-Host "Stopping Cortana from being used as part of your Windows Search Function"
$Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
If (Test-Path $Search) {
    Set-ItemProperty $Search AllowCortana -Value 0
}

#Stops the Windows Feedback Experience from sending anonymous data
Write-Host "Stopping the Windows Feedback Experience program"
$Period1 = 'HKCU:\Software\Microsoft\Siuf'
$Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
$Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
If (!(Test-Path $Period3)) { 
    mkdir $Period1
    mkdir $Period2
    mkdir $Period3
    New-ItemProperty $Period3 PeriodInNanoSeconds -Value 0
}
        
Write-Host "Adding Registry key to prevent bloatware apps from returning"
#Prevents bloatware applications from returning
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
If (!(Test-Path $registryPath)) {
    Mkdir $registryPath
    New-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
}          

Write-Host "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
$Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
If (Test-Path $Holo) {
    Set-ItemProperty $Holo FirstRunSucceeded -Value 0
}

#Turns off Data Collection via the AllowTelemtry key by changing it to 0
Write-Host "Turning off Data Collection"
$DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
If (Test-Path $DataCollection) {
    Set-ItemProperty $DataCollection AllowTelemetry -Value 0
}

#Disables People icon on Taskbar
Write-Host "Disabling People icon on Taskbar"
$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
If (Test-Path $People) {
    Set-ItemProperty $People PeopleBand -Value 0
}

Write-Host "Removing CloudStore from registry if it exists"
$CloudStore = 'HKCUSoftware\Microsoft\Windows\CurrentVersion\CloudStore'
If (Test-Path $CloudStore) {
    Stop-Process Explorer.exe -Force
    Remove-Item $CloudStore
    Start-Process Explorer.exe -Wait
}

#Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
reg unload HKU\Default_User

#Disables scheduled tasks that are considered unnecessary 
Write-Host "Disabling scheduled tasks"
#Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask
Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask

Clear-Host

# ------------------------

Write-Host "
Script complete!
"
Pause

Exit