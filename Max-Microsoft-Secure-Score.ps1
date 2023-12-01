Start-Transcript -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Max-Microsoft-Secure-Score-check.log" -Append

# Set RunAsPPL value in Lsa
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_25
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "RunAsPPL" -Value 1 -Type DWord

# Disable EnumerateAdministrators in CredUI
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_29
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
# Now, set the registry value
Set-ItemProperty -Path $registryPath -Name "EnumerateAdministrators" -Value 0 -Type DWord

# Enable Virtualization Based Security
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_2080
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $registryPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
# Set RequirePlatformSecurityFeatures for Secure Boot and DMA protection
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $registryPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord
# Enable Credential Guard with UEFI lock
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "LsaCfgFlags" -Value 1 -Type DWord

#Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_72
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord

#Disable 'Allow Basic authentication' for WinRM Service
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_74
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "AllowBasic" -Value 0 -Type DWord

#Disable 'Allow Basic authentication' for WinRM Client
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_73
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "AllowBasic" -Value 0 -Type DWord

#Disable Anonymous enumeration of shares
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_88
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "RestrictAnonymous" -Value 1 -Type DWord

#Disable the local storage of passwords and credentials
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_93
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "DisableDomainCreds" -Value 1 -Type DWord

#Disable 'Continue running background apps when Google Chrome is closed'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_19
$registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "BackgroundModeEnabled" -Value 0 -Type DWord

#Disable running or installing downloaded software with invalid signature
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_79
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "RunInvalidSignatures" -Value 0 -Type DWord

#Disable 'Autoplay for non-volume devices'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_67
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
Set-ItemProperty -Path $registryPath -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord


#Enable 'Microsoft network client: Digitally sign communications (always)'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_95
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-ItemProperty -Path $registryPath -Name "RequireSecuritySignature" -Value 1 -Type DWord

#Block outdated ActiveX controls for Internet Explorer
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_85
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext"
Set-ItemProperty -Path $registryPath -Name "VersionCheckEnabled" -Value 1 -Type DWord

#Disable JavaScript on Adobe DC
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_97
$registryPath = "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown"
# Check if the registry path exists, and create it if it doesn't
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "bDisableJavaScript" -Value 1 -Type DWord

#Disable IP source routing
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_82
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Set-ItemProperty -Path $registryPath -Name "DisableIPSourceRouting" -Value 2 -Type DWord

#Set IPv6 source routing to highest protection
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_81
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Set-ItemProperty -Path $registryPath -Name "DisableIPSourceRouting" -Value 2 -Type DWord

#Enable 'Chrome Block third party cookies'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_23
$registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "BlockThirdPartyCookies" -Value 1 -Type DWord

#Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_46
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "DisableNotifications" -Value 1 -Type DWord

#Disable Solicited Remote Assistance
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_87
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
Set-ItemProperty -Path $registryPath -Name "fAllowToGetHelp" -Value 0 -Type DWord

#Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_70
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $registryPath -Name "NoAutorun" -Value 1 -Type DWord

#Enable Automatic Updates Office
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_15
$registryPath = "HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate"
Set-ItemProperty -Path $registryPath -Name "enableautomaticupdates" -Value 1 -Type DWord

#Enable 'Hide Option to Enable or Disable Updates' Office
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_16
$registryPath = "HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate"
Set-ItemProperty -Path $registryPath -Name "hideenabledisableupdates" -Value 1 -Type DWord

#Disable 'Autoplay' for all drives
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_69
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $registryPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

#Disable SMBv1 client driver
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_53
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "Start" -Value 4 -Type DWord

#Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_49
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "DisableNotifications" -Value 1 -Type DWord

#Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_43
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path -Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Registry -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "DisableNotifications" -Value 1 -Type DWord

#120 Disable 'Anonymous enumeration of SAM accounts'
#https://security.microsoft.com/securescore?viewid=actions&actionId=scid_68
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $registryPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord

Sleep 2

$registryChecks = @(
    @{
        Description = "# Set RunAsPPL value in Lsa"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "RunAsPPL"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable EnumerateAdministrators in CredUI"
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
        PropertyName = "EnumerateAdministrators"
        ExpectedValue = 0
    },
    @{
        Description = "# Enable Virtualization Based Security"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        PropertyName = "EnableVirtualizationBasedSecurity"
        ExpectedValue = 1
    },
    @{
        Description = "# Set RequirePlatformSecurityFeatures for Secure Boot and DMA protection"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        PropertyName = "RequirePlatformSecurityFeatures"
        ExpectedValue = 3
    },
    @{
        Description = "# Enable Credential Guard with UEFI lock"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "LsaCfgFlags"
        ExpectedValue = 1
    },
    @{
        Description = "# Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "LmCompatibilityLevel"
        ExpectedValue = 5
    },
    @{
        Description = "# Disable 'Allow Basic authentication' for WinRM Service"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        PropertyName = "AllowBasic"
        ExpectedValue = 0
    },
    @{
        Description = "# Disable 'Allow Basic authentication' for WinRM Client"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        PropertyName = "AllowBasic"
        ExpectedValue = 0
    },
    @{
        Description = "# Disable Anonymous enumeration of shares"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "RestrictAnonymous"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable the local storage of passwords and credentials"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "DisableDomainCreds"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable 'Continue running background apps when Google Chrome is closed'"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        PropertyName = "BackgroundModeEnabled"
        ExpectedValue = 0
    },
    @{
        Description = "# Disable running or installing downloaded software with invalid signature"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"
        PropertyName = "RunInvalidSignatures"
        ExpectedValue = 0
    },
    @{
        Description = "# Disable 'Autoplay for non-volume devices'"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        PropertyName = "NoAutoplayfornonVolume"
        ExpectedValue = 1
    },
    @{
        Description = "# Enable 'Microsoft network client: Digitally sign communications (always)'"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        PropertyName = "RequireSecuritySignature"
        ExpectedValue = 1
    },
    @{
        Description = "# Block outdated ActiveX controls for Internet Explorer"
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext"
        PropertyName = "VersionCheckEnabled"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable JavaScript on Adobe DC"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown"
        PropertyName = "bDisableJavaScript"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable IP source routing"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        PropertyName = "DisableIPSourceRouting"
        ExpectedValue = 2
    },
    @{
        Description = "# Set IPv6 source routing to highest protection"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        PropertyName = "DisableIPSourceRouting"
        ExpectedValue = 2
    },
    @{
        Description = "# Enable 'Chrome Block third party cookies'"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        PropertyName = "BlockThirdPartyCookies"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        PropertyName = "DisableNotifications"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        PropertyName = "DisableNotifications"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable 'Anonymous enumeration of SAM accounts'"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        PropertyName = "RestrictAnonymousSAM"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable 'Autoplay' for all drives"
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        PropertyName = "NoDriveTypeAutoRun"
        ExpectedValue = 255
    },
    @{
        Description = "# Disable SMBv1 client driver"
        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        PropertyName = "Start"
        ExpectedValue = 4
    },
    @{
        Description = "# Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        PropertyName = "DisableNotifications"
        ExpectedValue = 1
    },
    @{
        Description = "# Disable Solicited Remote Assistance"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        PropertyName = "fAllowToGetHelp"
        ExpectedValue = 0
    },
    @{
        Description = "# Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'"
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        PropertyName = "NoAutorun"
        ExpectedValue = 1
    },
    @{
        Description = "# Enable Automatic Updates Office"
        RegistryPath = "HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate"
        PropertyName = "enableautomaticupdates"
        ExpectedValue = 1
    },
    @{
        Description = "# Enable 'Hide Option to Enable or Disable Updates' Office"
        RegistryPath = "HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate"
        PropertyName = "hideenabledisableupdates"
        ExpectedValue = 1
    }
    # Add more entries in the same format for each registry change you've made
)

foreach ($check in $registryChecks) {
    $value = Get-ItemProperty -Path $check['RegistryPath'] -Name $check['PropertyName'] -ErrorAction SilentlyContinue
    $result = if ($value) {
        $value = $value.$($check['PropertyName'])
        if ($value -eq $check['ExpectedValue']) {
            "TRUE"
        } else {
            "FALSE"
        }
    } else {
        "FALSE"
    }
    
    Write-Output "$($result) $($check['Description'])`n` $($check['PropertyName']) = $($value)"
}
Stop-Transcript