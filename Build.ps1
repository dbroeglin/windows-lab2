[CmdletBinding()]
Param(
    [switch]$Lab,
    [switch]$Reset,
    [String]$VMName
)
    
$ErrorActionPreference = "Stop"

if (! $Global:LabilityCredentials) {
    $Global:LabilityCredentials = Get-Credential -UserName "Administrator" -Message "Lab admin password"
}

[String]$ConfigurationData = Join-Path $PSScriptRoot LabConfig.psd1
$ConfigurationPath = "C:\Lability\Configurations\"

if ($Lab) {
    . $PSScriptRoot\LabConfig.ps1

    LabConfig -ConfigurationData $ConfigurationData `
        -OutputPath $ConfigurationPath `
        -Credential $Global:LabilityCredentials
    Start-LabConfiguration -ConfigurationData $ConfigurationData `
        -Credential $Global:LabilityCredentials
    Start-Lab -ConfigurationData $ConfigurationData
}

if ($Reset) {
    Reset-LabVM -Name $VMName -ConfigurationData $ConfigurationData `
        -Path $ConfigurationPath -NoSnapshot `
        -Credential $global:LabilityCredentials -Verbose | Start-VM
}

# New-NetIPAddress -IPAddress 10.0.0.254 -PrefixLength 24 -InterfaceIndex  (Get-NetAdapter -Name "vEthernet (Internal)").InterfaceIndex
# New-NetNat -Name LabNat -InternalIPInterfaceAddressPrefix 10.0.0.0/24