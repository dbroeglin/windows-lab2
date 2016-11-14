[CmdletBinding()]
Param(
    [String]$VMName
)

if (! $Global:LabilityCredentials) {
    $Global:LabilityCredentials = Get-Credential -UserName "Administrator" -Message "Lab admin password"

    # Credentials to use after the domain is created and guests are joined
    $Global:LabCredentials = New-Object -Type System.Management.Automation.PSCredential `
        -ArgumentList "LAB\Administrator",$LabilityCredentials.Password
}

[String]$ConfigurationData = Join-Path $PSScriptRoot LabConfig.psd1
$ConfigurationPath = (Get-LabHostDefault).ConfigurationPath

task Build {
    . $PSScriptRoot\LabConfig.ps1

    LabConfig -ConfigurationData $ConfigurationData `
        -OutputPath $ConfigurationPath `
        -Credential $Global:LabilityCredentials
    Start-LabConfiguration -ConfigurationData $ConfigurationData `
        -Credential $Global:LabilityCredentials -Verbose
    Start-Lab -ConfigurationData $ConfigurationData
}

task ReBuild { 
    assert($VMName)
    Reset-LabVM -Name $VMName -ConfigurationData $ConfigurationData `
        -Path $ConfigurationPath -NoSnapshot `
        -Credential $global:LabilityCredentials -Verbose | Start-VM
}

task Clean {
    Remove-LabConfiguration -ConfigurationData .\LabConfig.psd1    
}

# New-NetIPAddress -IPAddress 10.0.0.254 -PrefixLength 24 -InterfaceIndex  (Get-NetAdapter -Name "vEthernet (Internal)").InterfaceIndex
# New-NetNat -Name LabNat -InternalIPInterfaceAddressPrefix 10.0.0.0/24