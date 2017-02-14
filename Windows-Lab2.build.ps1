[CmdletBinding()]
Param(
    [String]$VMName,

    [String]$ConfigurationFile = "LabConfig.psd1",

    [String]$NodeName          = "NS01",

    [String]$NsUsername        = "nsroot",

    [String]$NsPassword        = "nsroot"
)

if (! $Global:LabilityCredentials) {
    $Global:LabilityCredentials = Get-Credential -UserName "Administrator" -Message "Lab admin password"

    # Credentials to use after the domain is created and guests are joined
    $Global:LabCredentials = New-Object -Type System.Management.Automation.PSCredential `
        -ArgumentList "LAB\Administrator",$LabilityCredentials.Password
}

[String]$ConfigurationPath = Join-Path $PSScriptRoot $ConfigurationFile

Import-LocalizedData -BaseDirectory $PSScriptRoot -FileName $ConfigurationFile -BindingVariable ConfigurationData


task Build {
    . $PSScriptRoot\LabConfig.ps1

    LabConfig -ConfigurationData $ConfigurationPath `
        -OutputPath (Get-LabHostDefault).ConfigurationPath `
        -Credential $Global:LabilityCredentials
    Start-LabConfiguration -ConfigurationData $ConfigurationPath `
        -Credential $Global:LabilityCredentials -Verbose
    Start-Lab -ConfigurationData $ConfigurationPath
}

task ReBuild { 
    assert($VMName)
    Reset-LabVM -Name $VMName -ConfigurationData $ConfigurationPath `
        -Path (Get-LabHostDefault).ConfigurationPath -NoSnapshot `
        -Credential $global:LabilityCredentials -Verbose | Start-VM
}

task Clean {
    Remove-LabConfiguration -ConfigurationData $ConfigurationPath    
}

# New-NetIPAddress -IPAddress 10.0.0.254 -PrefixLength 24 -InterfaceIndex  (Get-NetAdapter -Name "vEthernet (Internal)").InterfaceIndex
# New-NetNat -Name LabNat -InternalIPInterfaceAddressPrefix 10.0.0.0/24

task NSPrepare {    
    $Script:NsConfigurationData = $ConfigurationData.AllNodes | Where-Object NodeName -eq $NodeName

    if (!$Script:NsConfigurationData) {
        Write-Error "Unable to find node configuration for NodeName '$NodeName'"
    }
    #Write-Host $( ConvertTo-Json $NsConfigurationData)

    $SecurePassword = ConvertTo-SecureString $NsPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($NsUsername, $SecurePassword)

    $Script:session = Connect-NetScaler -IPAddress $NSConfigurationData.NSIP -Credential $Credentials -PassThru
}

task NSSetup NSPrepare, {
    Add-NSIPResource -IPAddress $NsConfigurationData.SNIP -SubnetMask 255.255.255.0 -Type SNIP -Session $session
    Set-NSHostname  -Hostname $($NsConfigurationData.NodeName.ToLower()) -Session $Session -Force
    if (!(Get-NSSystemFile -FileLocation /nsconfig/license -Filename license.lic -ErrorAction SilentlyContinue)) {
        Install-NSLicense -Path .\license.lic -Session $Session
    } else {
        Write-Host "License file already exists: not uploaded." -ForegroundColor Yellow
    }

    Restart-NetScaler -WarmReboot -Wait -SaveConfig -Session $Session -Force
}

task NSReset NSPrepare, {
    Clear-NSConfig -Level Full -Force -Session $session
}, NSSetup