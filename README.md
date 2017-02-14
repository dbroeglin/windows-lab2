# Lability based Windows Lab

This lab is a new installment of my previous https://github.com/dbroeglin/windows-lab 
Vagrant based Windows Lab.

## Getting started

    Find-Module InvokeBuild,Lability | Install-Module

    # TODO: Lability setup

Then to configure and start the lab:

    Invoke-Build -File Build.ps1 -Task Build

To rinse and repeat:

    Invoke-Build -File Build.ps1 -Task Clean,Build

To rinse and repeat _one_ VM only:

    Invoke-Build -File Build.ps1 -Task ReBuild -VMName DC01
    
## Troubleshooting

The following commands might help troubleshooting (credentials are set globally when the build script is called) :

    Invoke-Command -VMName LAB-DC01 -Credential $LabCredential { 
        Get-WinEvent -LogName 'Microsoft-Windows-Powershell/Operational' | 
            Select -First 10 | 
            Select -Expand Message
    }
    
Careful: the `-VMname` parameter works only with Win10 or Windows Server 2016.

## Netscaler setup

Register a media for Netscaler:

    $NSVPX111 = @{
        Id = "NSVPX_11_1";
        Filename = "NSVPX-HyperV-11.1-50.10_nc.vhd"
        Description = "Citrix NetScaler 11.1 VPX Build 50.10";
        Architecture = "x64";
        MediaType = "VHD";
        OperatingSystem = "Linux";
        Uri = "${HOME}\Downloads\NSVPX-HyperV-11.1-50.10_nc\NSVPX-11.1-48.10_nc.vhd";
    }
    Register-LabMedia @NSVPX111 -Force;

Start the lab 
with a configuration like:

    @{
        NodeName                    = 'NS01'
        # NSIP: 10.0.0.10, SNIP: 10.0.0.11
        Lability_SwitchName         = @('Labnet', 'Labnet')
        Lability_ProcessorCount     = 2
        Lability_StartupMemory      = 2GB
        Lability_Media              = 'NSVPX_11_1'
        Lability_MacAddress         = @('00:15:5D:7E:31:00', '00:15:5D:7E:31:01')
    } 

and configure the NSIP through the NetScaler console.

Install the Netscaler PowerShell module: 

    Find-Module Netscaler | Install-Module

The _Host ID_ will be `00155d7e3100`. Get a license file and finish the Netscaler 
configuration with the following commands:

    $session = Connect-NetScaler -IPAddress 10.0.0.10 -PassThru
    Add-NSIPResource -IPAddress 10.0.0.11 -SubnetMask 255.255.255.0 -Type SNIP  -Session $session
    Set-NSHostname  -Hostname ns01 -Session $Session -Force
    Install-NSLicense -Path .\license.lic -Session $Session
    Restart-NetScaler -WarmReboot -Wait -SaveConfig -Session $Session -Force
    