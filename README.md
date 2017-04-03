# Lability based Windows Lab

This lab is a new installment of my previous https://github.com/dbroeglin/windows-lab 
Vagrant based Windows Lab.

## Getting started

You will need the Lability and InvokeBuild powershell modules:

    Find-Module InvokeBuild,Lability | Install-Module

    # TODO: Lability setup

If you plan on working with Netscaler :

    Find-Module Netscaler | Install-Module

See below for more information on setting up Netscaler.

Then to configure and start the lab:

    Invoke-Build Build

To rinse and repeat:

    Invoke-Build Clean, Build

To rinse and repeat _one_ VM only:

    Invoke-Build ReBuild -VMName DC01

A full cleanup can be done with (careful though, this even cleans up parts of Lability) :

    Invoke-Build MrProper


## Troubleshooting

### Running the DSC configuration 

    Invoke-Command -Credential $LabCredential -VMName LAB-DC01 { 
        Start-DscConfiguration -UseExisting -Debug -Wait
    }

### Troubleshooting DSC operations

The following commands might help troubleshooting (credentials are set globally when the build script is called) :

    Invoke-Command -VMName LAB-DC01 -Credential $LabCredential { 
        Get-WinEvent -LogName 'Microsoft-Windows-Powershell/Operational' | 
            Select -First 10 | 
            Select -Expand Message
    }
    
Note: the `-VMname` parameter works only with Win10 or Windows Server 2016.

## Netscaler setup

### Download and register a media for netscaler

1. Download _NetScaler VPX Express_ from https://www.citrix.com/downloads/netscaler-adc/ (a
log in is required, just create a Citrix account)
1. Unzip the downloaded file:
        Expand-Archive $HOME\Downloads\NSVPX-HyperV-11.1-50.10_nc.zip
1. Register the netscaler disk as a Lability media:

        $NSVPX111 = @{
            Id              = "NSVPX_11_1"
            Filename        = "NSVPX-HyperV-11.1-50.10_nc.vhd"
            Description     = "Citrix NetScaler 11.1 VPX Build 50.10"
            Architecture    = "x64"
            MediaType       = "VHD"
            OperatingSystem = "Linux"
            Uri             = "$PWD\Downloads\NSVPX-HyperV-11.1-50.10_nc\Virtual Hard Disks\Dynamic.vhd"
            # Checksum      = 4C452571BC7C8E35D8AD92CF01A5805C # Use Get-FileHash -Algorithm MD5
        }
        Register-LabMedia @NSVPX111 -Force

# Starting the lab and preping Netscaler

In the lab use the following configuration:

    @{
        NodeName                    = 'NS01'
        # NSIP: 10.0.0.10 is not set by lability but here to be used by scripts
        NSIP                        = '10.0.0.10'
        SNIP                        = '10.0.0.11'
        Lability_SwitchName         = @('Labnet')
        Lability_ProcessorCount     = 2
        Lability_StartupMemory      = 2GB
        Lability_Media              = 'NSVPX_11_1'
        Lability_MacAddress         = @('00:15:5D:7E:31:00')
    } 

and configure the NSIP through the NetScaler console: (NSIP: 10.0.0.10, 
Netmask 255.255.255.0, GW: 10.0.0.254)

Install the Netscaler PowerShell module: 

    Find-Module Netscaler | Install-Module

The _Host ID_ will be `00155d7e3100`. Get a license file, save it as `license.lic` 
and finish the Netscaler configuration with the following commands (this is the 
minimal configuration required to access the Web configuration GUI):

    $SecurePassword = ConvertTo-SecureString 'nsroot' -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ('nsroot', $SecurePassword)
    $session = Connect-NetScaler -IPAddress 10.0.0.10 -Credential $Credential -PassThru
    Set-NSHostname  -Hostname ns01 -Session $Session -Force
    Set-NSTimeZone -TimeZone 'GMT+01:00-CET-Europe/Zurich' -Force
    Add-NSDnsNameServer -IPAddress 10.0.0.1
    Add-NSIPResource -IPAddress 10.0.0.11 -SubnetMask 255.255.255.0 -Type SNIP  -Session $session
    Install-NSLicense -Path .\license.lic -Session $Session
    Restart-NetScaler -WarmReboot -Wait -SaveConfig -Session $Session -Force