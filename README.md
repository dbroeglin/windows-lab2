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
