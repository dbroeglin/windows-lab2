# Lability based Windows Lab

This lab is a new installment of my previous https://github.com/dbroeglin/windows-lab 
Vagrant based Windows Lab.

## Getting started

    Install-Module Lability,InvokeBuild

    # TODO: Lability setup

Then to configure and start the lab:

    Invoke-Build -File Build.ps1 -Task Build

To rinse and repeat:

    Invoke-Build -File Build.ps1 -Task Clean,Build

To rinse and repeat _one_ VM only:

    Invoke-Build -File Build.ps1 -Task ReBuild -VMName DC01