[CmdletBinding()]
Param(
    [String]$VMName,
    [String]$ConfigurationFile = "LabConfig.psd1",
    [String]$NodeName          = "NS01",
    [String]$NsUsername        = "nsroot",
    [String]$NsPassword        = "nsroot",
    [String]$LabVmPrefix       = "LAB"
)

if ($VmName) {
    $LabVMName = "$LabVmPrefix-$VMName"
}

if (! $Global:LabilityCredentials) {
    $Global:LabilityCredentials = Get-Credential -UserName "Administrator" -Message "Lab admin password"

    # Credentials to use after the domain is created and guests are joined
    $Global:LabCredentials = New-Object -Type System.Management.Automation.PSCredential `
        -ArgumentList "LAB\Administrator",$LabilityCredentials.Password
}

[String]$ConfigurationPath = Join-Path $PSScriptRoot $ConfigurationFile
[String]$MofConfigurationPath = (Get-LabHostDefault).ConfigurationPath

# Using the localized data hack to load the configuration data in order
# to be backwards compatible with PS v4
Import-LocalizedData -BaseDirectory $PSScriptRoot -FileName $ConfigurationFile -BindingVariable ConfigurationData

task CheckModuleVersions {
    $ConfigurationData.NonNodeData.Lability.DSCResource | ForEach-Object {
        $Spec = $_
        $Module = Get-Module -ListAvailable $_.Name
        if (-not @($Module.Version) -contains $Spec.RequiredVersion) {
            Write-Host -ForegroundColor Red "Mismatch for $($Spec.Name): $($Spec.RequiredVersion) <> $($Module.Version)"
        }
    }
}

task InstallRequiredModules {
    $ConfigurationData.NonNodeData.Lability.DSCResource | ForEach-Object {
        Write-Host "    Import-DscResource -ModuleName $($_.Name) -ModuleVersion $($_.RequiredVersion)"
        Find-Module @_ | Install-Module
    }
}

task Build PrepareDscConfig, {
    Start-LabConfiguration -ConfigurationData $ConfigurationPath `
        -Credential $Global:LabilityCredentials -Verbose

    $Script:NsConfigurationData = $ConfigurationData.AllNodes |
        Where-Object NodeName -like "NS*" | ForEach-Object {
            try {
                $UserDataISOFile = Join-Path (Get-LabHostDefault).DifferencingVhdPath "$($_.NodeName).iso"
                Write-UserData -NSIP $_.NSIP -Netmask $_.Netmask -DefaultGateway $_.Gateway `
                    -DestinationPath $PWD/userdata
                Remove-Item $UserDataISOFile -Force -ErrorAction SilentlyContinue
                New-IsoFile -Media CDR -Source $PWD/userdata -Path $UserDataISOFile -Force

                Set-VMDvdDrive -VMName "$LabVmPrefix-$($_.NodeName)" -Path $UserDataISOFile
            } finally {
                Remove-Item $PWD/userdata -Force -ErrorAction SilentlyContinue
            }
        }

    Start-Lab -ConfigurationData $ConfigurationPath -Verbose
}

task PrepareDscConfig {
    . $PSScriptRoot\LabConfig.ps1

    LabConfig -ConfigurationData $ConfigurationPath `
        -OutputPath $MofConfigurationPath `
        -Credential $Global:LabilityCredentials -Verbose

    Copy-Item -Path $PSScriptRoot\Data\sts.extlab.local.pfx -Destination (Get-LabHostDefault).ResourcePath
}

task ReBuild PrepareDscConfig, {
    assert($VMName)

    Reset-LabVM -Name $VMName -ConfigurationData $ConfigurationPath `
        -Path $MofConfigurationPath -NoSnapshot `
        -Credential $global:LabilityCredentials -Verbose | Start-VM -Verbose
}

task ReApply PrepareDscConfig, {
    assert($VMName)

    Copy-Item (Join-Path $MofConfigurationPath "$VMName.mof") -Destination c:\ -ToSession (
        New-PSSession -VMName $LabVMName -Credential $LabCredentials)
    Invoke-Command -Credential $LabCredentials -VMName $LabVMName {
        Start-DscConfiguration -Debug -Wait -Path "c:\" -Force
    }
}

task Clean {
    # Stop-Lab -ConfigurationData $ConfigurationPath
    Remove-LabConfiguration -ConfigurationData $ConfigurationPath
}

task MrProper Clean, {
    # We did not use Get-LabHostDefault to prevent any risk of
    # wiping off the whole disk should it return null
    Remove-Item -Recurse C:\Lability\Configurations\*
    Remove-Item -Recurse C:\Lability\MasterVirtualHardDisks\*
    Remove-Item -Recurse C:\Lability\VMVirtualHardDisks\*
}

# New-NetIPAddress -IPAddress 10.0.0.254 -PrefixLength 24 -InterfaceIndex  (Get-NetAdapter -Name "vEthernet (Internal)").InterfaceIndex
# New-NetNat -Name LabNat -InternalIPInterfaceAddressPrefix 10.0.0.0/24

task NSPrepare {
    assert($NodeName)

    $Script:NsConfigurationData = $ConfigurationData.AllNodes | Where-Object NodeName -eq $NodeName

    if (!$Script:NsConfigurationData) {
        Write-Error "Unable to find node configuration for NodeName '$NodeName'"
    }
    #Write-Host $( ConvertTo-Json $NsConfigurationData)

    $SecurePassword = ConvertTo-SecureString $NsPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($NsUsername, $SecurePassword)

    $Script:session = Connect-NetScaler -IPAddress $NSConfigurationData.NSIP -Credential $Credentials -PassThru
}

task NSConfig NSPrepare, {
    & "$PSScriptRoot\NSConfig.ps1"
}

task NSSetup NSPrepare, {
    Add-NSIPResource -IPAddress $NsConfigurationData.SNIP -SubnetMask 255.255.255.0 -Type SNIP -Session $session
    Add-NSIPResource -IPAddress $NsConfigurationData.VIP -SubnetMask 255.255.255.0 -Type VIP -Session $session
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



# Source: https://gallery.technet.microsoft.com/scriptcenter/New-ISOFile-function-a8deeffd
function New-IsoFile
{
  <#
   .Synopsis
    Creates a new .iso file
   .Description
    The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders
   .Example
    New-IsoFile "c:\tools","c:Downloads\utils"
    This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders. The folders themselves are included at the root of the .iso image.
   .Example
    New-IsoFile -FromClipboard -Verbose
    Before running this command, select and copy (Ctrl-C) files/folders in Explorer first.
   .Example
    dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE"
    This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx
   .Notes
    NAME:  New-IsoFile
    AUTHOR: Chris Wu
    LASTEDIT: 03/23/2016 14:46:50
 #>

  [CmdletBinding(DefaultParameterSetName='Source')]Param(
    [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,
    [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",
    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null,
    [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER',
    [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),
    [switch]$Force,
    [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard
  )

  Begin {
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe'
    if (!('ISOFile' -as [type])) {
      Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile
{
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)
  {
    int bytes = 0;
    byte[] buf = new byte[BlockSize];
    var ptr = (System.IntPtr)(&bytes);
    var o = System.IO.File.OpenWrite(Path);
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;
    if (o != null) {
      while (TotalBlocks-- > 0) {
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);
      }
      o.Flush(); o.Close();
    }
  }
}
'@
    }

    if ($BootFile) {
      if('BDR','BDRE' -contains $Media) { Write-Warning "Bootable image doesn't seem to work with media type $Media" }
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open()  # adFileTypeBinary
      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname)
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream)
    }

    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE')

    Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media))

    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break }
  }

  Process {
    if($FromClipboard) {
      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break }
      $Source = Get-Clipboard -Format FileDropList
    }

    foreach($item in $Source) {
      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) {
        $item = Get-Item -LiteralPath $item
      }

      if($item) {
        Write-Verbose -Message "Adding item to the target image: $($item.FullName)"
        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.') }
      }
    }
  }

  End {
    if ($Boot) { $Image.BootImageOptions=$Boot }
    $Result = $Image.CreateResultImage()
    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks)
    Write-Verbose -Message "Target image ($($Target.FullName)) has been created"
    $Target
  }
}

function Write-UserData {
    Param(
        [String]$NSIP,
        [String]$Netmask,
        [String]$DefaultGateway,
        [String]$DestinationPath
    )

    [xml]$userdata = @"
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<Environment xmlns:oe="http://schemas.dmtf.org/ovf/environment/1"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
oe:id=""
xmlns="http://schemas.dmtf.org/ovf/environment/1">
<PlatformSection>
<Kind>HYPER-V</Kind>
<Version>2013.1</Version>
<Vendor>CISCO</Vendor>
<Locale>en</Locale>
</PlatformSection>
<PropertySection>
<Property oe:key="com.citrix.netscaler.ovf.version" oe:value="1.0"/>
<Property oe:key="com.citrix.netscaler.platform" oe:value="NS1000V"/>
<Property oe:key="com.citrix.netscaler.orch_env" oe:value="cisco-orch-env"/>
<Property oe:key="com.citrix.netscaler.mgmt.ip" oe:value=""/>
<Property oe:key="com.citrix.netscaler.mgmt.netmask" oe:value=""/>
<Property oe:key="com.citrix.netscaler.mgmt.gateway" oe:value=""/>
</PropertySection>
</Environment>
"@

    $userdata.Environment.PropertySection.Property | ForEach-Object {
        $Property = $_
        switch ($Property.key) {
            "com.citrix.netscaler.mgmt.ip"      { $Property.value = $NSIP }
            "com.citrix.netscaler.mgmt.netmask" { $Property.value = $Netmask }
            "com.citrix.netscaler.mgmt.gateway" { $Property.value = $DefaultGateway }
        }
    }

    $userdata.save($DestinationPath)
}