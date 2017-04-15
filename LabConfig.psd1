@{
    AllNodes = @(
        @{
            NodeName                    = '*'
            InterfaceAlias              = 'Ethernet'
            DefaultGateway              = '10.0.0.254'
            SubnetMask                  = 24
            AddressFamily               = 'IPv4'
            DnsServerAddress            = '10.0.0.1'
            DomainName                  = 'lab.local'
            PSDscAllowPlainTextPassword = $true
            #CertificateFile = "$env:AllUsersProfile\Lability\Certificates\LabClient.cer";
            #Thumbprint = 'AAC41ECDDB3B582B133527E4DE0D2F8FEB17AAB2';
            PSDscAllowDomainUser        = $true; # Removes 'It is not recommended to use domain credential for node X' messages
            Lability_SwitchName         = 'LabNet'
            Lability_ProcessorCount     = 1
            Lability_StartupMemory      = 2GB
            Lability_Media              = '2016_x64_Standard_EN_Eval'
            #Lability_Media              = '2012R2_x64_Standard_EN_V5_Eval'
            Lability_Module             = 'xDscDiagnostics'
        }
        @{
            NodeName                    = 'DC01'
            IPAddress                   = '10.0.0.1'
            DnsServerAddress            = '127.0.0.1'
            Role                        = 'DC'
        }
        @{
            NodeName                    = 'NS01'

            # NSIP: 10.0.0.10 is not set by lability but here to be used by scripts
            NSIP                        = '10.0.0.10'
            VIP                         = '10.0.0.11'
            SNIP                        = '10.0.0.12'

            # Duplicate those for build scripts
            Gateway                     = '10.0.0.254'
            Netmask                     = '255.255.255.0'

            Lability_ProcessorCount     = 2
            Lability_StartupMemory      = 2GB
            Lability_Media              = 'NSVPX_11_1'
            Lability_MacAddress         = '00:15:5D:7E:31:00'
        }
        @{
            NodeName                    = 'NS02'

            # NSIP: 10.0.0.20 is not set by lability but here to be used by scripts
            NSIP                        = '10.0.0.20'

            # Duplicate those for build scripts
            Gateway                     = '10.0.0.254'
            Netmask                     = '255.255.255.0'

            Lability_ProcessorCount     = 2
            Lability_StartupMemory      = 2GB
            Lability_Media              = 'NSVPX_11_1'
            Lability_MacAddress         = '00:15:5D:7E:31:01'
        }
        <#
        @{
            NodeName                = 'JAHIA01'
            IPAddress               = '10.0.0.31'
            Role                    = @('JOINED', 'JAHIA')
            Lability_Resource       = @('jdk-8u112-windows-x64.exe')
        }
        #>
        @{
            NodeName                = 'ADFS01'
            Role                    = @('JOINED', 'ADFS')
            Lability_Resource       = @('sts.extlab.local.pfx')

            IPAddress               = '10.0.0.32'
            AdfsCertThumbprint      = "1BC84A035D2264F1DB41A40B24691119B9616F79"
            AdfsDisplayName         = "LAB ADFS"
            AdfsFQDN                = "sts.extlab.local"
        }
        @{
            NodeName                = 'WEB01'
            IPAddress               = '10.0.0.33'
            Role                    = @('JOINED', 'WEB')
            Lability_Resource       = @('wwa.extlab.local.pfx')
        }
    );
    NonNodeData = @{
        Lability = @{
            EnvironmentPrefix = 'LAB-';
            Media = @(
                @{
                    Id              = "NSVPX_11_1"
                    Filename        = "NSVPX-HyperV-11.1-50.10_nc.vhd"
                    Description     = "Citrix NetScaler 11.1 VPX Build 50.10"
                    Architecture    = "x64"
                    MediaType       = "VHD"
                    OperatingSystem = "Linux"
                    Uri             = "file:///Sources/windows-lab2/Downloads/NSVPX-HyperV-11.1-50.10_nc/Virtual Hard Disks/Dynamic.vhd"
                    # Checksum      = 4C452571BC7C8E35D8AD92CF01A5805C # Use Get-FileHash -Algorithm MD5
                }
            );
            Network = @(
                @{ Name = 'Labnet';   Type = 'Internal'; }
                @{ Name = 'Internet'; Type = 'External'; NetAdapterName = 'Ethernet'; AllowManagementOS = $true; }
                # @{ Name = 'Corpnet'; Type = 'External'; NetAdapterName = 'Ethernet'; AllowManagementOS = $true; }
                <#
                    IPAddress: The desired IP address.
                    InterfaceAlias: Alias of the network interface for which the IP address should be set. <- Use NetAdapterName
                    DefaultGateway: Specifies the IP address of the default gateway for the host. <- Not needed for internal switch
                    Subnet: Local subnet CIDR (used for cloud routing).
                    AddressFamily: IP address family: { IPv4 | IPv6 }
                #>
            );
            Module = @(
                ## Downloads the latest published module version from the PowerShell Gallery
                @{ Name = 'xDscDiagnostics' }
            )
            DSCResource = @(
                @{ Name = 'xComputerManagement';          RequiredVersion = '1.8.0.0'  }
                @{ Name = 'xSmbShare';                    RequiredVersion = '2.0.0.0'  }
                @{ Name = 'xNetworking';                  RequiredVersion = '3.2.0.0'  }
                @{ Name = 'xActiveDirectory';             RequiredVersion = '2.9.0.0'  }
                @{ Name = 'xDnsServer';                   RequiredVersion = '1.7.0.0'  }
                @{ Name = 'xDhcpServer';                  RequiredVersion = '1.3.0.0'  }
                @{ Name = 'xPSDesiredStateConfiguration'; RequiredVersion = '6.0.0.0'  }
                @{ Name = 'xCertificate';                 RequiredVersion = '2.4.0.0'  }
                @{ Name = 'xWebAdministration';           RequiredVersion = '1.17.0.0' }
                ## The 'GitHub# provider can download modules directly from a GitHub repository, for example:
                ## @{ Name = 'Lability'; Provider = 'GitHub'; Owner = 'VirtualEngine'; Repository = 'Lability'; Branch = 'dev'; }
            );
            Resource = @(
                @{
                    Id = 'sts.extlab.local.pfx'
                    Filename = 'sts.extlab.local.pfx'
                    Uri = 'http://dummy'
                    DestinationPath = '\Downloads'
                }
                @{
                    Id = 'wwa.extlab.local.pfx'
                    Filename = 'wwa.extlab.local.pfx'
                    Uri = 'http://dummy'
                    DestinationPath = '\Downloads'
                }
               @{
                    Id = 'jdk-8u112-windows-x64.exe'
                    Filename = 'jdk-8u112-windows-x64.exe'
                    Uri = 'http://oracle_would_not_work_see_README'
                    Checksum = '1C765B83260C3E691A7B716E21B290C7'
                    DestinationPath = '\Downloads'
                }
            );
        };
    };
};
