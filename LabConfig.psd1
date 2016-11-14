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
            Lability_SwitchName         = 'Labnet'
            Lability_ProcessorCount     = 1
            Lability_StartupMemory      = 2GB
            Lability_Media              = '2016_x64_Standard_EN_Eval'           
            #Lability_Media              = '2012R2_x64_Standard_EN_V5_Eval'
            Lability_Module             = 'xDscDiagnostics'
        }
        @{
            NodeName                = 'DC01'
            IPAddress               = '10.0.0.1'
            DnsServerAddress        = '127.0.0.1'
            Role                    = 'DC'
        }   
        <#     
        @{
            NodeName                = 'JAHIA01' 
            IPAddress               = '10.0.0.31'
            Role                    = @('JOINED', 'JAHIA')
            Lability_Resource       = @('jdk-8u112-windows-x64.exe')
        }
        @{
            NodeName                = 'ADFS01' 
            IPAddress               = '10.0.0.32'
            Role                    = @('JOINED', 'ADFS')
        }
        #>
    );
    NonNodeData = @{
        Lability = @{
            EnvironmentPrefix = 'LAB-';
            Media = @();
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
                ## Download published version from the PowerShell Gallery
                @{ Name = 'xComputerManagement'; MinimumVersion = '1.3.0.0'; Provider = 'PSGallery'; }
                ## If not specified, the provider defaults to the PSGallery.
                @{ Name = 'xSmbShare'; MinimumVersion = '1.1.0.0'; }
                @{ Name = 'xNetworking'; RequiredVersion = '2.7.0.0'; }
                @{ Name = 'xActiveDirectory'; MinimumVersion = '2.9.0.0'; }
                @{ Name = 'xDnsServer'; MinimumVersion = '1.5.0.0'; }
                @{ Name = 'xDhcpServer'; MinimumVersion = '1.3.0.0'; }
                @{ Name = 'xPSDesiredStateConfiguration'; MinimumVersion = '4.0.0.0'; }
                ## The 'GitHub# provider can download modules directly from a GitHub repository, for example:
                ## @{ Name = 'Lability'; Provider = 'GitHub'; Owner = 'VirtualEngine'; Repository = 'Lability'; Branch = 'dev'; }
            );
            Resource = @(
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
