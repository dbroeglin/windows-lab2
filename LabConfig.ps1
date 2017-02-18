Configuration LabConfig {
    Param (
        [Parameter()] 
        [PSCredential] 
        [System.Management.Automation.Credential()]
        $Credential = (Get-Credential -Credential 'Administrator'),
        [Parameter()] [String] $DownloadDir = "C:\Downloads"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 1.8.0.0
    Import-DscResource -ModuleName xSmbShare -ModuleVersion 2.0.0.0
    Import-DscResource -ModuleName xNetworking -ModuleVersion 3.2.0.0
    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 2.9.0.0
    Import-DscResource -ModuleName xDnsServer -ModuleVersion 1.5.0.0
    Import-DscResource -ModuleName xDhcpServer -ModuleVersion 1.3.0.0
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 6.0.0.0

    node $AllNodes.Where({$true}).NodeName {
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true;
            AllowModuleOverwrite = $true;
            ConfigurationMode = 'ApplyOnly';
            CertificateID = $node.Thumbprint;
        }

        if (-not [System.String]::IsNullOrEmpty($node.IPAddress)) {
            xIPAddress 'PrimaryIPAddress' {
                IPAddress      = $node.IPAddress;
                InterfaceAlias = $node.InterfaceAlias;
                PrefixLength   = $node.SubnetMask;
                AddressFamily  = $node.AddressFamily;
            }

            if (-not [System.String]::IsNullOrEmpty($node.DefaultGateway)) {
                xDefaultGatewayAddress 'PrimaryDefaultGateway' {
                    InterfaceAlias = $node.InterfaceAlias;
                    Address = $node.DefaultGateway;
                    AddressFamily = $node.AddressFamily;
                }
            }

            if (-not [System.String]::IsNullOrEmpty($node.DnsServerAddress)) {
                xDnsServerAddress 'PrimaryDNSClient' {
                    Address        = $node.DnsServerAddress;
                    InterfaceAlias = $node.InterfaceAlias;
                    AddressFamily  = $node.AddressFamily;
                }
            }

            if (-not [System.String]::IsNullOrEmpty($node.DnsConnectionSuffix)) {
                xDnsConnectionSuffix 'PrimaryConnectionSuffix' {
                    InterfaceAlias = $node.InterfaceAlias;
                    ConnectionSpecificSuffix = $node.DnsConnectionSuffix;
                }
            }

        } #end if IPAddress

        xFirewall 'FPS-ICMP4-ERQ-In' {
            Name = 'FPS-ICMP4-ERQ-In';
            DisplayName = 'File and Printer Sharing (Echo Request - ICMPv4-In)';
            Description = 'Echo request messages are sent as ping requests to other nodes.';
            Direction = 'Inbound';
            Action = 'Allow';
            Enabled = 'True';
            Profile = 'Any';
        }

        xFirewall 'FPS-ICMP6-ERQ-In' {
            Name = 'FPS-ICMP6-ERQ-In';
            DisplayName = 'File and Printer Sharing (Echo Request - ICMPv6-In)';
            Description = 'Echo request messages are sent as ping requests to other nodes.';
            Direction = 'Inbound';
            Action = 'Allow';
            Enabled = 'True';
            Profile = 'Any';
        }
    } #end nodes ALL

node $AllNodes.Where({$_.Role -contains 'DC1'}).NodeName {
        ## Flip credential into username@domain.com
        $domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($Credential.UserName)@$($node.DomainName)", $Credential.Password);

        xComputer 'Hostname' {
            Name = $node.NodeName;
        }

        ## Hack to fix DependsOn with hypens "bug" :(
        foreach ($feature in @(
                'AD-Domain-Services',
                'GPMC',
                'RSAT-AD-Tools',
                'DHCP',
                'RSAT-DHCP'
            )) {
            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present';
                Name = $feature;
                IncludeAllSubFeature = $true;
            }
        }

        xADDomain 'ADDomain' {
            DomainName = $node.DomainName;
            SafemodeAdministratorPassword = $Credential;
            DomainAdministratorCredential = $Credential;
            DependsOn = '[WindowsFeature]ADDomainServices';
        }

        xDhcpServerAuthorization 'DhcpServerAuthorization' {
            Ensure = 'Present';
            DependsOn = '[WindowsFeature]DHCP','[xADDomain]ADDomain';
        }

        xDhcpServerScope 'DhcpScope10_0_0_0' {
            Name = 'Corpnet';
            IPStartRange = '10.0.0.100';
            IPEndRange = '10.0.0.200';
            SubnetMask = '255.255.255.0';
            LeaseDuration = '00:08:00';
            State = 'Active';
            AddressFamily = 'IPv4';
            DependsOn = '[WindowsFeature]DHCP';
        }

        xDhcpServerOption 'DhcpScope10_0_0_0_Option' {
            ScopeID = '10.0.0.0';
            DnsDomain = 'corp.contoso.com';
            DnsServerIPAddress = '10.0.0.1';
            Router = '10.0.0.254';
            AddressFamily = 'IPv4';
            DependsOn = '[xDhcpServerScope]DhcpScope10_0_0_0';
        }

        xADUser User1 {
            DomainName = $node.DomainName;
            UserName = 'User1';
            Description = 'Lability Test Lab user';
            Password = $Credential;
            Ensure = 'Present';
            DependsOn = '[xADDomain]ADDomain';
        }

        xADUser svc_adfs {
            DomainName = $node.DomainName;
            UserName = 'svc_adfs';
            Description = 'ADFS service user';
            Password = $Credential;
            Ensure = 'Present';
            DependsOn = '[xADDomain]ADDomain';
        }

        xADGroup DomainAdmins {
            GroupName = 'Domain Admins';
            MembersToInclude = 'User1';
            DependsOn = '[xADUser]User1';
        }

        xADGroup EnterpriseAdmins {
            GroupName = 'Enterprise Admins';
            GroupScope = 'Universal';
            MembersToInclude = 'User1';
            DependsOn = '[xADUser]User1';
        }

    } #end nodes DC

    node $AllNodes.Where({$_.Role -contains 'JAHIA'}).NodeName {
        $JavaPackagePath = Join-Path $DownloadDir "jdk-8u112-windows-x64.exe"

        xRemoteFile "jdk-8u112-windows-x64.exe"
        {
            DestinationPath = $JavaPackagePath 
            MatchSource = $False
            Uri = "http://download.oracle.com/otn-pub/java/jdk/8u112-b15/jdk-8u112/jdk-8u112-windows-x64.exe"
            Headers = @{
                "Cookie" = "oraclelicense=accept-securebackup-cookie"
            }
        }

        xPackage "jdk-8u112-windows-x64.exe"
        {
            Ensure = 'Present'
            Name = 'Java SE Development Kit 8 Update 112 (64-bit)'
            Path = $JavaPackagePath
            Arguments = '/q'
            ProductId = ''
            DependsOn = @("[xRemoteFile]jdk-8u112-windows-x64.exe")
        }

        xEnvironment "JAVA_HOME" {
            Name = "JAVA_HOME"
            Ensure = "Present"
            Value = "C:\Program Files\Java\jdk1.8.0_112"
        }     
    } #end nodes JAHIA

    node $AllNodes.Where({$_.Role -contains 'ADFS'}).NodeName {
        WindowsFeature ADFSInstall
        {
            Ensure = "Present"
            Name = "ADFS-Federation"
        } 

        WindowsFeature ADPS
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        }

    } #end nodes ADFS

    node $AllNodes.Where({$_.Role -contains 'JOINED'}).NodeName {
        ## Flip credential into username@domain.com
        $upn = '{0}@{1}' -f $Credential.UserName, $node.DomainName;
        $domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($upn, $Credential.Password);

        xComputer 'DomainMembership' {
            Name = $node.NodeName;
            DomainName = $node.DomainName;
            Credential = $domainCredential;
        }
    } #end nodes DomainJoined

} #end Lab Configuration
