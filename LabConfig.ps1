Configuration LabConfig {
<#
    Requires the following custom DSC resources:
        xComputerManagement (v1.4.0.0 or later):        https://github.com/PowerShell/xComputerManagement
        xNetworking/dev (v2.7.0.0 or later):            https://github.com/PowerShell/xNetworking
        xActiveDirectory (v2.9.0.0 or later):           https://github.com/PowerShell/xActiveDirectory
        xSmbShare (v1.1.0.0 or later):                  https://github.com/PowerShell/xSmbShare
        xDhcpServer (v1.3.0 or later):                  https://github.com/PowerShell/xDhcpServer
        xDnsServer (v1.5.0 or later):                   https://github.com/PowerShell/xDnsServer
        xPSDesiredStateConfiguration (v4.0.0.0 or later https://github.com/PowerShell/xPSDesiredStateConfiguration 

 @("xComputerManagement", "xNetworking", "xActiveDirectory", "xSmbShare", 
   "xPSDesiredStateConfiguration", "xDHCPServer", "xDnsServer", "xPSDesiredStateConfiguration" ) | 
   % { Find-Module $_; Install-Module $_ }
        
#>
    param (
        [Parameter()] [ValidateNotNull()] [PSCredential] $Credential = (Get-Credential -Credential 'Administrator')
    )
    Import-DscResource -Module xComputerManagement, xNetworking, xActiveDirectory
    Import-DscResource -Module xSmbShare, PSDesiredStateConfiguration
    Import-DscResource -Module xDHCPServer, xDnsServer, xPSDesiredStateConfiguration

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
                SubnetMask     = $node.SubnetMask;
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

node $AllNodes.Where({$_.Role -in 'DC'}).NodeName {
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
            Router = '10.0.0.2';
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

    node $AllNodes.Where({$_.Role -in 'JAHIA'}).NodeName {
        $JavaPackagePath = ""

        xRemoteFile DownloadJava
        {
            DestinationPath = $JavaPackagePath 
            Uri = $uri
            UserAgent = $userAgent
            Headers = $headers
        }        
    } #end nodes JAHIA

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
