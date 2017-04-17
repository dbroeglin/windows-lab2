Configuration LabConfig {
    Param (
        [Parameter()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [PSCredential]::new("Administrator", (ConvertTo-SecureString -AsPlainText -Force "Passw0rd")),

        [Parameter()] [String] $DownloadDir = "C:\Downloads",

        [PSCredential]
        [System.Management.Automation.Credential()]
        $AdfsSvcCredential = [PSCredential]::new("svc_adfs", (ConvertTo-SecureString -AsPlainText -Force "Passw1rd")),

        [String]
        $AdfsDisplayName = 'Lab ADFS',

        [String]
        $AdfsFQDN = 'sts.extlab.local',

        [String]
        $AdfsCertThumbprint = '1BC84A035D2264F1DB41A40B24691119B9616F79'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Import-DscResource -ModuleName xComputerManagement          -ModuleVersion 1.8.0.0
    Import-DscResource -ModuleName xSmbShare                    -ModuleVersion 2.0.0.0
    Import-DscResource -ModuleName xNetworking                  -ModuleVersion 3.2.0.0
    Import-DscResource -ModuleName xActiveDirectory             -ModuleVersion 2.9.0.0
    Import-DscResource -ModuleName xDnsServer                   -ModuleVersion 1.7.0.0
    Import-DscResource -ModuleName xDhcpServer                  -ModuleVersion 1.3.0.0
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 6.0.0.0
    Import-DscResource -ModuleName xWebAdministration           -ModuleVersion 1.17.0.0
    Import-DscResource -ModuleName xCertificate                 -ModuleVersion 2.4.0.0

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

node $AllNodes.Where({$_.Role -contains 'DC'}).NodeName {
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
            DomainName           = $node.DomainName
            UserName             = $AdfsSvcCredential.UserName
            UserPrincipalName    = ("{0}@lab.local" -f $AdfsSvcCredential.UserName)
            Description          = 'ADFS service user'
            Password             = $AdfsSvcCredential
            Ensure               = 'Present'
            DependsOn            = '[xADDomain]ADDomain'
        }

        xADUser alice {
            DomainName        = $node.DomainName
            UserName          = 'alice'
            UserPrincipalName = 'alice@lab.local'
            Description       = 'Alice'
            Password          = $Credential
            Ensure            = 'Present'
            DependsOn         = '[xADDomain]ADDomain'
        }

        xADUser bob {
            DomainName        = $node.DomainName
            UserName          = 'bob'
            UserPrincipalName = 'bob@lab.local'
            Description       = 'Bob'
            Password          = $Credential
            Ensure            = 'Present'
            DependsOn         = '[xADDomain]ADDomain'
        }

        xADUser ns_svc {
            DomainName           = $node.DomainName
            UserName             = 'ns_svc'
            UserPrincipalName    = 'ns_svc@lab.local'
            Description          = 'Netscaler Service Account (KCD)'
            Password             = $Credential
            PasswordNeverExpires = $True
            Ensure               = 'Present'
            DependsOn            = '[xADDomain]ADDomain'
        }

        xADUser iis_svc {
            DomainName           = $node.DomainName
            UserName             = 'iis_svc'
            UserPrincipalName    = 'iis_svc@lab.local'
            Description          = 'IIS Service Account (KCD)'
            Password             = $Credential
            PasswordNeverExpires = $True
            Ensure               = 'Present'
            DependsOn            = '[xADDomain]ADDomain'
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

        xDNSRecord www.lab.local {
            Name     = 'www'
            Type     =  'ARecord'
            Zone     = 'lab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq WEB01).IPAddress
            DependsOn = '[xADDomain]ADDomain'
        }

        xDNSRecord wwa.lab.local {
            Name     = 'wwa'
            Type     =  'ARecord'
            Zone     = 'lab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq WEB01).IPAddress
            DependsOn = '[xADDomain]ADDomain'
        }

        xDNSRecord wwb.lab.local {
            Name     = 'wwb'
            Type     =  'ARecord'
            Zone     = 'lab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq WEB01).IPAddress
            DependsOn = '[xADDomain]ADDomain'
        }

        xDnsServerADZone extlab.local {
            Name             = 'extlab.local'
            ReplicationScope = 'Forest'
            Ensure           = 'Present'
            DependsOn = '[xADDomain]ADDomain'
        }

        xDNSRecord aaa.extlab.local {
            Name     = 'aaa'
            Type     =  'ARecord'
            Zone     = 'extlab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq NS01).VIP
            DependsOn = @("[xDnsServerADZone]extlab.local")
        }

        xDNSRecord www.extlab.local {
            Name     = 'www'
            Type     =  'ARecord'
            Zone     = 'extlab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq NS01).VIP
            DependsOn = @("[xDnsServerADZone]extlab.local")
        }

        xDNSRecord wwa.extlab.local {
            Name     = 'wwa'
            Type     =  'ARecord'
            Zone     = 'extlab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq NS01).VIP
            DependsOn = @("[xDnsServerADZone]extlab.local")
        }

        xDNSRecord wwb.extlab.local {
            Name     = 'wwb'
            Type     =  'ARecord'
            Zone     = 'extlab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq NS01).VIP
            DependsOn = @("[xDnsServerADZone]extlab.local")
        }

        xDNSRecord sts.extlab.local {
            Name     = 'sts'
            Type     =  'ARecord'
            Zone     = 'extlab.local'
            Target   = ($ConfigurationData.AllNodes | Where-Object NodeName -eq NS01).VIP
            DependsOn = @("[xDnsServerADZone]extlab.local")
        }
    } #end nodes DC

    node $AllNodes.Where({$_.Role -contains 'JOINED'}).NodeName {
        ## Flip credential into username@domain.com
        $upn = '{0}@{1}' -f $Credential.UserName, $node.DomainName;
        # TODO: parameterize this one
        $domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($upn, $Credential.Password);

<#
        xWaitForADDomain DscForestWait
        {
            DomainName           = $Node.DomainName
            DomainUserCredential = $domainCredential
            RetryCount           = 30
            RetryIntervalSec     = 30
        }
#>
        xComputer 'DomainMembership' {
            Name       = $node.NodeName
            DomainName = $node.DomainName
            Credential = $domainCredential
#            DependsOn  = "[xWaitForADDomain]DscForestWait"
        }
    } #end nodes JOINED

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

    node $AllNodes.Where({$_.Role -contains 'WEB'}).NodeName {
        ## Hack to fix DependsOn with hypens "bug" :(
        foreach ($feature in @(
                'Web-Server',
                'Web-Windows-Auth',
                'Web-Mgmt-Console'# Install IIS management console for troubleshooting
            )) {
            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present';
                Name = $feature;
                IncludeAllSubFeature = $true;
            }
        }

        File WebContent
        {
            Ensure          = 'Present'
            DestinationPath = 'C:\inetpub\wwwroot\index.html'
            Contents        = 'Hello World!'
            Type            = 'File'
        }

        File wwaroot
        {
            Ensure          = 'Present'
            DestinationPath = 'C:\inetpub\wwaroot'
            Type            = 'Directory'
        }

        File wwa_index
        {
            Ensure          = 'Present'
            DestinationPath = 'C:\inetpub\wwaroot\index.html'
            Contents        = 'WWA: Hello World!'
            Type            = 'File'
            DependsOn       = @("[File]wwaroot")
        }

        xWebsite wwa.lab.local {
            Ensure          = 'Present'
            Name            = 'wwa.lab.local'
            BindingInfo = MSFT_xWebBindingInformation {
                Protocol = "http"
                Port     = 80
                Hostname = "wwa.lab.local"
            }
            AuthenticationInfo = MSFT_xWebAuthenticationInformation {
                Anonymous = $False
                Basic     = $False
                Digest    = $False
                Windows   = $True
            }
            State           = 'Started'
            PhysicalPath    = 'c:\inetpub\wwaroot'
            DependsOn       = '[File]wwa_index', '[WindowsFeature]WebServer'
        }

    } #end nodes WEB

    node $AllNodes.Where({$_.Role -contains 'ADFS'}).NodeName {
        WindowsFeature ADFS
        {
            Ensure = "Present"
            Name = "ADFS-Federation"
        }

        WindowsFeature RSAT-AD-PowerShell
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        }

        xPfxImport sts.extlab.local
        {
            Thumbprint = $Node.AdfsCertThumbprint
            Path       = "C:\Downloads\$($Node.AdfsFQDN).pfx"
            Credential = [PSCredential]::new("Dummy", (ConvertTo-SecureString -AsPlainText -Force "Passw0rd"))
            Location   = 'LocalMachine'
            Store      = 'My'
        }

        Script ADFSFarm
        {
            GetScript = {

            }
            SetScript = {
                ### If ADFS Farm shoud be present, then go ahead and install it.
                if (!$this.Ensure -or $this.Ensure -eq 'Present') {
                    try{
                        $AdfsProperties = Get-AdfsProperties -ErrorAction stop;
                    }
                    catch {
                        $AdfsProperties = $false
                    }

                    if ($AdfsProperties) {
                        Write-Verbose -Message 'Configuring Active Directory Federation Services (ADFS) properties.';
                        $AdfsProperties = @{
                            DisplayName = $AdfsDisplayName;
                        };
                        Set-AdfsProperties @AdfsProperties;
                    } else {
                        Write-Verbose -Message 'Installing Active Directory Federation Services (ADFS) farm.';
                        Import-PfxCertificate  -CertStoreLocation Cert:\LocalMachine\My -FilePath c:\Downloads\sts.extlab.local.pfx -Password (
                            ConvertTo-SecureString -AsPlainText -Force "Passw0rd")
                        $AdfsFarm = @{
                            ServiceAccountCredential      = [PSCredential]::new("LAB\svc_adfs", (ConvertTo-SecureString -AsPlainText -Force "Passw1rd"))
                            Credential                    = [PSCredential]::new("LAB\Administrator", (ConvertTo-SecureString -AsPlainText -Force "Passw0rd"))
                            CertificateThumbprint         = $using:Node.AdfsCertThumbprint
                            FederationServiceDisplayName  = $using:Node.AdfsDisplayName
                            FederationServiceName         = $using:Node.AdfsFQDN
                        }
                        Install-ADFSFarm @AdfsFarm -OverwriteConfiguration
                    }
                }

                if ($this.Ensure -eq 'Absent') {
                    ### From the help for Remove-AdfsFarmNode: The Remove-AdfsFarmNode cmdlet is deprecated. Instead, use the Uninstall-WindowsFeature cmdlet.
                    Uninstall-WindowsFeature -Name ADFS-Federation;
                }

                return;
            }
            TestScript = {
                $Compliant = $true;

                Write-Verbose -Message 'Testing for presence of Active Directory Federation Services (ADFS) farm.';

                try {
                    $Properties = Get-AdfsProperties -ErrorAction Stop;
                }
                catch {
                    $Compliant = $false;
                    return $Compliant;
                }

                if ($this.Ensure -eq 'Present') {
                    Write-Verbose -Message 'Checking for presence of ADFS Farm.';
                    if ($this.ServiceName -ne $Properties.HostName) {
                        Write-Verbose -Message 'ADFS Service Name doesn''t match the desired state.';
                        $Compliant = $false;
                    }
                }

                if ($this.Ensure -eq 'Absent') {
                    Write-Verbose -Message 'Checking for absence of ADFS Farm.';
                    if ($Properties) {
                        Write-Verbose -Message
                        $Compliant = $false;
                    }
                }

                return $Compliant;
            }
            DependsOn = '[WindowsFeature]ADFS', '[xComputer]DomainMembership', '[xPfxImport]sts.extlab.local'
        }
    } #end nodes ADFS

} #end Lab Configuration
