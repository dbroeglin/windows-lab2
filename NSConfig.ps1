[CmdletBinding()]
Param(
    $Hostname          = "ns01",
    $Nsip              = "10.0.0.10",
    $Snip              = "10.0.0.11",
    $SnipSubnetMask    = "255.255.255.0",
    $Username          = "nsroot",
    $Password          = "nsroot",
    $Timezone          = 'GMT+01:00-CET-Europe/Zurich',

    [Switch]$Clear,
    [Switch]$Bootstrap
)

#region Configuration

$ContentSwitchingName = "cs-external"
$AAAVServer           = "aaa-vsrv-aaa.extlab.local"

$NameServers = @(
    '10.0.0.1'
)

$ReverseProxies = @(
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'sts.extlab.local'
        InternalFQDN                = 'sts.extlab.local'
        InternalIPAddress           = '10.0.0.32'
        InternalProtocol            = 'SSL'
        Certificate                 = 'sts.extlab.local'
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 100
    },
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'www.extlab.local' 
        InternalFQDN                = 'www.lab.local'
        Certificate                 = 'www.extlab.local'
        AuthenticationHost          = 'aaa.extlab.local'
        AuthenticationVServerName   = $AAAVServer
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 101
    }
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'wwa.extlab.local' 
        InternalFQDN                = 'wwa.lab.local'
        Certificate                 = 'wwa.extlab.local'
        AuthenticationHost          = 'aaa.extlab.local'
        AuthenticationVServerName   = $AAAVServer
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 102
    } 
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'wwb.extlab.local' 
        InternalFQDN                = 'wwb.lab.local'
        Certificate                 = 'wwb.extlab.local'
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 103
    }        
)

$AuthenticationServers = @(
    @{
        FQDN             = "aaa.extlab.local"
        SAMLCertificate  = 'adfs_token_signing'
        DomainName       = 'extlab.local'
        ADFSFQDN         = 'sts.extlab.local'        
    }    
)

#endregion

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 4

. "$PSScriptRoot\NSConfigHelpers.ps1"

$Session = Connect-NetscalerInstance -NSIP $Nsip -Username $Username -Password $Password

if ($Bootstrap) {
    Write-Verbose "Bootstraping NetScaler..."
    Add-NSIPResource -IPAddress $Snip -SubnetMask $SnipSubnetMask -Type SNIP  -Session $Session
    Install-NSLicense -Path .\license.lic -Session $Session
    Restart-NetScaler -WarmReboot -Wait -SaveConfig -Force -Session $Session
    
    # Reconnect after reboot
    Start-Sleep 10
    Write-Verbose "Reconnecting after restart..."
    $Session = Connect-NetscalerInstance -NSIP $Nsip -Username $Username -Password $Password
}
if ($Clear) {
    Clear-NSConfig -Session $Session -Force
}


Write-Verbose "Applying Netscaler configuration..."
Set-NSTimeZone -TimeZone $Timezone -Session $Session -Force
Set-NSHostname -Hostname $Hostname -Session $Session -Force

Disable-NSMode -Name l3 -Force -Session $Session

Write-Verbose "  -- Setting up features..."
Enable-NSFeature -Force -Name "aaa", "lb", "rewrite", "ssl", "sslvpn", "cs" -Session $Session

Write-Verbose "  -- Setting up DNS..."

New-NSLBVirtualServer -Name vsrv-dns -ServiceType DNS -NonAddressable -Session $Session
$NameServers | ForEach-Object -Begin { $i = 0 } -Process {
    $i++
    $ServerName  = "srv-dns$i"
    $ServiceName = "svc-dns$i"

    New-NSLBServer -Name $ServerName -IPAddress $_ -Session $Session
    Invoke-Nitro -Method POST -Type service -Payload @{
            # "service":{"name":"svc-dns","servername":"srv-dns1","servicetype":"DNS","port":"53","td":"","customserverid":"None","state":"ENABLED","healthmonitor":"YES","appflowlog":"ENABLED","comment":""}
            name        = $ServiceName
            servername  = $ServerName
            servicetype = 'DNS'
            port        = '53'
        } -Action add -Force -Session $Session
    Add-NSLBVirtualServerBinding -ServiceName $ServiceName -VirtualServerName vsrv-dns -Session $Session
}

Invoke-Nitro -Method POST -Type dnsnameserver -Payload @{
    # "dnsnameserver":{"type":"UDP","state":"ENABLED","dnsvservername":"vsrv-dns"}
    dnsvservername = 'vsrv-dns'
    state =          'ENABLED'
    type =           'UDP'
} -Force -Session $Session



Write-Verbose "  -- Uploading certificates..."
"aaa.extlab.local", "sts.extlab.local", "www.extlab.local", "wwa.extlab.local", "wwb.extlab.local" | ForEach-Object {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.pfx" -Filename "$_.pfx" -Password Passw0rd -Session $Session
}

"adfs_token_signing" | ForEach-Object {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.cer" -Filename "$_.cer" -Session $Session
}    

if (-not (Get-NSCSVirtualServer -Name $ContentSwitchingName -ErrorAction SilentlyContinue -Session $Session)) {
    Write-Verbose "  -- Creating CS VServer '$ContentSwitchingName"
    New-NSCSVirtualServer -Name $ContentSwitchingName -ServiceType SSL -IPAddress 10.0.0.200 -port 443 -Session $Session   
}

Write-Verbose "  ---- Activating SNI on '$ContentSwitchingName'... "    
Invoke-Nitro -Method PUT -Type sslvserver -Payload @{
        # "sslvserver":{"vservername":"cs-lab","dh":"DISABLED","dhkeyexpsizelimit":"DISABLED","ersa":"ENABLED","ersacount":"0","sessreuse":"ENABLED","sesstimeout":"120",
        #   "cipherredirect":"DISABLED","sslv2redirect":"DISABLED","clientauth":"DISABLED","sslredirect":"DISABLED","snienable":"ENABLED","sendclosenotify":"YES",
        #   "cleartextport":"0","pushenctrigger":"Always","ssl2":"DISABLED","ssl3":"ENABLED","tls1":"ENABLED","tls11":"ENABLED",
        #"tls12":"ENABLED"}
        vservername = $ContentSwitchingName
        snienable   = "ENABLED"
        ssl3        = "DISABLED"
    } -Force -Session $Session

<#
Write-Verbose "  ---- Setting up authentication for $ContentSwitchingName..."
Invoke-Nitro -Type csvserver -Method PUT -Payload @{ 
        name               = $ContentSwitchingName
        authenticationhost = 'aaa.extranet.local'
        authnvsname        = 'aaa-server'
        authentication     = "ON"
        authn401           = "OFF"
    } -Force
#>

Write-Verbose "  -- Setting up authentication servers..."
$AuthenticationServers | ForEach-Object { New-AAAConfig @_ }

Write-Verbose "  -- Setting up load balancers..."
$ReverseProxies | ForEach-Object { New-ReverseProxy @_ }

$TargetVServer              = $AAAVServer
$VirtualHost                = "aaa.extlab.local"
$ContentSwitchingPolicyName = "cs-pol-$VirtualHost"
$ContentSwitchingActionName = "cs-act-$VirtualHost"

if (-not (Invoke-Nitro -Method GET -Type csaction -Resource $ContentSwitchingActionName -ErrorAction SilentlyContinue -Session $Session)) {
    Write-Verbose "  ---- Creating content switching action for '$TargetVServer'... "    
    Invoke-Nitro -Method POST -Type csaction -Payload @{
            # #"csaction":{"name":"cs-act-aaa","comment":"","targetvserver":"aaa-server"}
            name            = $ContentSwitchingActionName
            targetvserver   = $TargetVServer
        } -Action add -Force -Session $Session
}

if (-not (Invoke-Nitro -Method GET -Type cspolicy -Resource $ContentSwitchingPolicyName -ErrorAction SilentlyContinue -Session $Session)) {
    Write-Verbose "  ---- Creating content switching policy for '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type cspolicy -Payload @{
            # "cspolicy":{"policyname":"cs-pol-toto","rule":"HTTP.REQ.HOSTNAME.EQ(\"www.extlab.local\")"}
            policyname  = $ContentSwitchingPolicyName
            rule        = "HTTP.REQ.HOSTNAME.EQ(`"$VirtualHost`")"
            action      = $ContentSwitchingActionName
        } -Action add -Force -Session $Session
}

if (-not (Invoke-Nitro -Method GET -Type csvserver_cspolicy_binding -ErrorAction SilentlyContinue -Session $Session)) {
    Write-Verbose "  ---- Creating content switching binding '$ContentSwitchingName' <- '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type csvserver_cspolicy_binding -Payload @{
            # "csvserver_cspolicy_binding":{"policyname":"cs-pol-aaa","priority":"110","gotopriorityexpression":"END","name":"cs-lab","bindpoint":"REQUEST"}}
            policyname      = $ContentSwitchingPolicyName
            name            = $ContentSwitchingName
            priority        = 99
        } -Action add -Force -Session $Session
}


Write-Verbose "  -- Setting up KCD for 'www.extlab.local'..."
Write-Verbose "  ---- Setting up KCD account..."
New-NSKCDAccount -Name ns_svc -Realm "lab.local" -Credential ([PSCredential]::new("ns_svc", (ConvertTo-SecureString "Passw0rd" -Force -AsPlainText)))

Write-Verbose "  ---- Setting up KCD traffic profile..."
Invoke-Nitro -Type tmtrafficaction -Method POST -Payload @{
        name             = "prf-sso-kcd"
        initiatelogout   = "OFF"
        persistentcookie = "OFF"
        apptimeout       = "5"
        sso              = "ON"
        kcdaccount       = "ns_svc"
    } -Action Add -Force

Write-Verbose "  ---- Setting up KCD traffic policy..."
Invoke-Nitro -Type tmtrafficpolicy -Method POST -Payload @{
        name   = "pol-sso-kcd"
        action = "prf-sso-kcd"
        rule   = "true"
    } -Action Add -Force
Add-NSLBVirtualServerTrafficPolicyBinding -VirtualServerName "vsrv-www.extlab.local" -PolicyName "pol-sso-kcd" -Priority 100


Write-Verbose "Saving configuration..."
Save-NSConfig -Session $Session
Write-Verbose "Netscaler configuration has been applied."