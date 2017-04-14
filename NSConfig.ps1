[CmdletBinding()]
Param(
    $Nsip              = "10.0.0.10",
    $Hostname          = "ns01",
    $Username          = "nsroot",
    $Password          = "nsroot",
    $Timezone          = 'GMT+01:00-CET-Europe/Zurich'
)

#region Configuration

$ContentSwitchingName = "cs-external"

$NameServers = @(
    '10.0.0.1'
)

$ReverseProxies = @(
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'sts.extlab.local' 
        InternalFQDN                = 'sts.extlab.local'
        Certificate                 = 'sts.extlab.local'
        AuthenticationHost          = 'aaa.extlab.local'
        AuthenticationVServerName   = 'aaa-server'
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 100
    },
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'www.extlab.local' 
#        InternalFQDN                = 'www.lab.local'
        InternalFQDN                = 'www.google.com'
        Certificate                 = 'www.extlab.local'
        AuthenticationHost          = 'aaa.extlab.local'
        AuthenticationVServerName   = 'aaa-server'
        ContentSwitchingName        = $ContentSwitchingName
        Priority                    = 101
    }    
)

$AuthenticationServers = @(
    @{
        Name             = "aaa-server"
        CertificateName  = "aaa.extlab.local"
        IPAddress        = "10.0.0.110"
        Port             = "443"
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

Write-Verbose "Applying Netscaler configuration..."
Set-NSTimeZone -TimeZone $Timezone -Session $Session -Force
Set-NSHostname -Hostname $Hostname -Session $Session -Force

Disable-NSMode -Name l3 -Force

Write-Verbose "  -- Setting up features..."
Enable-NSFeature -Session $Session -Force -Name "aaa", "lb", "rewrite", "ssl", "sslvpn", "cs"

Write-Verbose "  -- Setting up DNS..."

New-NSLBVirtualServer -Name vsrv-dns -ServiceType DNS -NonAddressable
$NameServers | ForEach-Object -Begin { $i = 0 } -Process {
    $i++
    $ServerName  = "srv-dns$i"
    $ServiceName = "svc-dns$i"

    New-NSLBServer -Name $ServerName -IPAddress $_
    Invoke-Nitro -Method POST -Type service -Payload @{
            # "service":{"name":"svc-dns","servername":"srv-dns1","servicetype":"DNS","port":"53","td":"","customserverid":"None","state":"ENABLED","healthmonitor":"YES","appflowlog":"ENABLED","comment":""}
            name        = $ServiceName
            servername  = $ServerName
            servicetype = 'DNS'
            port        = '53'
        } -Action add -Force
    Add-NSLBVirtualServerBinding -ServiceName $ServiceName -VirtualServerName vsrv-dns
}

Invoke-Nitro -Method POST -Type dnsnameserver -Payload @{
    # "dnsnameserver":{"type":"UDP","state":"ENABLED","dnsvservername":"vsrv-dns"}
    dnsvservername = 'vsrv-dns'
    state =          'ENABLED'
    type =           'UDP'
} -Force



Write-Verbose "  -- Uploading certificates..."
"aaa.extlab.local", "sts.extlab.local", "www.extlab.local" | ForEach {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.pfx" -Filename "$_.pfx" -Password Passw0rd    
}

"adfs_token_signing" | ForEach {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.cer" -Filename "$_.cer"    
}    

if (-not (Get-NSCSVirtualServer -Name $ContentSwitchingName -ErrorAction SilentlyContinue)) {
    Write-Verbose "  -- Creating CS VServer '$ContentSwitchingName"
    New-NSCSVirtualServer -Name $ContentSwitchingName -ServiceType SSL -IPAddress 10.0.0.200 -port 443    
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
    } -Force

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

$TargetVServer              = "aaa-server"
$VirtualHost                = "aaa.extlab.local"
$ContentSwitchingPolicyName = "cs-pol-$VirtualHost"
$ContentSwitchingActionName = "cs-act-$VirtualHost"

if (-not (Invoke-Nitro -Method GET -Type csaction -Resource $ContentSwitchingActionName -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching action for '$TargetVServer'... "    
    Invoke-Nitro -Method POST -Type csaction -Payload @{
            # #"csaction":{"name":"cs-act-aaa","comment":"","targetvserver":"aaa-server"}
            name            = $ContentSwitchingActionName
            targetvserver   = $TargetVServer
        } -Action add -Force
}


if (-not (Invoke-Nitro -Method GET -Type cspolicy -Resource $ContentSwitchingPolicyName -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching policy for '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type cspolicy -Payload @{
            # "cspolicy":{"policyname":"cs-pol-toto","rule":"HTTP.REQ.HOSTNAME.EQ(\"www.extlab.local\")"}
            policyname  = $ContentSwitchingPolicyName
            rule        = "HTTP.REQ.HOSTNAME.EQ(`"$VirtualHost`")"
            action      = $ContentSwitchingActionName
        } -Action add -Force
}

if (-not (Invoke-Nitro -Method GET -Type csvserver_cspolicy_binding -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching binding '$ContentSwitchingName' <- '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type csvserver_cspolicy_binding -Payload @{
            # "csvserver_cspolicy_binding":{"policyname":"cs-pol-aaa","priority":"110","gotopriorityexpression":"END","name":"cs-lab","bindpoint":"REQUEST"}}
            policyname      = $ContentSwitchingPolicyName
            name            = $ContentSwitchingName
            priority        = 99
        } -Action add -Force
}

Write-Verbose "Saving configuration..."
Save-NSConfig
Write-Verbose "Netscaler configuration has been applied."