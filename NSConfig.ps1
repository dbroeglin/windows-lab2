[CmdletBinding()]
Param(
    $Nsip              = "10.0.0.10",
    $Hostname          = "ns01",
    $Username          = "nsroot",
    $Password          = "nsroot",
    $Timezone          = 'GMT+01:00-CET-Europe/Zurich'
)

#region Configuration

$ReverseProxies = @(
    @{
        IPAddress                   = '10.0.0.100'
        ExternalFQDN                = 'www.extlab.local' 
        InternalFQDN                = 'www.lab.local'
        Certificate                 = 'aaa.extlab.local'
        AuthenticationHost          = 'aaa.extlab.local'
        AuthenticationVServerName   = 'aaa-server'
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
        ADFSFQDN         = 'adfs.extlab.local'        
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

Write-Verbose "  -- Setting up features..."
Enable-NSFeature -Session $Session -Force -Name "aaa", "lb", "rewrite", "ssl", "sslvpn", "cs"

Write-Verbose "  -- Uploading certificates..."
"aaa.extlab.local", "adfs.extlab.local", "www.extlab.local" | ForEach {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.pfx" -Filename "$_.pfx" -Password Passw0rd    
}

"adfs_token_signing" | ForEach {
    Import-Certificate -CertificateName $_ -LocalFilename ".\Data\$_.cer" -Filename "$_.cer"    
}    

Write-Verbose "  -- Setting up authentication servers..."
$AuthenticationServers | ForEach-Object { New-AAAConfig @_ }

Write-Verbose "  -- Setting up load balancers..."
$ReverseProxies | ForEach-Object { New-ReverseProxy @_ }

$ContentSwitchingName = "cs-lab"

if (-not (Get-NSCSVirtualServer -Name $ContentSwitchingName -ErrorAction SilentlyContinue)) {
    New-NSCSVirtualServer -Name $ContentSwitchingName -ServiceType SSL -IPAddress 10.0.0.200 -port 443    
}

<#Write-Verbose "  ---- Activating SNI on '$ContentSwitchingName'... "    
Invoke-Nitro -Method PUT -Type sslvserver -Payload @{
        # "sslvserver":{"vservername":"cs-lab","dh":"DISABLED","dhkeyexpsizelimit":"DISABLED","ersa":"ENABLED","ersacount":"0","sessreuse":"ENABLED","sesstimeout":"120",
        #   "cipherredirect":"DISABLED","sslv2redirect":"DISABLED","clientauth":"DISABLED","sslredirect":"DISABLED","snienable":"ENABLED","sendclosenotify":"YES",
        #   "cleartextport":"0","pushenctrigger":"Always","ssl2":"DISABLED","ssl3":"ENABLED","tls1":"ENABLED","tls11":"ENABLED","tls12":"ENABLED"}
        name        = $ContentSwitchingName
        snienable   = "ENABLED"
    } -Action add -Force#>

$VirtualHost = "www.extlab.local"
$ContentSwitchingPolicyName = "cs-pol-$VirtualHost"

if (-not (Invoke-Nitro -Method GET -Type cspolicy -Resource $ContentSwitchingPolicyName -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching policy for '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type cspolicy -Payload @{
            # "cspolicy":{"policyname":"cs-pol-toto","rule":"HTTP.REQ.HOSTNAME.EQ(\"www.extlab.local\")"}
            policyname  = $ContentSwitchingPolicyName
            rule        = "HTTP.REQ.HOSTNAME.EQ(`"$VirtualHost`")"
        } -Action add -Force
}

if (-not (Invoke-Nitro -Method GET -Type csvserver_cspolicy_binding -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching binding '$ContentSwitchingName' <- '$VirtualHost'... "    
    Invoke-Nitro -Method POST -Type csvserver_cspolicy_binding -Payload @{
            # "csvserver_cspolicy_binding":{"policyname":"cs-pol-toto","priority":"100","gotopriorityexpression":"END","targetlbvserver":"vsrv-www.extlab.local","name":"cs-lab",
            #"bindpoint":"REQUEST"}}
            policyname      = $ContentSwitchingPolicyName
            targetlbvserver = "vsrv-$VirtualHost"
            name            = $ContentSwitchingName
            priority        = 100
        } -Action add -Force
}

$TargetVServer = "aaa-server"
$ContentSwitchingActionName = "cs-aaa"

if (-not (Invoke-Nitro -Method GET -Type csaction -Resource $ContentSwitchingActionName -ErrorAction SilentlyContinue)) {
    Write-Verbose "  ---- Creating content switching action for '$TargetVServer'... "    
    Invoke-Nitro -Method POST -Type csaction -Payload @{
            # #"csaction":{"name":"cs-act-aaa","comment":"","targetvserver":"aaa-server"}
            name            = $ContentSwitchingActionName
            targetvserver   = $TargetVServer
        } -Action add -Force
}

$VirtualHost = "aaa.extlab.local"
$ContentSwitchingPolicyName = "cs-pol-aaa"

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