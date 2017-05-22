Configuration AdfsConfig {
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Ensure,

        [String]$CertificateSubject,
        [String[]]$Fqdn,
        [String]$CertificateDirectory,
        [String]$CertificatePassword          
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Script Dummy {
        TestScript = { $False }
        GetScript = { }
        SetScript = {
            Write-Verbose "Importing certificate..."
            Import-PfxCertificate $using:CertificateDirectory\$using:CertificateSubject.pfx `
                    -CertStoreLocation Cert:\LocalMachine\My `
                    -Password (ConvertTo-SecureString $using:CertificatePassword -AsPlainText -Force)

                if (Get-ADFSRelyingPartyTrust -Name Netscaler) {
                    Write-Verbose "Removing old relying party trust..."
                    Remove-ADFSRelyingPartyTrust -TargetName Netscaler
                }

                Write-Verbose "Adding relying party trust..."
                Add-ADFSRelyingPartyTrust -Name Netscaler `
                    -Identifier Netscaler `
                    -SamlEndpoint (
                        $using:Fqdn | ForEach-Object -Begin { $i = 0 } {
                            New-ADFSSamlEndpoint -Binding "POST" -Protocol "SAMLAssertionConsumer" -Uri "https://$_/cgi/samlauth" -Index ($i++)
                        }
                    ) `
                    -RequestSigningCertificate (Get-ChildItem  -Path Cert:\LocalMachine\My  | ? { $_.Subject  -Match "$using:CertificateSubject"})

                $rules = @'
        @RuleName = "Store: ActiveDirectory -> Mail (ldap attribute: mail), Name (ldap attribute: userPrincipalName), GivenName (ldap attribute: givenName), Surname (ldap attribute: sn)"
        c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
        => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), query = ";mail,displayName,userPrincipalName,givenName,sn;{0}", param = c.Value);
'@

                Write-Verbose "Adding relying party trust transformation rules..."
                Set-ADFSRelyingPartyTrust -TargetName Netscaler -IssuanceTransformRules $rules

                $AuthRule = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
                $RuleSet = New-ADFSClaimRuleSet -ClaimRule $AuthRule

                Write-Verbose "Adding relying party trust authorzation rules..."
                Set-ADFSRelyingPartyTrust -TargetName Netscaler -IssuanceAuthorizationRules $RuleSet.ClaimRulesString

                Write-Verbose "Adding relying party trust not before skew..."
                Set-ADFSRelyingPartyTrust -TargetName Netscaler -NotBeforeSkew 2
        }
    }
}
