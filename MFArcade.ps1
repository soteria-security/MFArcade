Function Invoke-MFArcade {
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Output path for report')]
        [string] $OutPath,
        [Parameter(Mandatory = $false,
            HelpMessage = 'Get Detailed report')]
        [switch] $DetailedReport,
        [Parameter(Mandatory = $false,
            HelpMessage = "Report Output Format")]
        [ValidateSet("All", "HTML", "CSV", "XML", "JSON",
            IgnoreCase = $true)]
        [string] $reportType = "All"
    )

    # Identify Conditional Access Policy gaps per user. Identify users with no MFA.
    $establishedConnection = $null

    Function Connect-Session {
        Write-Host "Connecting to Microsoft Graph"
        Connect-MgGraph -ContextScope Process -Scopes "Reports.Read.All", "Policy.Read.All", "Directory.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All"
    }

    Try {
        $connection = Get-MgContext

        $reqdScopes = @("Reports.Read.All", "Policy.Read.All", "Directory.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All")

        If ($connection) {
            $activeScopes = $connection.Scopes

            $missingScopes = @()
            
            $scopeCount = 0
            
            foreach ($scope in $reqdScopes) {
                If ($scope -in $activeScopes) {
                    $scopeCount ++
                }
                Else {
                    $missingScopes += $scope
                }
            }

            If ($scopeCount -lt 5) {
                Write-Warning "Necessary scopes are not available in this session: $($missingScopes -join ',')"

                Do {
                    $prompt = Read-Host -Prompt "Would you like to reconnect with the appropriate scopes? (Y|N)"
                } while ($prompt -notmatch '^[yn]$')

                If ($prompt -eq 'N') {
                    Break
                }
                ElseIf ($prompt -eq 'Y') {
                    Connect-Session
                }
            }
            Else {
                $establishedConnection = $true
            } 
        }
    }
    Catch {
        If (! $establishedConnection) {
            Connect-Session
        }
    }

    Function QuickAssessment {
        $tenantLicense = ((Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/subscribedSkus").Value).ServicePlans

        If ($tenantLicense.ServicePlanName -match "AAD_PREMIUM*") {
            $results = @()

            $secureDefault = ((Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy").Value)

            $conditionalAccess = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/policies/conditionalAccessPolicies").Value  | Where-Object { $_.grantcontrols.builtincontrols -eq 'mfa' }

            If ($secureDefault.IsEnabled -eq $true) {
                $secDef = "Secure Defaults Enabled. Conditonal Access Not Supported."
                    
                $results += $secDef
            }`
                ElseIf (($secureDefault.IsEnabled -eq $false) -and (($conditionalAccess | Measure-Object).count -eq 0)) {
                $secDef = "No Conditional Access Policies Exist"

                $results += $secDef
            }`
                Else {
                $mfaReport = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails").Value

                ForEach ($lookup in $mfaReport) {
                    $userTemplate = [PSCustomObject]@{
                        Name                 = $null
                        Id                   = $null
                        UserPrincipalName    = $null
                        IsEnabled            = $null
                        IsExternal           = $null
                        IsMFACapable         = $null
                        IsMFARegistered      = $null
                        RegisteredMFAMethods = @()
                        MemberOf             = @()
                        AppliedCAPolicies    = @()
                        CAPoliciesNotApplied = @()
                        PossibleCAGaps       = @()
                    }

                    If ($lookup.userPrincipalName -match '#EXT#') {
                        $userTemplate.UserPrincipalName = $lookup.userPrincipalName
                        $upn = ($lookup.userPrincipalName).Replace('#EXT#', '%23EXT%23')
                        $userTemplate.IsExternal = $true
                    }
                    Else {
                        $upn = $lookup.userPrincipalName
                        $userTemplate.UserPrincipalName = $lookup.userPrincipalName
                        $userTemplate.IsExternal = $false
                    }

                    $target = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)?select=id,displayName")

                    $grpMemberships = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)/transitiveMemberOf?select=id,roleTemplateId,displayName").value

                    $groupDetails = $grpMemberships | Foreach-Object { "$($_.displayName) ($((($_.'@odata.type') -split '#microsoft.graph.')[1]))" }

                    $userTemplate.Name = $target.displayName
                    $userTemplate.Id = $target.id
                    $userTemplate.IsEnabled = $lookup.isEnabled
                    $userTemplate.IsMFACapable = $lookup.isCapable
                    $userTemplate.IsMFARegistered = $lookup.isMfaRegistered
                    $userTemplate.RegisteredMFAMethods = $lookup.authMethods -join ','
                    $userTemplate.MemberOf = $groupDetails -join ','

                    $appliedPolicies = @()
                    $disabledPolicies = @()
                    $caGaps = @()

                    Foreach ($policy in $conditionalAccess) {
                        If ($policy.State -ne 'enabled') {
                            $disabledPolicies += "$($policy.displayName) not applied. The policy is in $($policy.state) mode.`n"
                        }

                        # User Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -contains $target.id) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Group Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includegroups -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.includegroups }) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Role Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeroles -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.includeroles }) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Gaps in CA Policies
                        # By Role
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeroles -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.includeroles }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        # By User
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($target.id | Where-Object { $_ -in $policy.conditions.users.includeusers }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        # By Group
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includegroups -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.includegroups }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                    }

                    $userTemplate.AppliedCAPolicies = ($appliedPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.CAPoliciesNotApplied = ($disabledPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.PossibleCAGaps = ($caGaps | Sort-Object -Unique) -join ','

                    $results += $userTemplate
                }
            }

            Return $results
        }
    }

    Function DetailedAssessment {
        $tenantLicense = ((Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/subscribedSkus").Value).ServicePlans

        If ($tenantLicense.ServicePlanName -match "AAD_PREMIUM*") {
            $results = @()

            $secureDefault = ((Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy").Value)

            $conditionalAccess = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/policies/conditionalAccessPolicies").Value  | Where-Object { $_.grantcontrols.builtincontrols -eq 'mfa' }

            If ($secureDefault.IsEnabled -eq $true) {
                $secDef = "Secure Defaults Enabled. Conditonal Access Not Supported."
                    
                $results += $secDef
            }`
                ElseIf (($secureDefault.IsEnabled -eq $false) -and (($conditionalAccess | Measure-Object).count -eq 0)) {
                $secDef = "No Conditional Access Policies Exist"

                $results += $secDef
            }`
                Else {
                $mfaReport = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails").Value

                ForEach ($lookup in $mfaReport) {
                    $userTemplate = [PSCustomObject]@{
                        Name                          = $null
                        Id                            = $null
                        UserPrincipalName             = $null
                        IsEnabled                     = $null
                        IsExternal                    = $null
                        IsAdmin                       = $null
                        IsSSPRCapable                 = $null
                        IsSSPREnabled                 = $null
                        IsSSPRRegistered              = $null
                        IsMFACapable                  = $null
                        IsMFARegistered               = $null
                        RegisteredMFAMethods          = @()
                        DefaultMFAMethod              = $null
                        SystemPreferredMethodEnforced = $null
                        SystemEnforcedMethod          = $null
                        UserPreferredMFAMethod        = $null
                        IsPasswordlessCapable         = $null
                        MemberOf                      = @()
                        AppliedCAPolicies             = @()
                        CAPoliciesNotApplied          = @()
                        PossibleCAGaps                = @()
                    }

                    If ($lookup.userPrincipalName -match '#EXT#') {
                        $userTemplate.UserPrincipalName = $lookup.userPrincipalName
                        $upn = ($lookup.userPrincipalName).Replace('#EXT#', '%23EXT%23')
                        $userTemplate.IsExternal = $true
                    }
                    Else {
                        $upn = $lookup.userPrincipalName
                        $userTemplate.UserPrincipalName = $lookup.userPrincipalName
                        $userTemplate.IsExternal = $false
                    }

                    $target = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)?select=id,displayName")

                    $targetAuthMethods = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)/authentication/methods").value

                    $authMethods = @()

                    $grpMemberships = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)/transitiveMemberOf?select=id,roleTemplateId,displayName").value

                    $groupDetails = $grpMemberships | Foreach-Object { "$($_.displayName) ($((($_.'@odata.type') -split '#microsoft.graph.')[1]))" }

                    $userTemplate.Name = $target.displayName
                    $userTemplate.Id = $target.id
                    $userTemplate.IsEnabled = $lookup.isEnabled
                    $userTemplate.IsMFACapable = $lookup.isCapable
                    $userTemplate.IsMFARegistered = $lookup.isMfaRegistered
                    $userTemplate.IsSSPRCapable = $lookup.isSsprCapable
                    $userTemplate.IsSSPREnabled = $lookup.isSsprEnabled
                    $userTemplate.IsSSPRRegistered = $lookup.isSsprRegistered
                    $userTemplate.SystemPreferredMethodEnforced = $lookup.isSystemPreferredAuthenticationMethodEnabled
                    $userTemplate.SystemEnforcedMethod = $lookup.systemPreferredAuthenticationMethods
                    $userTemplate.IsPasswordlessCapable = $lookup.isPasswordlessCapable
                    $userTemplate.IsAdmin = $lookup.isAdmin
                    $userTemplate.DefaultMFAMethod = $lookup.defaultMfaMethod
                    $userTemplate.UserPreferredMFAMethod = $lookup.userPreferredMethodForSecondaryAuthentication
                    $userTemplate.RegisteredMFAMethods = $authMethods -join ','
                    $userTemplate.MemberOf = $groupDetails -join ','

                    $appliedPolicies = @()
                    $disabledPolicies = @()
                    $caGaps = @()

                    Foreach ($policy in $conditionalAccess) {
                        If ($policy.State -ne 'enabled') {
                            $disabledPolicies += "$($policy.displayName) not applied. The policy is in $($policy.state) mode.`n"
                        }

                        # User Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -contains $target.id) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Group Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includegroups -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.includegroups }) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Role Targeted Policies
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeroles -eq "All") -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($policy.DisplayName) applied to All Users"
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.includeroles }) -and ((! ($policy.conditions.users.excludeusers -contains $target.id)) -or (! $grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or (! $grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles }))) {
                            $appliedPolicies += "$($target.displayName) targeted in policy $($policy.DisplayName)"
                        }

                        # Gaps in CA Policies
                        # By Role
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeroles -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.includeroles }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        # By User
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includeusers -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($target.id | Where-Object { $_ -in $policy.conditions.users.includeusers }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        # By Group
                        If (($policy.state -eq 'enabled') -and ($policy.conditions.users.includegroups -eq "All") -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                        Elseif (($policy.state -eq 'enabled') -and ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.includegroups }) -and (($policy.conditions.users.excludeusers -contains $target.id)) -or ($grpMemberships.id | Where-Object { $_ -in $policy.conditions.users.excludegroups }) -or ($grpMemberships.roleTemplateId | Where-Object { $_ -in $policy.conditions.users.excluderoles })) {
                            $caGaps += $($policy.DisplayName)
                        }
                    }

                    $userTemplate.AppliedCAPolicies = ($appliedPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.CAPoliciesNotApplied = ($disabledPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.PossibleCAGaps = ($caGaps | Sort-Object -Unique) -join ','

                    foreach ($x in $targetAuthMethods) {
                        Try {
                            switch ($x.Value["@odata.type"]) {
                                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                                    $MethodAuthType = 'AuthenticatorApp'
                                    $AdditionalProperties = $x.Value["displayName"]
                                }
        
                                '#microsoft.graph.phoneAuthenticationMethod' {
                                    $MethodAuthType = 'PhoneAuthentication'
                                    $AdditionalProperties = $x.Value["phoneType", "phoneNumber"] -join ' '
                                }
        
                                '#microsoft.graph.passwordAuthenticationMethod' {
                                    $MethodAuthType = 'PasswordAuthentication'
                                    $AdditionalProperties = $x.Value["displayName"]
                                }
        
                                '#microsoft.graph.fido2AuthenticationMethod' {
                                    $MethodAuthType = 'Fido2'
                                    $AdditionalProperties = $x.Value["model"]
                                }
        
                                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                                    $MethodAuthType = 'WindowsHelloForBusiness'
                                    $AdditionalProperties = $x.Value["displayName"]
                                }
        
                                '#microsoft.graph.emailAuthenticationMethod' {
                                    $MethodAuthType = 'EmailAuthentication'
                                    $AdditionalProperties = $x.Value["emailAddress"]
                                }
        
                                '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                                    $MethodAuthType = 'TemporaryAccessPass'
                                    $AdditionalProperties = 'TapLifetime:' + $x.Value["lifetimeInMinutes"] + 'm - Status:' + $x.Value["methodUsabilityReason"]
                                }
        
                                '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' {
                                    $MethodAuthType = 'Passwordless'
                                    $AdditionalProperties = $x.Value["displayName"]
                                }
        
                                '#microsoft.graph.softwareOathAuthenticationMethod' {
                                    $MethodAuthType = 'SoftwareOath'
                                    $AdditionalProperties = $x.Value["displayName"]
                                }
                            }
                        }
                        Catch {
                        
                        }
                        If ($null -ne $MethodAuthType) {
                            $authMethods += "$($MethodAuthType): $($AdditionalProperties)"
                            
                        }
                    }

                    $results += $userTemplate
                }
            }

            Return $results
        }
    }

    Connect-Session

    If ($DetailedReport.IsPresent) {
        DetailedAssessment
    }
    Else {
        QuickAssessment
    }
}

Invoke-MFArcade