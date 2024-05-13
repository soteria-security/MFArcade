<#
.SYNOPSIS
    Generates a risk-based report of user mutli-factor authentication and possible Conditional Access Policy assignment gaps.
.PARAMETER OutPath
    Report destination. Directory input only.
.PARAMETER ReportType
    Desired Report Format. Options are CSV, XML, JSON, EXCEL, HTML, or None (GridView). All may also be specified to create all report types except GridView.
.PARAMETER ShowReport
    Automatically launches the chosen report type.
.EXAMPLE
   .\MFArcade.ps1 -OutPath "$reports\MFArcade" -reportType EXCEL -ShowReport
.EXAMPLE
    .\MFArcade.ps1 -OutPath "$reports\MFArcade" -reportType EXCEL
.EXAMPLE
    .\MFArcade.ps1 -OutPath "$reports\MFArcade" -reportType None
.OUTPUTS
    Desired report output in the defined OutPath parameter.
.LINK
    https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-methods-activity
#>

param (
    [Parameter(Mandatory = $true,
        HelpMessage = 'Output path for report')]
    [string] $OutPath,
    [Parameter(Mandatory = $false,
        HelpMessage = "Report Output Format")]
    [ValidateSet("All", "HTML", "CSV", "XML", "JSON", "EXCEL", "None",
        IgnoreCase = $true)]
    [string] $reportType = "All",
    [Parameter(Mandatory = $true,
        HelpMessage = 'Opens the genrated report(s)')]
    [switch] $ShowReport
)

#Requires -Modules "Microsoft.Graph.Reports","Microsoft.Graph.Beta.Identity.DirectoryManagement", "Microsoft.Graph.Groups", "Microsoft.Graph.Beta.Identity.SignIns"
#Requires -Modules "ImportExcel"

Function Invoke-MFArcade {
    $establishedConnection = $null

    $global:path = $OutPath

    If (! (Test-Path $global:path)) {
        New-Item -ItemType Directory -Path $global:path -Force | Out-Null
    }

    $global:sortedResults = @()

    Function Connect-Session {
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

        If (! $establishedConnection) {
            Write-Host "Connecting to Microsoft Graph"
            Connect-MgGraph -ContextScope Process -Scopes "Reports.Read.All", "Policy.Read.All", "Directory.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All"
        }
    }

    Connect-Session

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

                $total = ($mfaReport | Measure-Object).Count
                $counter = 0
                    
                ForEach ($lookup in $mfaReport) {
                    $counter++
                    $progress = ($counter / $total) * 100
                    $progressMsg = "Processing Object $counter of $total"
        
                    Write-Progress -Activity "Processing Users" -Status $progressMsg -PercentComplete $progress

                    $userTemplate = [PSCustomObject]@{
                        Name                          = $null
                        Id                            = $null
                        UserPrincipalName             = $null
                        Risk                          = $null
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

                    $grpMemberships = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($upn)/transitiveMemberOf?select=id,roleTemplateId,displayName").value

                    $groupDetails = $grpMemberships | Foreach-Object { "$($_.displayName) ($((($_.'@odata.type') -split '#microsoft.graph.')[1]))" }

                    $appliedPolicies = @()
                    $disabledPolicies = @()
                    $caGaps = @()
                    $authMethods = @()

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

                    foreach ($x in $targetAuthMethods) {
                        switch ($x["@odata.type"]) {
                            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                                $MethodAuthType = 'AuthenticatorApp'
                                $AdditionalProperties = $x["displayName"]
                            }
        
                            '#microsoft.graph.phoneAuthenticationMethod' {
                                $MethodAuthType = 'PhoneAuthentication'
                                $AdditionalProperties = $x["phoneType", "phoneNumber"] -join ' '
                            }
        
                            '#microsoft.graph.passwordAuthenticationMethod' {
                                $MethodAuthType = 'PasswordAuthentication'
                                $AdditionalProperties = $x["displayName"]
                            }
        
                            '#microsoft.graph.fido2AuthenticationMethod' {
                                $MethodAuthType = 'Fido2'
                                $AdditionalProperties = $x["model"]
                            }
        
                            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                                $MethodAuthType = 'WindowsHelloForBusiness'
                                $AdditionalProperties = $x["displayName"]
                            }
        
                            '#microsoft.graph.emailAuthenticationMethod' {
                                $MethodAuthType = 'EmailAuthentication'
                                $AdditionalProperties = $x["emailAddress"]
                            }
        
                            '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                                $MethodAuthType = 'TemporaryAccessPass'
                                $AdditionalProperties = 'TapLifetime:' + $x["lifetimeInMinutes"] + 'm - Status:' + $x["methodUsabilityReason"]
                            }
        
                            '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' {
                                $MethodAuthType = 'Passwordless'
                                $AdditionalProperties = $x["displayName"]
                            }
        
                            '#microsoft.graph.softwareOathAuthenticationMethod' {
                                $MethodAuthType = 'SoftwareOath'
                                $AdditionalProperties = $x["displayName"]
                            }
                        }
                    
                        $result = [PSCustomObject]@{
                            Method        = $MethodAuthType
                            MethodDetails = $AdditionalProperties
                        }
                        
                        $authMethods += "$($result.Method) ; $($result.MethodDetails)"
                    }


                    $userTemplate.Name = $target.displayName
                    $userTemplate.Id = $target.id
                    $userTemplate.IsEnabled = $lookup.isEnabled
                    $userTemplate.IsMFACapable = $lookup.isCapable
                    $userTemplate.IsMFARegistered = $lookup.isMfaRegistered
                    $userTemplate.IsSSPRCapable = $lookup.isSsprCapable
                    $userTemplate.IsSSPREnabled = $lookup.isSsprEnabled
                    $userTemplate.IsSSPRRegistered = $lookup.isSsprRegistered
                    $userTemplate.SystemPreferredMethodEnforced = $lookup.isSystemPreferredAuthenticationMethodEnabled
                    $userTemplate.SystemEnforcedMethod = ($lookup.systemPreferredAuthenticationMethods) -join " "
                    $userTemplate.IsPasswordlessCapable = $lookup.isPasswordlessCapable
                    $userTemplate.IsAdmin = $lookup.isAdmin
                    $userTemplate.DefaultMFAMethod = $lookup.defaultMfaMethod
                    $userTemplate.UserPreferredMFAMethod = $lookup.userPreferredMethodForSecondaryAuthentication
                    $userTemplate.RegisteredMFAMethods = $authMethods -join ', '
                    $userTemplate.MemberOf = $groupDetails -join ','
                    $userTemplate.AppliedCAPolicies = ($appliedPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.CAPoliciesNotApplied = ($disabledPolicies | Sort-Object -Unique) -join ','
                    $userTemplate.PossibleCAGaps = ($caGaps | Sort-Object -Unique) -join ','

                    $Risk = ""

                    If ($caGaps) {
                        $Risk = 'Critical'
                    }
                    ElseIf (($lookup.isAdmin -eq $true) -and (($lookup.IsMfaRegistered -eq $false) -or ($lookup.IsMfaCapable -eq $false)) -or (($lookup.isAdmin -eq $true) -and (($lookup.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($lookup.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                        $Risk = 'Critical'
                    }
                    ElseIf (($lookup.isAdmin -eq $false) -and (($lookup.IsMfaRegistered -eq $false) -or ($lookup.IsMfaCapable -eq $false)) -or (($lookup.isAdmin -eq $false) -and (($lookup.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($lookup.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                        $Risk = 'High'
                    }
                    ElseIf ($lookup.IsSsprRegistered -eq $false) {
                        $Risk = 'Medium'
                    }
                    Else {
                        $Risk = 'Low'
                    }

                    $userTemplate.Risk = $Risk

                    $results += $userTemplate
                }
            }

            $global:sortedResults += $results | Sort-Object { Switch -Regex ($_.Risk) { 'Critical' { 1 }	'High' { 2 }	'Medium' { 3 }	'Low' { 4 } } } 
        }
    }


    Function Generate-HTMLReport {
        $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).html"
        Write-Host "Generating report $($reportFile)"

        $criticalCount = 0
        $highCount = 0
        $mediumCount = 0
        $lowCount = 0

        ForEach ($result in $global:sortedResults) {
            If ($result.Risk -eq 'Critical') {
                $result.Risk = '<span style="color:Crimson;"><strong>Critical</strong></span>'
                $criticalCount += 1
            }
            If ($result.Risk -eq 'High') {
                $result.Risk = '<span style="color:DarkOrange;"><strong>High</strong></span>'
                $highCount += 1
            }
            If ($result.Risk -eq 'Medium') {
                $result.Risk = '<span style="color:DarkGoldenRod;"><strong>Medium</strong></span>'
                $mediumCount += 1
            }
            If ($result.Risk -eq 'Low') {
                $lowCount += 1
            }
        }
        
        $totalCount = $criticalCount + $highCount + $mediumCount + $lowCount

        $tableRows = $global:sortedResults | ForEach-Object {
            $rowHtml = @"
                <tr>
                    <td>$($_.Name)</td>
                    <td>$($_.Id)</td>
                    <td>$($_.UserPrincipalName)</td>
                    <td>$($_.Risk)</td>
                    <td>$($_.IsEnabled)</td>
                    <td>$($_.IsExternal)</td>
                    <td>$($_.IsAdmin)</td>
                    <td>$($_.IsSSPRCapable)</td>
                    <td>$($_.IsSSPREnabled)</td>
                    <td>$($_.IsSSPRRegistered)</td>
                    <td>$($_.IsMFACapable)</td>
                    <td>$($_.IsMFARegistered)</td>
                    <td>$($_.RegisteredMFAMethods)</td>
                    <td>$($_.DefaultMFAMethod)</td>
                    <td>$($_.SystemPreferredMethodEnforced)</td>
                    <td>$($_.SystemEnforcedMethod)</td>
                    <td>$($_.UserPreferredMFAMethod)</td>
                    <td>$($_.IsPasswordlessCapable)</td>
                    <td>$($_.MemberOf)</td>
                    <td>$($_.AppliedCAPolicies)</td>
                    <td>$($_.CAPoliciesNotApplied)</td>
                    <td>$($_.PossibleCAGaps)</td>
                </tr>
"@
            $rowHtml
        }

        $htmlReport = @"
        <html>

        <head>
            <meta content="text/html; charset=UTF-8" http-equiv="content-type">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style type="text/css">
                @import url(https://themes.googleusercontent.com/fonts/css?kit=toadOcfmlt9b38dHJxOBGL40yRR11Bk043VmwNc2-VdJNKf5lpbTaoq56xx1HhKI-lm9KUox0UUkSgunUYOJKw);
        
                ul.lst-kix_bakjdvg45s3f-8 {
                    list-style-type: none
                }
        
                @import url('https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400&display=swap');
        
                ol {
                    margin: 0;
                    padding: 0
                }

                table {
                    border-collapse: collapse;
                    width: 100%;
                    max-width: 100%;
                    overflow-x: auto;
                }

                th, td {
                    border: 1px solid black;
                    padding: 8px;
                    text-align: center;
                    word-wrap: break-word;
                }

                .table-container {
                    overflow-x: auto;
                    width: 100%;
                    max-width: 1200px; /* Adjust the maximum width as needed */
                    margin: 0 auto; /* Center the table horizontally */
                }
        
                .c12 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 0pt;
                    border-right-width: 0pt;
                    border-left-color: #000000;
                    vertical-align: top;
                    border-right-color: #000000;
                    border-left-width: 0pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 65.2pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c33 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 0pt;
                    border-right-width: 0pt;
                    border-left-color: #000000;
                    vertical-align: top;
                    border-right-color: #000000;
                    border-left-width: 0pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 200.2pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c3 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 1pt;
                    border-right-width: 1pt;
                    border-left-color: #000000;
                    vertical-align: middle;
                    border-right-color: #000000;
                    border-left-width: 1pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 27pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c15 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 1pt;
                    border-right-width: 1pt;
                    border-left-color: #000000;
                    vertical-align: middle;
                    border-right-color: #000000;
                    border-left-width: 1pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 65.2pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c11 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 1pt;
                    border-right-width: 1pt;
                    border-left-color: #000000;
                    vertical-align: middle;
                    border-right-color: #000000;
                    border-left-width: 1pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 200.2pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c30 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 0pt;
                    border-right-width: 0pt;
                    border-left-color: #000000;
                    vertical-align: top;
                    border-right-color: #000000;
                    border-left-width: 0pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 27pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c4 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 1pt;
                    border-right-width: 1pt;
                    border-left-color: #000000;
                    vertical-align: middle;
                    border-right-color: #000000;
                    border-left-width: 1pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 247.5pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c18 {
                    border-right-style: solid;
                    padding: 5pt 5pt 5pt 5pt;
                    border-bottom-color: #000000;
                    border-top-width: 0pt;
                    border-right-width: 0pt;
                    border-left-color: #000000;
                    vertical-align: top;
                    border-right-color: #000000;
                    border-left-width: 0pt;
                    border-top-style: solid;
                    border-left-style: solid;
                    border-bottom-width: 1pt;
                    width: 247.5pt;
                    border-top-color: #000000;
                    border-bottom-style: solid
                }
        
                .c25 {
                    padding-top: 16pt;
                    padding-bottom: 4pt;
                    line-height: 1.15;
                    page-break-after: avoid;
                    orphans: 2;
                    widows: 2;
                    text-align: left;
                    height: 24pt
                }
        
                .c19 {
                    padding-top: 16pt;
                    padding-bottom: 4pt;
                    line-height: 1.15;
                    page-break-after: avoid;
                    orphans: 2;
                    widows: 2;
                    text-align: left
                }
        
                .c21 {
                    padding-top: 0pt;
                    padding-bottom: 0pt;
                    line-height: 1.15;
                    page-break-after: avoid;
                    orphans: 2;
                    widows: 2;
                    text-align: left
                }
        
                .c5 {
                    color: #000000;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 11pt;
                    font-family: "Source Sans Pro Light", "Source Sans Pro";
                    font-style: normal
                }
        
                .c31 {
                    color: #d9d9d9;
                    font-weight: 200;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 11pt;
                    font-family: "Source Sans Pro Light", "Source Sans Pro";
                    font-style: normal
                }
        
                .c14 {
                    color: #4290eb;
                    font-weight: 200;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 30pt;
                    font-family: "Source Sans Pro Light", "Source Sans Pro";
                    font-style: normal
                }
        
                .c2 {
                    color: #4290eb;
                    font-weight: 400;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 24pt;
                    font-family: "Source Sans Pro";
                    font-style: normal
                }
        
                .c1 {
                    padding-top: 0pt;
                    padding-bottom: 0pt;
                    line-height: 1.15;
                    orphans: 2;
                    widows: 2;
                    text-align: justify;
                }
        
                .c7 {
                    color: #000000;
                    font-weight: 400;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 11pt;
                    font-family: "Source Sans Pro";
                    font-style: normal
                }
        
                .c23 {
                    color: #000000;
                    font-weight: 600;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 11pt;
                    font-family: "Source Sans Pro";
                    font-style: normal
                }
        
                .c34 {
                    color: #000000;
                    font-weight: 200;
                    text-decoration: none;
                    vertical-align: baseline;
                    font-size: 6pt;
                    font-family: "Source Sans Pro Light", "Source Sans Pro";
                    font-style: normal
                }
        
                .c0 {
                    padding-top: 0pt;
                    padding-bottom: 0pt;
                    line-height: 1.0;
                    orphans: 2;
                    widows: 2;
                    text-align: left;
                }
        
                .c8 {
                    padding-top: 0pt;
                    padding-bottom: 0pt;
                    line-height: 1.0;
                    orphans: 2;
                    widows: 2;
                    text-align: center
                }
        
                .c20 {
                    padding-top: 0pt;
                    padding-bottom: 0pt;
                    line-height: 1.15;
                    orphans: 2;
                    widows: 2;
                    text-align: justify
                }
        
                .c6 {
                    padding-top: 0pt;
                    padding-bottom: 10pt;
                    line-height: 1.15;
                    orphans: 2;
                    widows: 2;
                    text-align: justify
                }
        
                .c24 {
                    background-color: #ffffff;
                    max-width: 540pt;
                    padding: 36pt 36pt 36pt 36pt
                }
        
                .c10 {
                    color: inherit;
                    text-decoration: inherit
                }
        
                .c29 {
                    font-size: 30pt
                }
        
                .table-container {
                    overflow-x: auto;
                }
        
                @media only screen and (max-width: 600px) {
                    th,
                    td {
                        font-size: 12px;
                    }
                }
            </style>
        </head>
        
        <body class="c24">
            <link href="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/themes/prism.min.css" rel="stylesheet" />
            <script src="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/prism.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/components/prism-powershell.min.js"></script>
            <p class="c21 title" id="h.jcmsrxce36fv" style="text-align:center;">
                <span class="c27">
                    <a class="c10" href="">MFArcade Report</a>
                </span>
                <span class="c14"></span>
            </p>
            <p class="c21 title" id="h.gan1mgr3c5k5" style="text-align:center;">
                <span class="c14">Multi-factor Registration and Conditional Access Gaps Report</span>
            </p>
            <p class="c1">
                <span class="c5"></span>
            </p>
            <h1 class="c19" id="h.1pyz3jiilmxm">
                <span class="c2">About This Report</span>
            </h1>
            <!--BEGIN_EXECSUM_TEMPLATE-->
            <p class="c6">
                This report was generated by <a
                    href="https://github.com/soteria-security/Invoke-MFArcade">MFArcade Report</a>, the
                open-source Microsoft 365 multi-factor assessment tool.
                <br /><br />
            </p>
            <!--END_EXECSUM_TEMPLATE-->
            <!--BEGIN_CHART_TEMPLATE-->
            <h1 class="c19" id="h.1pyz3jiilmxm">
                <span class="c2">Risk Severity</span>
            </h1>
            <!-- RISK RATING BAR CHART -->
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0"></script>
            <div class="chart-container">
                <canvas id="riskChart"></canvas>
            </div>
            <script>
                var ctx = document.getElementById('riskChart').getContext('2d');

                // Calculate percentages based on total count
                var totalFindingsString = $totalCount;
                var totalFindings = parseInt(totalFindingsString);

                var criticalCount = $criticalCount;
                var highCount = $highCount;
                var mediumCount = $mediumCount;
                var lowCount = $lowCount

                var dataValues = [criticalCount, highCount, mediumCount, lowCount];

                // Find the largest bar value
                var largestBarValue = Math.max(...dataValues);

                // Calculate the maximum value for the x-axis ticks
                var maxTickValue = Math.ceil(largestBarValue / 10) * 10;

                // Add an extra tick if necessary
                if (maxTickValue < largestBarValue) {
                    maxTickValue += 5;
                }

                var myChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{
                            label: 'Severity',
                            backgroundColor: ['#FC0303', '#FC6D03', '#FCDE03'],
                            data: dataValues
                        }]
                    },
                    plugins: [ChartDataLabels],
                    options: {
                        legend: {
                            display: false,
                        },
                        title: {
                            display: true,
                            text: 'Risk Ratings'
                        },
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        scales: {
                            x: {
                                type: 'linear',
                                min: 0,
                                max: (maxTickValue += 5),
                                ticks: {
                                    stepSize: 5,
                                    precision: 0
                                },
                                grid: {
                                    display: false
                                }
                            },
                            y: {
                                grid: {
                                    display: false
                                }
                            }
                        },
                        plugins: {
                            datalabels: {
                                anchor: 'end',
                                align: 'end',
                                font: {
                                    size: 11,
                                    weight: 'bold'
                                },
                                formatter: function (value, context) {
                                    var count = context.dataset.data[context.dataIndex];
                                    var percentage = Math.round(((count / totalFindings) * 100).toFixed(1)) + '%';
                                    return context.chart.data.labels[context.dataIndex] + ": " + count + "\n" + "(" + percentage + ")";
                                }
                            }
                        },
                        tooltips: {
                            callbacks: {
                                label: function (tooltipItem, data) {
                                    var count = data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index];
                                    var percentage = Math.round(((count / totalFindings) * 100).toFixed(1)) + '%';
                                    return data.labels[tooltipItem.index] + ": " + count + " (" + percentage + ")";
                                }
                            }
                        }
                    }
                });
            </script>
            <!--END_CHART_TEMPLATE-->
            <!--BEGIN_FINDING_SHORT_REPEATER-->
            <h1 class="c19" id="h.1pyz3jiilmxm">
                <span class="c2">Multi-factor Risk Table</span>
            </h1>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
            <table class="table-container" id="results">
                <thead>
                    <tr class="c9">
                        <th>Name</th>
                        <th>Id</th>
                        <th>UserPrincipalName</th>
                        <th>Risk</th>
                        <th>IsEnabled</th>
                        <th>IsExternal</th>
                        <th>IsAdmin</th>
                        <th>IsSSPRCapable</th>
                        <th>IsSSPREnabled</th>
                        <th>IsSSPRRegistered</th>
                        <th>IsMFACapable</th>
                        <th>IsMFARegistered</th>
                        <th>RegisteredMFAMethods</th>
                        <th>DefaultMFAMethod</th>
                        <th>SystemPreferredMethodEnforced</th>
                        <th>SystemEnforcedMethod</th>
                        <th>UserPreferredMFAMethod</th>
                        <th>IsPasswordlessCapable</th>
                        <th>MemberOf</th>
                        <th>AppliedCAPolicies</th>
                        <th>CAPoliciesNotApplied</th>
                        <th>PossibleCAGaps</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
            <!--END_FINDING_SHORT_REPEATER-->
        </body>
        
        </html>
"@
        $htmlReport | Out-File -FilePath $reportFile
        If ($ShowReport.IsPresent) {
            If ((Test-Path $reportFile) -eq $true) {
                Start-Process $reportFile
            }
        }
    }

    Function Generate-CSVReport {
        $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).csv"
        Write-Host "Generating report $($reportFile)"
        Try {
            $global:sortedResults | Export-Csv -Path $reportFile -NoTypeInformation -ErrorAction Stop
        }
        Catch {
            Write-Warning "Error message: $($_.Exception.Message)"
        }
        If ($ShowReport.IsPresent) {
            If ((Test-Path $reportFile) -eq $true) {
                Start-Process $reportFile
            }
        }
    }

    Function Generate-JSONReport {
        $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).json"
        Write-Host "Generating report $($reportFile)"
        Try {
            $global:sortedResults | ConvertTo-Json -Depth 10 | Out-File $reportFile -ErrorAction Stop
        }
        Catch {
            Write-Warning "Error message: $($_.Exception.Message)"
        }
        If ($ShowReport.IsPresent) {    
            If ((Test-Path $reportFile) -eq $true) {
                Start-Process $reportFile
            }
        }
    }

    Function Generate-XMLReport {
        $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).xml"
        Write-Host "Generating report $($reportFile)"
        Try {
            $global:sortedResults | Export-Clixml -Depth 3 -Path $reportFile -ErrorAction Stop
        }
        Catch {
            Write-Warning "Error message: $($_.Exception.Message)"
        }
        If ($ShowReport.IsPresent) {
            If ((Test-Path $reportFile) -eq $true) {
                Start-Process $reportFile
            }
        }
    }

    Function Generate-ExcelReport {
        $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).xlsx"
        Write-Host "Generating report $($reportFile)"
    
        $reportDetails = $global:sortedResults
    
        $criticalCount = 0
        $highCount = 0
        $mediumCount = 0
        $lowCount = 0
    
        ForEach ($result in $global:sortedResults) {
            Switch ($result.Risk) {
                'Critical' { $criticalCount += 1 }
                'High' { $highCount += 1 }
                'Medium' { $mediumCount += 1 }
                'Low' { $lowCount += 1 }
            }
        }
    
        $data = ConvertFrom-Csv @"
            Risk,RiskCount
            Critical,$criticalCount
            High,$highCount
            Medium,$mediumCount
            Low,$lowCount
"@
    
        # Sort data by risk level
        $data = $data | Sort-Object @{ Expression = { [Array]::IndexOf(@('Critical', 'High', 'Medium', 'Low'), $_.Risk) } }
    
        $chart = @{
            WorkSheet = $excelReport.Summary
            Title     = "Risk Distribution"
            XRange    = 'Risk'
            YRange    = 'RiskCount'
            ChartType = "ColumnClustered"
            NoLegend  = $true
        }
    
        $excelReport = Open-ExcelPackage -Path $reportFile -Create
    
        $excelReport = $data | Export-Excel -ExcelPackage $excelReport -WorksheetName "Summary" -AutoNameRange -AutoSize -TableStyle Medium16 -ExcelChartDefinition $chart -PassThru -StartRow 1
    
        $excelReport = $reportDetails | Export-Excel -ExcelPackage $excelReport -WorksheetName "MFA_Report" -AutoSize -TableStyle Medium16 -PassThru
    
        If ($ShowReport.IsPresent) {
            Close-ExcelPackage $excelReport -Show
        }
        Else {
            Close-ExcelPackage $excelReport
        }
    }

    DetailedAssessment

    If ($reportType -eq 'Csv') {
        Generate-CSVReport
    }
    ElseIf ($reportType -eq 'JSON') {
        Generate-JSONReport
    }
    ElseIf ($reportType -eq 'XML') {
        Generate-XMLReport
    }
    ElseIf ($reportType -eq 'HTML') {
        Generate-HTMLReport
    }
    ElseIf ($reportType -eq 'EXCEL') {
        Generate-ExcelReport
    }
    ElseIf ($reportType -eq 'All') {
        Generate-CSVReport
        Generate-ExcelReport
        Generate-JSONReport
        Generate-HTMLReport
        Generate-XMLReport
    }
    ElseIf ($reportType -eq 'None') {
        $global:sortedResults | Out-GridView
    }
}

Invoke-MFArcade