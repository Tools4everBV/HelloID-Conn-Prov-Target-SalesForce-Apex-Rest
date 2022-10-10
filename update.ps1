#######################################################
# HelloID-Conn-Prov-Target-SalesForce-Apex-Rest-Update
#
# Version: 1.0.0.1
#######################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

#region mapping
# Last name generation based on name convention code
#  B  "<birth name prefix> <birth name>"
#  P  "<partner name prefix> <partner name>"
#  BP "<birth name prefix> <birth name> - <partner name prefix> <partner name>"
#  PB "<partner name prefix> <partner name> - <birth name prefix> <birth name>"
function New-Surname {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]
        $person
    )

    if ([string]::IsNullOrEmpty($person.Name.FamilyNamePrefix)) {
        $prefix = ""
    }
    else {
        $prefix = $person.Name.FamilyNamePrefix + " "
    }

    if ([string]::IsNullOrEmpty($person.Name.FamilyNamePartnerPrefix)) {
        $partnerPrefix = ""
    }
    else {
        $partnerPrefix = $person.Name.FamilyNamePartnerPrefix + " "
    }

    $Surname = switch ($person.Name.Convention) {
        "B" { $person.Name.FamilyName }
        "BP" { $person.Name.FamilyName + " - " + $partnerprefix + $person.Name.FamilyNamePartner }
        "P" { $person.Name.FamilyNamePartner }
        "PB" { $person.Name.FamilyNamePartner + " - " + $prefix + $person.Name.FamilyName }
        default { $prefix + $person.Name.FamilyName }
    }

    $Prefix = switch ($person.Name.Convention) {
        "B" { $prefix }
        "BP" { $prefix }
        "P" { $partnerPrefix }
        "PB" { $partnerPrefix }
        default { $prefix }
    }

    $output = [PSCustomObject]@{
        prefixes = $Prefix
        surname  = $Surname
    }

    Write-Output $output
}

Function New-ShortenedAlias {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]
        $person
    )
    $Alias = ($p.Name.NickName).Substring(0, 1)
    $Surname = (New-Surname $p).surname.ToLower()

    if ($Surname.Length -gt 4) {
        $Surname = $Surname.Substring(0, 4)
    }

    $Alias += $Surname
    
    $output = [PSCustomObject]@{
        Alias = $Alias        
    }

    Write-Output $output
}

$account = [PSCustomObject]@{
    UserName             = $p.Accounts.MicrosoftActiveDirectory.mail
    Firstname            = $p.Name.GivenName
    LastName             = (New-Surname $p).surname    
    CommunityNickname    = $p.Name.NickName
    Email                = $p.Accounts.MicrosoftActiveDirectory.mail
    Alias                = (New-ShortenedAlias $p).Alias
    FederationIdentifier = $p.ExternalId
    MobilePhone          = $p.Contact.Business.Phone.Mobile
    Title                = $p.PrimaryContract.Title.Name
    Department           = $p.PrimaryContract.Department.DisplayName
    UserProfile          = 'SalesForce UserProfile'
    UserRole             = 'SalesForce UserRole'
}

#region Helper Functions
function Get-SalesForceAccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]
        $AdminUserName,

        [Parameter(Mandatory = $true)]
        [string]
        $AdminPassword,

        [Parameter(Mandatory = $true)]
        [string]
        $SecurityToken
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $body = @{
            grant_type    = 'password'
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            username      = "$AdminUserName"
            password      = "$AdminPassword" + "$SecurityToken"
        }

        $splatRestMethodParameters = @{
            Uri     = "$($config.BaseUrl)/services/oauth2/token"
            Method  = 'POST'
            Headers = $headers
            Body    = $body
        }
        Invoke-RestMethod @splatRestMethodParameters
        Write-Verbose 'Finished retrieving accessToken'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $HttpErrorObj = @{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj['ErrorMessage'] = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = [System.IO.StreamReader]::new($Stream)
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.RequestUri), InvocationCommand: '$($HttpErrorObj.MyCommand)"
    }
}
#endregion

if (-not($dryRun -eq $true)) {
    try {
        Write-Verbose "Updating account for '$($p.DisplayName)'"

        if ($($config.IsConnectionTls12)) {
            Write-Verbose 'Switching to TLS 1.2'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }

        Write-Verbose 'Retrieving accessToken'
        $accessToken = Get-SalesForceAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -AdminUserName $($config.AdminUserName) -adminPassword $($config.AdminPassword) -SecurityToken $($config.SecurityToken)

        Write-Verbose 'Adding Authorization headers'
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Bearer $($accessToken.access_token)")
                
        if ($account.UserProfile) {
            Write-Verbose "Getting profileId for profile '$($account.UserProfile)'"
            $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Name,Id+from+Profile"
            $queryResult = Invoke-WebRequest -Uri $queryUrl -Method 'GET' -Headers $headers
            $queryResult = $queryResult | ConvertFrom-Json
            $selectedProfile = $queryResult.records | Where-Object { $_.Name -eq $($account.UserProfile) }
            if (-Not($selectedProfile)) {
                Write-Verbose "Profile '$($account.UserProfile)' cannot be found"
            }            
        }

        if ($account.UserRole) {
            Write-Verbose "Getting roleId for role '$($account.UserRole)'"
            $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Name,Id+from+UserRole"
            $queryResult = Invoke-WebRequest -Uri $queryUrl -Method 'GET' -Headers $headers
            $queryResult = $queryResult | ConvertFrom-Json
            $selectedRole = $queryResult.records | Where-Object { $_.Name -eq $($account.UserRole) }
            if (-Not($selectedRole)) {
                Write-Verbose "Role '$($account.UserRole)' cannot be found"
            }
        }

        Write-Verbose "Getting previous user for '$($p.DisplayName)'"        
        $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Username,Firstname,LastName,CommunityNickname,Email,Alias,FederationIdentifier,MobilePhone,Title,ProfileId,UserRoleId+from+User+WHERE+Id='$aRef'"
        $queryResult = Invoke-RestMethod -Uri $queryUrl -Method 'GET' -Headers $headers
        $pp = $queryResult.records
        
        $body = $null
        
        if ($account.UserName -ne $pp.UserName) {            
            $body += @{
                Username = $account.UserName
            }
        }
        if ($account.FirstName -ne $pp.FirstName) {
            $body += @{
                Firstname = $account.FirstName
            }
        }
        if ($account.LastName -ne $pp.LastName) {
            $body += @{
                LastName = $account.LastName
            }
        }
        if ($account.CommunityNickname -ne $pp.CommunityNickname) {
            $body += @{
                CommunityNickname = $account.CommunityNickname
            }
        }
        if ($account.Email -ne $pp.Email) {
            $body += @{
                Email = $account.Email
            }
        }
        if ($account.Alias -ne $pp.Alias) {
            $body += @{
                Alias = $account.Alias
            }
        }
        if ($account.FederationIdentifier -ne $pp.FederationIdentifier) {
            $body += @{
                FederationIdentifier = $account.FederationIdentifier
            }
        }
        if ($account.MobilePhone -ne $pp.MobilePhone) {
            $body += @{
                MobilePhone = $account.MobilePhone
            }
        }
        if ($account.Title -ne $pp.Title) {
            $body += @{
                Title = $account.Title
            }
        }
        if ($account.Department -ne $pp.Department) {
            $body += @{
                Title = $account.Department
            }
        }
        if ($selectedProfile.id -ne $pp.ProfileId) {
            $body += @{
                ProfileId = $selectedProfile.id
            }
        }
        if ($selectedRole.id -ne $pp.UserRoleId) {
            $body += @{
                UserRoleId = $selecselectedRoletedProfile.id
            }
        }

        if ($null -ne $body) {
            
            $body = $body | ConvertTo-Json
        
            $splatParams = @{
                Uri         = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/sobjects/User/$aRef"
                Headers     = $headers
                Body        = ([Text.Encoding]::UTF8.GetBytes($body))
                Method      = 'PATCH'
                ContentType = 'application/json'
            }

            $null = Invoke-RestMethod @splatParams            

            $logMessage = "Account for '$($p.DisplayName)' successfully updated"
            Write-Verbose -Verbose $logMessage
            $success = $true
            $auditLogs.Add([PSCustomObject]@{
                    Message = $logMessage
                    IsError = $False
                })
        }

        if ($null -eq $body) {
            $logMessage = "No updates necessary for account '$($p.DisplayName)'"
            Write-Verbose -Verbose $logMessage
            $success = $true
            $auditLogs.Add([PSCustomObject]@{
                    Message = $logMessage
                    IsError = $False
                })
        }
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            $auditMessage = "Account for '$($p.DisplayName)' not updated. Error: $errorMessage"
        }
        else {
            $auditMessage = "Account for '$($p.DisplayName)' not updated. Error: $($ex.Exception.Message)"
        }
        $auditLogs.Add([PSCustomObject]@{
                Message = $auditMessage
                IsError = $true
            })
        Write-Error $auditMessage
    }
}

$result = [PSCustomObject]@{
    Success          = $success
    Account          = $account
    AccountReference = $aRef
    AuditLogs        = $auditLogs

    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{        
        AccountReference = $aRef
        LoginName        = $account.username
    };
}

Write-Output $result | ConvertTo-Json -Depth 10