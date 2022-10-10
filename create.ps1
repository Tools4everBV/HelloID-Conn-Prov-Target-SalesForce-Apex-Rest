#######################################################
# HelloID-Conn-Prov-Target-SalesForce-Apex-Rest-Create
#
# Version: 1.0.0.1
#######################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
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
    UserName                       = $p.Accounts.MicrosoftActiveDirectory.mail
    Firstname                      = $p.Name.GivenName
    LastName                       = (New-Surname $p).surname
    CommunityNickname              = $p.Name.NickName
    Email                          = $p.Accounts.MicrosoftActiveDirectory.mail
    Alias                          = (New-ShortenedAlias $p).Alias
    FederationIdentifier           = $p.ExternalId
    MobilePhone                    = $p.Contact.Business.Phone.Mobile
    Title                          = $p.PrimaryContract.Title.Name
    Department                     = $p.PrimaryContract.Department.DisplayName
    CompanyName                    = 'Organisation Name'
    IsActive                       = $true
    UserPermissionsInteractionUser = $true    
    EmailPreferencesAutoBcc        = $false
    TimeZoneSidKey                 = 'Europe/Amsterdam'
    LocaleSidKey                   = 'nl_NL'
    LanguageLocaleKey              = 'nl_NL'
    EmailEncodingKey               = 'UTF-8'
    UserProfile                    = 'Salesforce Profile'
    UserRole                       = 'Salesforce UserRole'
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
        Write-Verbose "Creating account for '$($p.DisplayName)'"

        if ($($config.IsConnectionTls12)) {
            Write-Verbose 'Switching to TLS 1.2'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }

        Write-Verbose 'Retrieving accessToken'
        $accessToken = Get-SalesForceAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -AdminUserName $($config.AdminUserName) -adminPassword $($config.AdminPassword) -SecurityToken $($config.SecurityToken)

        Write-Verbose 'Adding Authorization headers'
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Bearer $($accessToken.access_token)")

        Write-Verbose "Checking if account with UserName '$($account.UserName)' already exists"
        #$queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Username,Id,CommunityNickname,ProfileId+from+User+WHERE+Username='$($account.UserName)'"
        $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Username,Id,CommunityNickname,ProfileId,FederationIdentifier+from+User+WHERE+FederationIdentifier='$($account.FederationIdentifier)'"
        $queryResult = Invoke-RestMethod -Uri $queryUrl -Method 'GET' -Headers $headers
        Write-Verbose -Verbose ($queryResult | ConvertTo-Json)
        #if ($queryResult.records.Username -contains $($account.UserName)) {
        if ($queryResult.records.FederationIdentifier -contains $($account.FederationIdentifier)) {
            $accountReference = $queryResult.records.Id
            #$logMessage = "Account with username $($account.UserName) found"
            $logMessage = "Account with ExternalId $($account.FederationIdentifier) found"
            Write-Verbose $logMessage
            $success = $true
            $auditLogs.Add([PSCustomObject]@{
                    Message = $logMessage
                    IsError = $False
                })
        }
        else {
            Write-Verbose "Account with username '$($account.UserName)' for '$($account.FederationIdentifier)' does not exist, proceeding with creating Salesforce account"

            Write-Verbose "Getting profileId for profile '$($account.UserProfile)'"
            $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Name,Id+from+Profile"
            $queryResult = Invoke-WebRequest -Uri $queryUrl -Method 'GET' -Headers $headers
            $queryResult = $queryResult | ConvertFrom-Json
            $selectedProfile = $queryResult.records | Where-Object { $_.Name -eq $($account.UserProfile) }
            
            Write-Verbose "Getting roleId for role '$($account.UserRole)'"
            $queryUrl = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/query/?q=SELECT+Name,Id+from+UserRole"
            $queryResult = Invoke-WebRequest -Uri $queryUrl -Method 'GET' -Headers $headers
            $queryResult = $queryResult | ConvertFrom-Json
            $selectedRole = $queryResult.records | Where-Object { $_.Name -eq $($account.UserRole) }

            $body = @{
                Username                       = $account.Username
                FirstName                      = $account.FirstName
                LastName                       = $account.LastName
                CommunityNickname              = $account.CommunityNickname
                Email                          = $account.Email
                Alias                          = $account.Alias
                FederationIdentifier           = $account.FederationIdentifier
                MobilePhone                    = $account.MobilePhone
                Title                          = $account.Title
                Department                     = $account.Department
                CompanyName                    = $account.CompanyName
                ProfileId                      = $selectedProfile.Id
                UserRoleId                     = $selectedRole.Id
                IsActive                       = $account.IsActive
                UserPermissionsInteractionUser = $account.UserPermissionsInteractionUser
                EmailPreferencesAutoBcc        = $account.EmailPreferencesAutoBcc
                TimeZoneSidKey                 = $account.TimeZoneSidKey
                LocaleSidKey                   = $account.LocaleSidKey
                LanguageLocaleKey              = $account.LanguageLocaleKey
                EmailEncodingKey               = $account.EmailEncodingKey
            } | ConvertTo-Json

            $splatParams = @{
                Uri         = "$($accessToken.instance_url)/services/data/$($config.ApiVersion)/sobjects/User"
                Headers     = $headers
                Body        = ([Text.Encoding]::UTF8.GetBytes($body))
                Method      = 'POST'
                ContentType = 'application/json'
            }

            $results = Invoke-RestMethod @splatParams
            $accountReference = $results.Id

            $logMessage = "Account for '$($p.DisplayName)' successfully created with username '$($account.UserName)'. Correlation id: '$accountReference'"
            Write-Verbose $logMessage
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
            $auditMessage = "Account for '$($p.DisplayName)' not created. Error: $errorMessage"
        }
        else {
            $auditMessage = "Account for '$($p.DisplayName)' not created. Error: $($ex.Exception.Message)"
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
    AccountReference = $accountReference
    AuditLogs        = $auditLogs

    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{        
        AccountReference = $accountReference
        LoginName        = $account.username
    };
}

Write-Output $result | ConvertTo-Json -Depth 10