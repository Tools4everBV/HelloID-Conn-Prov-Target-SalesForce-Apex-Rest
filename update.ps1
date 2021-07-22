#######################################################
# HelloID-Conn-Prov-Target-SalesForce-Apex-Rest-Update
#
# Version: 1.0.0.0
#######################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

$account = [PSCustomObject]@{
    UserName          = $pd.UserName.New
    Firstname         = $pd.Name.GivenName.New
    LastName          = $pd.Name.FamilyName.New
    CommunityNickname = $pd.Name.NickName.New
    Email             = $pd.Contact.Business.Email.New
    IsActive          = $true
    TimeZoneSidKey    = 'Europe/Amsterdam'
    LocalSidKey       = 'nl_NL'
    LanguageLocaleKey = 'nl_NL'
    EmailEncodingKey  = 'ISO-8859-1'
    UserProfile       = ''
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
            Uri     = 'https://login.salesforce.com/services/oauth2/token'
            Method  = 'POST'
            Headers = $headers
            Body    = $body
        }
        Invoke-RestMethod @splatRestMethodParameters
        Write-Verbose 'Finished retrieving accessToken'
    } catch {
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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
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
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Bearer $accessToken")

        if ($account.profile){
            Write-Verbose 'Getting current user profile information'
            $queryUrl = "$($config.BaseUrl)/services/data/$($config.ApiVersion)/query/?q=SELECT+Name,Id,UserLicenseId+from+Profile}"
            $queryResult = Invoke-RestMethod -Uri $queryUrl -Method 'GET' -Headers $headers
            $userProfile = $queryResult.records | Where-Object {$_.Name -eq $account.profile}
            if (-Not($profile)){
                Write-Verbose "Profile '$($account.profile)' cannot be found"
            }
            $profileId = $userProfile.Id
        }

        $body = $null
        if($account.UserName){
            $body += @{
                Username = $account.UserName
            }
        }
        if($account.FirstName){
            $body += @{
                Username = $account.FirstName
            }
        }
        if($account.LastName){
            $body += @{
                Username = $account.LastName
            }
        }
        if($account.CommunityNickname){
            $body += @{
                Username = $account.CommunityNickname
            }
        }
        if($account.Email){
            $body += @{
                Username = $account.Email
            }
        }
        if($account.LastName){
            $body += @{
                Username = $account.LastName
            }
        }
        $body['ProfileId'] = $profileId
        $body = $body | ConvertTo-Json

        $splatParams = @{
            Uri      = "$($config.BaseUrl)/services/data/$($config.ApiVersion)/sobjects/User/$aRef"
            Headers  = $headers
            Body     = $body
            Method   = 'PATCH'
        }
        $results = Invoke-RestMethod @splatParams
        $accountReference = $results.Id

        $logMessage = "Account for '$($p.DisplayName)' successfully updated"
        Write-Verbose $logMessage
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
            Message = $logMessage
            IsError = $False
        })
    } catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            $auditMessage = "Account for '$($p.DisplayName)' not updated. Error: $errorMessage"
        } else {
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
    AuditLogs        = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10
