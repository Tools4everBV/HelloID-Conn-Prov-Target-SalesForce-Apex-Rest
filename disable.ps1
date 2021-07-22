#######################################################
# HelloID-Conn-Prov-Target-SalesForce-Apex-Rest-Disable
#
# Version: 1.0.0.0
#######################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

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
        Write-Verbose "Disabling SalesForce account for '$($p.DisplayName)'"

        if ($($config.IsConnectionTls12)) {
            Write-Verbose 'Switching to TLS 1.2'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }

        Write-Verbose 'Retrieving accessToken'
        $accessToken = Get-SalesForceAccessToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret) -AdminUserName $($config.AdminUserName) -adminPassword $($config.AdminPassword) -SecurityToken $($config.SecurityToken)

        Write-Verbose 'Adding Authorization headers'
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Bearer $accessToken")

        $body = @{
            IsActive = 'false'
        } | ConvertTo-Json

        $splatParams = @{
            Uri      = "$($config.BaseUrl)/services/data/$($config.ApiVersion)/sobjects/User/$aRef"
            Headers  = $headers
            Body     = $body
            Method   = 'PATCH'
        }
        Invoke-RestMethod @splatParams
        $logMessage = "Account for '$($p.DisplayName)' successfully disabled"
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
            $auditMessage = "Account for '$($p.DisplayName)' not disabled. Error: $errorMessage"
        } else {
            $auditMessage = "Account for '$($p.DisplayName)' not disabled. Error: $($ex.Exception.Message)"
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
