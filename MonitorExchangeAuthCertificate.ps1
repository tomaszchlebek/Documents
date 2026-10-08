<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 26.03.06.1531

<#
.NOTES
	Name: MonitorExchangeAuthCertificate.ps1
	Requires: Exchange Management Shell and Organization Management permissions.
    Major Release History:
        01/10/2023  - Initial Public Release on CSS-Exchange

.SYNOPSIS
    Validates the Auth Certificate configuration of the Exchange organization where the script runs.
    It can be run in mode to automatically replace an invalid Auth Certificate or prepare a new next Auth Certificate
    to ensure a smooth Auth Certificate rollover.
.DESCRIPTION
    This script checks the status of the Auth Certificate which is set to the Auth Configuration of the Exchange organization.
    If the script is executed without any parameter, it will only perform tests if any Auth Certificate renewal action is required.
    The script can be executed in action mode which will then perform the appropriate Auth Certificate renewal actions (if required).
    The script can also be configured to run via Scheduled Task on a daily base. It will then perform the required renewal actions
    without admin interaction needed (except in Exchange Hybrid scenarios where a run of the Hybrid Configuration Wizard or HCW is required
    after a new Auth Certificate becomes active).
.PARAMETER ValidateAndRenewAuthCertificate
    You can use this parameter to let the script perform the required Auth Certificate renewal actions.
    If the script runs with this parameter set to $false, no action will be made to the current Auth Configuration.
.PARAMETER EnforceNewAuthCertificateCreation
    You can use this switch parameter to let the script stage a new next Auth Certificate which will become automatically active within 24 hours.
.PARAMETER CustomCertificateLifetimeInDays
    You can use this parameter to specify a custom lifetime for the newly created Auth certificate.
    By default, the self-signed certificate is created with a lifetime of 5 years.
.PARAMETER IgnoreUnreachableServers
    This optional parameter can be used to ignore if some of the Exchange servers within the organization cannot be reached.
    If this parameter is used, the script only validates the servers that can be reached and will perform Auth Certificate
    renewal actions based on the result.
.PARAMETER IgnoreHybridConfig
    This optional parameter allows you to explicitly perform Auth Certificate renewal actions (if required) even if an
    Exchange hybrid configuration was detected. You need to run the Hybrid Configuration Wizard (HCW) after the renewed
    Auth Certificate becomes the one in use.
.PARAMETER PrepareADForAutomationOnly
    This optional parameter can be used in AD Split Permission scenarios. It allows you to create the AD account which can then be
    used to run the Exchange Auth Certificate Monitoring script automatically via Scheduled Task.
.PARAMETER ADAccountDomain
    This optional parameter allows you to specify the domain which is then used by the script to generate the AD account used for automation.
.PARAMETER ConfigureScriptToRunViaScheduledTask
    This optional parameter can be used to automatically prepare the requirements in AD (user account), Exchange (email enable the account,
    hide the account from address book, create a new role group with limited permissions) and finally it creates the scheduled task on the computer
    on which the script was executed (it has to be an Exchange server running the mailbox role).
.PARAMETER AutomationAccountCredential
    This optional parameter can be used to provide a different user under whose context the script is then executed via scheduled task.
.PARAMETER SendEmailNotificationTo
    This optional parameter can be used to specify recipients which will then be notified in case that an Exchange Auth Certificate renewal action
    was performed.
.PARAMETER TrustAllCertificates
    This optional parameter can be used to trust all certificates when connecting to the EWS service to send out email notifications.
.PARAMETER TestEmailNotification
    This optional parameter can be used to test the email notification feature of the script.
.PARAMETER Password
    Parameter to provide a password to the script which is required in some scenarios.
    This parameter is required if you use one of the following parameters:
        - If you use the PrepareADForAutomationOnly parameter
        - If you use the ExportAuthCertificatesAsPfx parameter
    It is an optional parameter if you use the ConfigureScriptToRunViaScheduledTask parameter.
.PARAMETER ExportAuthCertificatesAsPfx
    This optional parameter can be used to export all on the system available Auth Certificates as password protected .pfx file.
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
	.\MonitorExchangeAuthCertificate.ps1
	Runs the script in validation mode and will show you the Auth Certificate renewal action which will be performed when executed in renew mode.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -Confirm:$false
    Runs the script in renewal mode without user interaction. The Auth Certificate renewal action will be performed (if required).
    In unattended mode the internal SMTP certificate will be replaced with the new Auth Certificate and is then set back to the previous one.
    The new Auth Certificate, which is eventually created, will have a lifetime of 5 years.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -CustomCertificateLifetimeInDays 365 -Confirm:$false
    Runs the script in renewal mode without user interaction. The Auth Certificate renewal action will be performed (if required).
    In unattended mode the internal SMTP certificate will be replaced with the new Auth Certificate and is then set back to the previous one.
    The new Auth Certificate, which is eventually created, will be created with a lifetime of 365 days (1 year).
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -EnforceNewAuthCertificateCreation -CustomCertificateLifetimeInDays 365 -Confirm:$false
    Runs the script in Auth Certificate enforcement mode. A new Auth Certificate is created and staged as new next Auth Certificate.
    The Exchange AuthAdmin servicelet will publish the newly created Auth Certificate as soon as it processes it the next time (usually in a 12 hour time frame).
    The new Auth Certificate, which is created, will be created with a lifetime of 365 days (1 year).
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -IgnoreUnreachableServers $true -Confirm:$false
    Runs the script in renewal mode without user interaction. We only take the Exchange server into account which are reachable and will perform
    the renewal action if required.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ValidateAndRenewAuthCertificate $true -IgnoreHybridConfig $true -Confirm:$false
    Runs the script in renewal mode without user interaction. The renewal action will be performed even if a Exchange hybrid configuration was detected.
    Please note that you have to run the Hybrid Configuration Wizard (HCW) after the active Auth Certificate was replaced.
.EXAMPLE
    .\MonitorExchangeAuthCertificate.ps1 -ConfigureScriptToRunViaScheduledTask -Password (Get-Credential).Password
    If you run the script using this parameter, the script will then create a new AD user which is then assigned to a newly created Exchange Role Group.
    The script will also create a scheduled task that runs on a hourly base. The '-ConfigureScriptToRunViaScheduledTask' parameter can be combined with the
    '-IgnoreHybridConfig $true' and '-IgnoreUnreachableServers $true' parameter.
#>

[CmdletBinding(DefaultParameterSetName = "MonitorExchangeAuthCertificateManually", SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [bool]$ValidateAndRenewAuthCertificate = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "EnforceNewNextAuthCertificateConfiguration")]
    [switch]$EnforceNewAuthCertificateCreation,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "EnforceNewNextAuthCertificateConfiguration")]
    [ValidateScript({ $_ -ge 0 })]
    [int]$CustomCertificateLifetimeInDays = 0,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "EnforceNewNextAuthCertificateConfiguration")]
    [bool]$IgnoreUnreachableServers = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "EnforceNewNextAuthCertificateConfiguration")]
    [bool]$IgnoreHybridConfig = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [switch]$PrepareADForAutomationOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [string]$ADAccountDomain = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [switch]$ConfigureScriptToRunViaScheduledTask,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [PSCredential]$AutomationAccountCredential,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $true, ParameterSetName = "TestEmailNotification")]
    [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
    [string[]]$SendEmailNotificationTo,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "TestEmailNotification")]
    [switch]$TrustAllCertificates,

    [Parameter(Mandatory = $false, ParameterSetName = "TestEmailNotification")]
    [switch]$TestEmailNotification,

    [Parameter(Mandatory = $true, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $true, ParameterSetName = "ExportExchangeAuthCertificatesAsPfx")]
    [SecureString]$Password,

    [Parameter(Mandatory = $false, ParameterSetName = "ExportExchangeAuthCertificatesAsPfx")]
    [switch]$ExportAuthCertificatesAsPfx,

    [Parameter(Mandatory = $false, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "MonitorExchangeAuthCertificateManually")]
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureAutomaticExecutionViaScheduledTask")]
    [Parameter(Mandatory = $false, ParameterSetName = "EnforceNewNextAuthCertificateConfiguration")]
    [Parameter(Mandatory = $false, ParameterSetName = "SetupAutomaticExecutionADRequirements")]
    [switch]$SkipVersionCheck
)

$BuildVersion = "26.03.06.1531"


function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    return $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}


function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$CurrentErrors,
        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}

# Confirm that either Remote Shell or EMS is loaded from an Edge Server, Exchange Server, or a Tools box.
# It does this by also initializing the session and running Get-EventLogLevel. (Server Management RBAC right)
# All script that require Confirm-ExchangeShell should be at least using Server Management RBAC right for the user running the script.
function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell"
        $currentErrors = $Error.Count
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $remoteShell = (-not(Test-Path $setupKey))
        $toolsServer = (Test-Path $setupKey) -and
        (-not(Test-Path $edgeTransportKey)) -and
        ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))
        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        function IsExchangeManagementSession {
            [OutputType("System.Boolean")]
            param(
                [ScriptBlock]$CatchActionFunction
            )

            $getEventLogLevelCallSuccessful = $false
            $isExchangeManagementShell = $false

            try {
                $currentErrors = $Error.Count
                $attempts = 0
                do {
                    $eventLogLevel = Get-EventLogLevel -ErrorAction Stop | Select-Object -First 1
                    $attempts++
                    if ($attempts -ge 5) {
                        throw "Failed to run Get-EventLogLevel too many times."
                    }
                } while ($null -eq $eventLogLevel)
                $getEventLogLevelCallSuccessful = $true
                foreach ($e in $eventLogLevel) {
                    Write-Verbose "Type is: $($e.GetType().Name) BaseType is: $($e.GetType().BaseType)"
                    if (($e.GetType().Name -eq "EventCategoryObject") -or
                        (($e.GetType().Name -eq "PSObject") -and
                        ($null -ne $e.SerializationData))) {
                        $isExchangeManagementShell = $true
                    }
                }
                Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
            } catch {
                Write-Verbose "Failed to run Get-EventLogLevel"
                Invoke-CatchActionError $CatchActionFunction
            }

            return [PSCustomObject]@{
                CallWasSuccessful = $getEventLogLevelCallSuccessful
                IsManagementShell = $isExchangeManagementShell
            }
        }
    }
    process {
        $isEMS = IsExchangeManagementSession $CatchActionFunction
        if ($isEMS.CallWasSuccessful) {
            Write-Verbose "Exchange PowerShell Module already loaded."
        } else {
            if (-not ($LoadExchangeShell)) { return }

            #Test 32 bit process, as we can't see the registry if that is the case.
            if (-not ([System.Environment]::Is64BitProcess)) {
                Write-Warning "Open a 64 bit PowerShell process to continue"
                return
            }

            if (Test-Path "$setupKey") {
                Write-Verbose "We are on Exchange 2013 or newer"

                try {
                    $currentErrors = $Error.Count
                    if (Test-Path $edgeTransportKey) {
                        Write-Verbose "We are on Exchange Edge Transport Server"
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exShell.psc1" -ErrorAction Stop

                        foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            Write-Verbose ("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }

                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    } else {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    }
                    Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

                    Write-Verbose "Imported Module. Trying Get-EventLogLevel Again"
                    $isEMS = IsExchangeManagementSession $CatchActionFunction
                    if (($isEMS.CallWasSuccessful) -and
                        ($isEMS.IsManagementShell)) {
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                    } else {
                        Write-Warning "Something went wrong while loading the Exchange Management Shell"
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } else {
                Write-Verbose "Not on an Exchange or Tools server"
            }
        }
    }
    end {

        $returnObject = [PSCustomObject]@{
            ShellLoaded = $isEMS.CallWasSuccessful
            Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
            Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
            Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
            Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
            EdgeServer  = $isEMS.CallWasSuccessful -and (Test-Path $setupKey) -and (Test-Path $edgeTransportKey)
            ToolsOnly   = $isEMS.CallWasSuccessful -and $toolsServer
            RemoteShell = $isEMS.CallWasSuccessful -and $remoteShell
            EMS         = $isEMS.IsManagementShell
        }

        return $returnObject
    }
}


function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")]
        [string]$Cmdlet
    )

    [string]$errorInformation = [System.Environment]::NewLine + [System.Environment]::NewLine +
    "----------------Error Information----------------" + [System.Environment]::NewLine

    if ($null -ne $CurrentError.OriginInfo) {
        $errorInformation += "Error Origin Info: $($CurrentError.OriginInfo.ToString())$([System.Environment]::NewLine)"
    }

    $errorInformation += "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())$([System.Environment]::NewLine)"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception.StackTrace)$([System.Environment]::NewLine)"
    } elseif ($null -ne $CurrentError.Exception) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        $errorInformation += "Position Message: $($CurrentError.InvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        $errorInformation += "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        $errorInformation += "Script Stack: $($CurrentError.ScriptStackTrace)$([System.Environment]::NewLine)"
    }

    $errorInformation += "-------------------------------------------------$([System.Environment]::NewLine)$([System.Environment]::NewLine)"

    & $Cmdlet $errorInformation
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Write-HostErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Host"
}

function Invoke-CatchActions {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $script:ErrorsExcluded += $CurrentError
    Write-Verbose "Error Excluded Count: $($Script:ErrorsExcluded.Count)"
    Write-Verbose "Error Count: $($Error.Count)"
    Write-VerboseErrorInformation $CurrentError
}

function Get-UnhandledErrors {
    [CmdletBinding()]
    param ()
    $index = 0
    return $Error |
        ForEach-Object {
            $currentError = $_
            $handledError = $Script:ErrorsExcluded |
                Where-Object { $_.Equals($currentError) }

                if ($null -eq $handledError) {
                    [PSCustomObject]@{
                        ErrorInformation = $currentError
                        Index            = $index
                    }
                }
                $index++
            }
}

function Get-HandledErrors {
    [CmdletBinding()]
    param ()
    $index = 0
    return $Error |
        ForEach-Object {
            $currentError = $_
            $handledError = $Script:ErrorsExcluded |
                Where-Object { $_.Equals($currentError) }

                if ($null -ne $handledError) {
                    [PSCustomObject]@{
                        ErrorInformation = $currentError
                        Index            = $index
                    }
                }
                $index++
            }
}

function Test-UnhandledErrorsOccurred {
    return $Error.Count -ne $Script:ErrorsExcluded.Count
}

function Invoke-ErrorCatchActionLoopFromIndex {
    [CmdletBinding()]
    param(
        [int]$StartIndex
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Start Index: $StartIndex Error Count: $($Error.Count)"

    if ($StartIndex -ne $Error.Count) {
        # Write the errors out in reverse in the order that they came in.
        $index = $Error.Count - $StartIndex - 1
        do {
            Invoke-CatchActions $Error[$index]
            $index--
        } while ($index -ge 0)
    }
}

function Invoke-ErrorMonitoring {
    # Always clear out the errors
    # setup variable to monitor errors that occurred
    $Error.Clear()
    $Script:ErrorsExcluded = @()
}

function Invoke-WriteDebugErrorsThatOccurred {

    function WriteErrorInformation {
        [CmdletBinding()]
        param(
            [object]$CurrentError
        )
        Write-VerboseErrorInformation $CurrentError
    }

    if ($Error.Count -gt 0) {
        Write-Verbose "`r`n`r`nErrors that occurred that wasn't handled"

        Get-UnhandledErrors | ForEach-Object {
            Write-Verbose "Error Index: $($_.Index)"
            WriteErrorInformation $_.ErrorInformation
        }

        Write-Verbose "`r`n`r`nErrors that were handled"
        Get-HandledErrors | ForEach-Object {
            Write-Verbose "Error Index: $($_.Index)"
            WriteErrorInformation $_.ErrorInformation
        }
    } else {
        Write-Verbose "No errors occurred in the script."
    }
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,

        [ValidateNotNullOrEmpty()]
        [string]$LogName = "Script_Logging",

        [bool]$AppendDateTime = $true,

        [bool]$AppendDateTimeToFileName = $true,

        [int]$MaxFileSizeMB = 10,

        [int]$CheckSizeIntervalMinutes = 10,

        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory. Inner Exception: $_"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}

function Invoke-LoggerInstanceCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance
    )
    process {
        if ($LoggerInstance.LoggerDisabled -or
            $LoggerInstance.PreventLogCleanup) {
            return
        }

        Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*" |
            Remove-Item -Force
    }
}


function Get-GlobalCatalogServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SiteName = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function returns a Global Catalog server for the Active Directory Site of the computer.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose ("Trying to query a Global Catalog for the current forest for site: $($SiteName)")
        return ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.FindGlobalCatalog($SiteName)).Name
    } catch {
        Write-Verbose ("Error while querying a Global Catalog for current forest - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return
    }
}


function Enable-TrustAnyCertificateCallback {
    param()

    <#
        This helper function can be used to ignore certificate errors. It works by setting the ServerCertificateValidationCallback
        to a callback that always returns true. This is useful when you are using self-signed certificates or certificates that are
        not trusted by the system.
    #>

    Add-Type -TypeDefinition @"
    namespace Microsoft.CSSExchange {
        public class CertificateValidator {
            public static bool TrustAnyCertificateCallback(
                object sender,
                System.Security.Cryptography.X509Certificates.X509Certificate cert,
                System.Security.Cryptography.X509Certificates.X509Chain chain,
                System.Net.Security.SslPolicyErrors sslPolicyErrors) {
                return true;
            }

            public static void IgnoreCertificateErrors() {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = TrustAnyCertificateCallback;
            }
        }
    }
"@
    [Microsoft.CSSExchange.CertificateValidator]::IgnoreCertificateErrors()
}

function Send-EwsMailMessage {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string]$From = $null,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$To,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$Cc = $null,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$Bcc = $null,

        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [switch]$BodyAsHtml,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Normal", "High")]
        [string]$Importance = "Normal",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$EwsManagedAPIAssemblyPath = "$($env:ExchangeInstallPath)bin\Microsoft.Exchange.WebServices.dll",

        [Parameter(Mandatory = $true)]
        [ValidatePattern("\/ews\/exchange.asmx$")]
        [string]$EwsServiceUrl,

        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCertificateMismatch,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        if (Test-Path $EwsManagedAPIAssemblyPath) {
            Write-Verbose ("EWS Managed API Assembly was found under: $($EwsManagedAPIAssemblyPath)")
            Add-Type -Path $EwsManagedAPIAssemblyPath
        } else {
            Write-Verbose ("EWS Managed API Assembly was not found under: $($EwsManagedAPIAssemblyPath)")
            Write-Verbose ("Please download it from: 'https://aka.ms/ews-managed-api-readme' and provide the correct path")
            return $false
        }
    } process {
        if ($IgnoreCertificateMismatch) {
            Write-Verbose ("IgnoreCertificateMismatch was used - policy will be set to: TrustAnyCertificate")
            Enable-TrustAnyCertificateCallback
        }

        try {
            $ewsService = New-Object "Microsoft.Exchange.WebServices.Data.ExchangeService" -ArgumentList Exchange2013_SP1
            $ewsService.Url = $EwsServiceUrl

            $ewsService.Credentials = New-Object "Microsoft.Exchange.WebServices.Data.WebCredentials"

            if ($null -ne $Credential) {
                Write-Verbose ("Credentials were provided - will try to use them")
                Write-Verbose ("Username: $($Credential.UserName)")
                $ewsService.UseDefaultCredentials = $false
                $ewsService.Credentials.Credentials.UserName = $Credential.UserName
                $ewsService.Credentials.Credentials.Password = $Credential.GetNetworkCredential().Password
            } else {
                Write-Verbose ("We will try to send the email from user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
                $ewsService.UseDefaultCredentials = $true
            }

            $newMessage = New-Object "Microsoft.Exchange.WebServices.Data.EmailMessage" -ArgumentList $ewsService
            $newMessage.Subject = $Subject
            $newMessage.Importance = $Importance
            $newMessage.Body = $Body

            if (-not($BodyAsHtml)) {
                Write-Verbose ("Message will be send in plain text")
                $newMessage.Body.BodyType = "Text"
            }

            if ($null -ne $From) {
                Write-Verbose ("We will try to send the message by using the following 'From' address: $($From)")
                $newMessage.From = $From
            }

            foreach ($toRecipient in $To) {
                Write-Verbose ("Recipient: $($toRecipient) will be added to 'To' line")
                [void]$newMessage.ToRecipients.Add($toRecipient)
            }

            if ($null -ne $Cc) {
                foreach ($ccRecipient in $Cc) {
                    Write-Verbose ("Recipient: $($ccRecipient) will be added to 'Cc' line")
                    [void]$newMessage.CcRecipients.Add($ccRecipient)
                }
            }

            if ($null -ne $Bcc) {
                foreach ($bccRecipient in $Bcc) {
                    Write-Verbose ("Recipient: $($bccRecipient) will be added to 'Bcc' line")
                    [void]$newMessage.BccRecipients.Add($bccRecipient)
                }
            }
        } catch {
            Write-Verbose ("Something went wrong while preparing to send an email with the subject '$($newMessage.Subject)'")
            Invoke-CatchActionError $CatchActionFunction
            return $false
        }
    } end {
        try {
            $newMessage.SendAndSaveCopy()
        } catch {
            Write-Verbose ("Something went wrong while trying to send an email with the subject '$($newMessage.Subject)'")
            Invoke-CatchActionError $CatchActionFunction
            return $false
        }

        Write-Verbose ("An email with the subject '$($newMessage.Subject)' was sent and saved in the SendItems folder")
        return $true
    }
}

<#
.DESCRIPTION
    An override for Write-Host to allow logging to occur and color format changes to match with what the user as default set for Warning and Error.
#>
function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function SetProperForegroundColor {
    $Script:OriginalConsoleForegroundColor = $host.UI.RawUI.ForegroundColor

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.WarningForegroundColor) {
        Write-Verbose "Foreground Color matches warning's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.ErrorForegroundColor) {
        Write-Verbose "Foreground Color matches error's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }
}

function RevertProperForegroundColor {
    $Host.UI.RawUI.ForegroundColor = $Script:OriginalConsoleForegroundColor
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function SetWriteHostManipulateObjectAction ($ManipulateObject) {
    $Script:WriteHostManipulateObjectAction = $ManipulateObject
}

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {

        if ($null -ne $Script:WriteVerboseManipulateMessageAction) {
            $Message = & $Script:WriteVerboseManipulateMessageAction $Message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteVerboseRemoteManipulateMessageAction) {
            $Message = & $Script:WriteVerboseRemoteManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Verbose $Message

        if ($null -ne $Script:WriteVerboseDebugAction) {
            & $Script:WriteVerboseDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteVerboseDebugAction) {
            & $Script:WriteRemoteVerboseDebugAction $Message
        }
    }
}

function SetWriteVerboseAction ($DebugAction) {
    $Script:WriteVerboseDebugAction = $DebugAction
}

function SetWriteRemoteVerboseAction ($DebugAction) {
    $Script:WriteRemoteVerboseDebugAction = $DebugAction
}

function SetWriteVerboseManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseManipulateMessageAction = $DebugAction
}

function SetWriteVerboseRemoteManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseRemoteManipulateMessageAction = $DebugAction
}




function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server configuration detected"
            Write-Verbose $proxyObject.OriginalString
            return $true
        } else {
            Write-Verbose "No proxy server configuration detected"
            return $false
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
        return $false
    }
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        Write-VerboseErrorInformation
    }
}

<#
    Determines if the script has an update available.
#>
function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $BuildVersion = "26.03.06.1531"

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $BuildVersion
        LatestVersion  = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection -Uri $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $result.LatestVersion = $latestVersion
            if ($null -ne $latestVersion) {
                $result.UpdateFound = ($latestVersion -ne $BuildVersion)
            } else {
                Write-Warning ("Unable to check for a script update as no script with the same name was found." +
                    "`r`nThis can happen if the script has been renamed. Please check manually if there is a newer version of the script.")
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}


function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    $MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        if (-not $chain.Build($sig.SignerCertificate)) {
            Write-Warning "Signer certificate doesn't chain correctly."
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            Write-Warning "Certificate Chain shorter than expected."
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
            Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
            throw
        }

        Write-Host "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

<#
.SYNOPSIS
    Overwrites the current running script file with the latest version from the repository.
.NOTES
    This function always overwrites the current file with the latest file, which might be
    the same. Get-ScriptUpdateAvailable should be called first to determine if an update is
    needed.

    In many situations, updates are expected to fail, because the server running the script
    does not have internet access. This function writes out failures as warnings, because we
    expect that Get-ScriptUpdateAvailable was already called and it successfully reached out
    to the internet.
#>
function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }

        try {
            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Pass -Confirm:$false
    to update without prompting the user. Pass -Verbose for additional
    diagnostic output.

    Returns $true if an update was downloaded, $false otherwise. The
    result will always be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Need to pass through ShouldProcess settings to Invoke-ScriptUpdate')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $AutoUpdate,
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
    if ($updateInfo.UpdateFound) {
        if ($AutoUpdate) {
            return Invoke-ScriptUpdate
        } else {
            Write-Warning "$($updateInfo.ScriptName) $BuildVersion is outdated. Please download the latest, version $($updateInfo.LatestVersion)."
        }
    }

    return $false
}




function Add-ADUserToLocalGroup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [string]$MemberUPN,
        [string]$Group,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function adds an Active Directory user to a local group.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Add-Type -AssemblyName "System.DirectoryServices.AccountManagement" -ErrorAction Stop

        $localContext = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $domainContext = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $localMachine = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext($localContext)
        $localGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($localMachine, $Group)

        if (-not($localGroup.Members.Contains($domainContext, [System.DirectoryServices.AccountManagement.IdentityType]::UserPrincipalName, $MemberUPN))) {
            if ($PSCmdlet.ShouldProcess($Group, "Add user $($MemberUPN) to local group")) {
                $localGroup.Members.Add($domainContext, [System.DirectoryServices.AccountManagement.IdentityType]::UserPrincipalName, $MemberUPN)
                $localGroup.Save()
            }
        } else {
            Write-Verbose ("User: $($MemberUPN) is already a member of group: $($Group)")
        }
    } catch [System.DirectoryServices.AccountManagement.PrincipalOperationException] {
        throw ("There are users in the local administrators group which cannot be resolved - please remove them and run the script again")
        Invoke-CatchActionError $CatchActionFunction
        return
    } catch {
        Write-Verbose ("Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return
    } finally {
        if ($null -ne $localGroup) {
            $localGroup.Dispose()
        }
    }

    return $true
}


function New-AuthCertificateManagementAccount {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [SecureString]$Password,
        [string]$DomainToUse = $env:USERDNSDOMAIN,
        [string]$DomainController = $env:USERDNSDOMAIN,
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $systemMailboxGuid = "b963af59-3975-4f92-9d58-ad0b1fe3a1a3"
    $samAccountName = "SM_ad0b1fe3a1a3"
    $userPrincipalName = "SystemMailbox{$($systemMailboxGuid)}@$($DomainToUse)"

    Write-Verbose ("Domain passed to the function is: $($DomainToUse)")
    Write-Verbose ("Domain or Domain Controller to be used with 'New-ADUser' call is: $($DomainController)")
    try {
        $adAccount = Get-ADUser -Identity $samAccountName -Server $DomainController -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose ("AD user account wasn't found using Domain Controller: $($DomainController)")
        Invoke-CatchActionError $CatchActionFunction
    } catch {
        Write-Verbose ("We hit an unhandled exception and cannot continue - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return $false
    }

    if ($null -eq $adAccount) {
        try {
            $newADUserParams = @{
                Name                 = "SystemMailbox{$($systemMailboxGuid)}"
                DisplayName          = "Microsoft Exchange Auth Certificate Manager"
                SamAccountName       = $samAccountName
                UserPrincipalName    = $userPrincipalName
                AccountPassword      = $Password
                Enabled              = $true
                PasswordNeverExpires = $true
                Server               = $DomainController
                ErrorAction          = "Stop"
            }

            if ($PSCmdlet.ShouldProcess($samAccountName, "New-ADUser")) {
                New-ADUser @newADUserParams | Out-Null
            }
            Write-Verbose ("User: 'Microsoft Exchange Auth Certificate Manager' was successfully created")
            return $true
        } catch [System.UnauthorizedAccessException] {
            Write-Verbose ("You don't have the permissions to create a new AD user account")
            Invoke-CatchActionError $CatchActionFunction
        } catch {
            Write-Verbose ("Something went wrong while creating the 'Microsoft Exchange Auth Certificate Manager' account - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    } else {
        Write-Verbose ("The AD account: $($userPrincipalName) already exists")
        Write-Verbose ("Trying to reset the password for the account")
        try {
            if ($PSCmdlet.ShouldProcess($adAccount, "Set-ADAccountPassword")) {
                Set-ADAccountPassword -Identity $adAccount -NewPassword $Password -Reset -Server $DomainController -Confirm:$false -ErrorAction Stop
            }
            if ($PSCmdlet.ShouldProcess($adAccount, "Set-ADUser")) {
                Set-ADUser -Identity $adAccount -ChangePasswordAtLogon $false -Server $DomainController -Confirm:$false -ErrorAction Stop
            }
            return $true
        } catch [System.UnauthorizedAccessException] {
            Write-Verbose ("You don't have the permissions to reset the password of an AD account")
            Invoke-CatchActionError $CatchActionFunction
        } catch {
            Write-Verbose ("Unable to reset the password for the already existing AD user account - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    return $false
}

function Build-ExchangeAuthCertificateManagementAccount {
    [CmdletBinding(DefaultParameterSetName = "CreateNewAccount", SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [bool]$UseExistingAccount = $false,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [PSCredential]$AccountCredentialObject,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [SecureString]$PasswordToSet,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [string]$DomainController,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $systemMailboxIdentity = "SM_ad0b1fe3a1a3"
        $domainToUse = (Get-Mailbox -Arbitration -ErrorAction SilentlyContinue | Where-Object {
                ($null -ne $_.UserPrincipalName)
            } | Select-Object -First 1).UserPrincipalName.Split("@")[-1]

        if (($UseExistingAccount) -and
            ($null -ne $AccountCredentialObject)) {
            Write-Verbose ("Account information passed - we will use account: $($AccountCredentialObject.UserName)")

            if ($AccountCredentialObject.UserName.IndexOf("\") -ne -1) {
                Write-Verbose ("Username passed in <Domain>\<SamAccountName> format")
                $systemMailboxIdentity = ($AccountCredentialObject.UserName).Split("\")[-1]
            } else {
                Write-Verbose ("Username passed in UPN or plain format")
                $systemMailboxIdentity = $AccountCredentialObject.UserName
            }

            $PasswordToSet = $AccountCredentialObject.Password
        }

        function NewAuthCertificateManagementRole {
            [CmdletBinding()]
            [OutputType([bool])]
            param(
                [string]$DomainController
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                Write-Verbose ("Trying to create 'Auth Certificate Management' role group by using Domain Controller: $($DomainController)")
                if ($PSCmdlet.ShouldProcess("View-Only Configuration, View-Only Recipients, Exchange Server Certificates, Organization Client Access", "New-RoleGroup")) {
                    $roleGroupParams = @{
                        Name             = "Auth Certificate Management"
                        Roles            = "View-Only Configuration", "View-Only Recipients" , "Exchange Server Certificates", "Organization Client Access"
                        Description      = "Members of this management group can create and manage Auth Certificates"
                        DomainController = $DomainController
                        ErrorAction      = "Stop"
                        WhatIf           = $WhatIfPreference
                    }
                    New-RoleGroup @roleGroupParams | Out-Null

                    Write-Verbose ("Validate that the role group was created successful")
                    $roleGroup = Get-RoleGroup -Identity "Auth Certificate Management" -DomainController $DomainController -ErrorAction SilentlyContinue

                    if ($null -ne $roleGroup) {
                        Write-Verbose ("Role group 'Auth Certificate Management' found by using Domain Controller: $($DomainController)")
                        return $true
                    } else {
                        throw ("Role group 'Auth Certificate Management' not found by using Domain Controller: $($DomainController)")
                    }
                } else {
                    return $true
                }
            } catch {
                Write-Verbose ("Unable to create 'Auth Certificate Management' role group - Exception: $($Error[0].Exception.Message)")
                Invoke-CatchActionError $CatchActionFunction
            }

            return $false
        }
    }
    process {
        if ($null -eq $domainToUse) {
            Write-Verbose ("Unable to figure out the domain used by the arbitration mailbox - we can't continue without this information")
            return
        }

        $authCertificateRoleGroup = Get-RoleGroup -Identity "Auth Certificate Management" -ErrorAction SilentlyContinue

        if ($null -eq $authCertificateRoleGroup) {
            Write-Verbose ("Role group for Auth Certificate management doesn't exist. Group 'Auth Certificate Management' will be created now")
            $newRoleGroupStatus = NewAuthCertificateManagementRole -DomainController $DomainController
        }

        if (($null -ne $authCertificateRoleGroup) -or
            ($newRoleGroupStatus)) {
            Write-Verbose ("Role group exists or was created successfully - searching for Auth Certificate management account")
            if ($UseExistingAccount -eq $false) {
                Write-Verbose ("System mailbox doesn't exist and will be created now")
                $newAuthCertificateManagementAccountParams = @{
                    Password         = $PasswordToSet
                    DomainToUse      = $domainToUse
                    DomainController = $DomainController
                    WhatIf           = $WhatIfPreference
                }

                if ($null -ne $CatchActionFunction) {
                    $newAuthCertificateManagementAccountParams.Add("CatchActionFunction", ${Function:Invoke-CatchActions})
                }

                $adUserExistsOrCreated = New-AuthCertificateManagementAccount @newAuthCertificateManagementAccountParams
                Write-Verbose ("Waiting 10 seconds for replication - please be patient")
                Start-Sleep -Seconds 10
            } else {
                Write-Verbose ("Trying to find the user which was passed to the function")
                $adUserExistsOrCreated = ((Get-User -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue).Count -eq 1)
                Write-Verbose ("Does the account exists? $($adUserExistsOrCreated)")
            }
        } else {
            Write-Verbose ("Something went wrong while preparing the Auth Certificate management role group")
            return
        }

        if ($adUserExistsOrCreated) {
            Write-Verbose ("Auth Certificate management AD account is now ready to use - going to email enable it now")
            $systemMailboxRecipientInfo = Get-Recipient -Identity $systemMailboxIdentity -ErrorAction SilentlyContinue

            if ($null -eq $systemMailboxRecipientInfo) {
                Write-Verbose ("Recipient has not yet been email enabled")
                try {
                    if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Enable-Mailbox")) {
                        Enable-Mailbox -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction Stop | Out-Null
                        Write-Verbose ("Wait another 5 seconds and give Exchange time to process")
                        Start-Sleep -Seconds 5
                    }
                } catch {
                    Write-Verbose ("Something went wrong while email activating the Auth Certificate management account")
                    Invoke-CatchActionError $CatchActionFunction
                    return
                }
            }
        } else {
            Write-Verbose ("Something went wrong while preparing the Auth Certificate management account")
            return
        }

        $systemMailboxMailboxInfo = Get-Mailbox -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue

        if (($WhatIfPreference) -and
            ($null -eq $systemMailboxMailboxInfo)) {
            $systemMailboxMailboxInfo = @{
                HiddenFromAddressListsEnabled = $false
            }
        }

        if ($null -ne $systemMailboxMailboxInfo) {
            Write-Verbose ("Auth Certificate management mailbox found")
            if ($systemMailboxMailboxInfo.HiddenFromAddressListsEnabled -eq $false) {
                Write-Verbose ("Auth Certificate management mailbox is not hidden from AddressList - going to hide the mailbox now")
                try {
                    if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Set-Mailbox")) {
                        Set-Mailbox -Identity $systemMailboxIdentity -HiddenFromAddressListsEnabled $true -ErrorAction Stop | Out-Null
                    }
                } catch {
                    Write-Verbose ("Unable to hide Auth Certificate management account from AddressList")
                    Invoke-CatchActionError $CatchActionFunction
                    return
                }
            }
        } else {
            Write-Verbose ("Unable to email enable the Auth Certificate management account")
            return
        }

        $roleGroupMembership = Get-RoleGroupMember "Auth Certificate Management" -ErrorAction SilentlyContinue
        $systemMailboxUserInfo = Get-User -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue

        if (($WhatIfPreference) -and
            ($null -eq $systemMailboxUserInfo)) {
            $systemMailboxUserInfo = @{
                SamAccountName    = $systemMailboxIdentity
                UserPrincipalName = $systemMailboxIdentity
            }
        }

        if (($null -eq $roleGroupMembership) -or
            (-not($roleGroupMembership.DistinguishedName.ToLower().Contains($systemMailboxUserInfo.DistinguishedName.ToLower())))) {
            Write-Verbose ("Add Auth Certificate management account to 'Auth Certificate Management' role group")
            try {
                if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Add-RoleGroupMember")) {
                    Add-RoleGroupMember "Auth Certificate Management" -Member $systemMailboxIdentity -ErrorAction Stop | Out-Null
                    Write-Verbose ("Auth Certificate management account added to 'Auth Certificate Management' role group")
                }
            } catch {
                Write-Verbose ("Unable to add Auth Certificate management account to role group")
                Invoke-CatchActionError $CatchActionFunction
                return
            }
        } else {
            Write-Verbose ("Account: $($systemMailboxIdentity) is already a member of the 'Auth Certificate Management' role group")
        }

        if ($null -ne $systemMailboxUserInfo) {
            Write-Verbose ("Account: $($systemMailboxIdentity) must be added to the local administrators group")
            if (Add-ADUserToLocalGroup -MemberUPN $systemMailboxUserInfo.UserPrincipalName -Group "S-1-5-32-544" -WhatIf:$WhatIfPreference) {
                Write-Verbose ("Account successfully added to local administrators group")
            } else {
                Write-Verbose ("Error while adding the user to the local administrators group - Exception: $($Error[0].Exception.Message)")
                return
            }
        } else {
            Write-Verbose ("Something went wrong as we can no longer find the Auth Certificate management account")
            return
        }
    }
    end {
        return [PSCustomObject]@{
            UserPrincipalName = $systemMailboxUserInfo.UserPrincipalName
            SamAccountName    = $systemMailboxUserInfo.SamAccountName
            Password          = $PasswordToSet
        }
    }
}


function Copy-ScriptToExchangeDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$FullPathToScript = $MyInvocation.ScriptName,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $exchangeInstallPath = $env:ExchangeInstallPath
    $scriptName = $FullPathToScript.Split("\")[-1]

    if ($null -ne $exchangeInstallPath) {
        Write-Verbose ("ExchangeInstallPath is: $($exchangeInstallPath)")
        $localScriptsPath = [System.IO.Path]::Combine($exchangeInstallPath, "Scripts")

        try {
            if (-not(Test-Path -Path $localScriptsPath)) {
                Write-Verbose ("Folder: $($localScriptsPath) doesn't exist - it will be created now")

                if ($PSCmdlet.ShouldProcess("$exchangeInstallPath\Scripts", "New-Item")) {
                    New-Item -Path $exchangeInstallPath -ItemType Directory -Name "Scripts" -ErrorAction Stop | Out-Null
                }
            }

            if (($WhatIfPreference) -or
                (Test-Path -Path $localScriptsPath -ErrorAction Stop)) {
                Write-Verbose ("Path: $($localScriptsPath) was successfully created")
                if ($PSCmdlet.ShouldProcess("Copy: $FullPathToScript To: $localScriptsPath", "Copy-Item")) {
                    Copy-Item -Path $FullPathToScript -Destination $localScriptsPath -Force -ErrorAction Stop
                }

                if (($WhatIfPreference) -or
                    (Test-Path -Path $FullPathToScript)) {
                    Write-Verbose ("Script: $($scriptName) successfully copied over to: $($localScriptsPath)")
                    return [PSCustomObject]@{
                        WorkingDirectory = $localScriptsPath
                        ScriptName       = $scriptName
                    }
                }
            }
        } catch {
            Write-Verbose ("Something went wrong - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    return
}



<#
.DESCRIPTION
    The Export-CertificateAndPrivateKey function uses .NET cryptography classes to securely export
    a certificate and its private key from either the LocalMachine or CurrentUser certificate store.
    If the specified computer name refers to the local host, the operation runs locally; otherwise,
    it uses PowerShell Remoting (Invoke-Command) to perform the export on the remote system.

    The exported certificate is returned as a byte array (PFX format) in memory only
    no files are written to disk. The private key must be marked as exportable, and
    the caller must have appropriate permissions to access it.
#>
function Export-CertificateAndPrivateKey {
    [CmdletBinding()]
    [OutputType([System.Byte[]])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [SecureString]$Password,

        [ValidateSet("CurrentUser", "LocalMachine")]
        [string]$Store = "LocalMachine",

        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $certificateOperationScriptBlock = {
        param(
            [string]$InThumbprint,
            [SecureString]$InPassword,
            [string]$InStore
        )

        $certificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", $($InStore))
        $certificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        $certificate = $certificateStore.Certificates | Where-Object { $_.Thumbprint -eq $InThumbprint }

        if (-not $certificate) {
            throw "Certificate with thumbprint $InThumbprint not found in $InStore\My"
        }

        if (-not $certificate.HasPrivateKey) {
            throw "Certificate with thumbprint $InThumbprint doesn't have a private key"
        }

        try {
            $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $InPassword)
        } catch {
            throw "The private key couldn't be exported. It either couldn't be accessed or isn't exportable: $_"
        } finally {
            $certificateStore.Close()
        }
    }

    $arguments = @($Thumbprint, $Password, $Store)

    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or
            $ComputerName -eq "localhost") {
            Write-Verbose "Exporting from the local computer"
            $pfxByteArray = & $certificateOperationScriptBlock @arguments
        } else {
            Write-Verbose "Exporting from a remote computer: $ComputerName"
            $pfxByteArray = Invoke-Command -ComputerName $ComputerName -ScriptBlock $certificateOperationScriptBlock -ArgumentList $arguments -ErrorAction Stop
        }
    } catch {
        Write-Verbose "Hit an issue while executing the script block: $_"
        Invoke-CatchActionError $CatchActionFunction
    }

    if ($pfxByteArray) {
        Write-Verbose "Certificate was successfully exported as bytes array"
        return $pfxByteArray
    }

    Write-Verbose "No certificate was exported"
    return $null
}

<#
.DESCRIPTION
    This function exports the current Auth Certificate and (if configured) the next Auth Certificate.
    The certificates will be stored as password protected .pfx file.
#>
function Export-ExchangeAuthCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [ScriptBlock]$CatchActionFunction
    )

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $certificatesReadyToExportList = New-Object System.Collections.Generic.List[object]
        $certificatesUnableToExportList = New-Object System.Collections.Generic.List[string]
        $currentAuthConfig = Get-AuthConfig -ErrorAction Stop
        $allExchangeCertificates = Get-ExchangeCertificate -Server $env:COMPUTERNAME -ErrorAction SilentlyContinue

        if ($null -ne $currentAuthConfig) {
            $currentAuthCertThumbprint = $currentAuthConfig.CurrentCertificateThumbprint
            $nextAuthCertThumbprint = $currentAuthConfig.NextCertificateThumbprint

            if (-not([System.String]::IsNullOrEmpty($currentAuthCertThumbprint))) {
                Write-Verbose ("CurrentCertificateThumbprint is: $($currentAuthCertThumbprint) - trying to find it on the local computer")
                $currentAuthCertificate = $allExchangeCertificates | Where-Object {
                    ($_.Thumbprint -eq $currentAuthCertThumbprint)
                }

                if (($null -eq $currentAuthCertificate) -or
                    ($currentAuthCertificate.HasPrivateKey -eq $false) -or
                    ($currentAuthCertificate.PrivateKeyExportable -eq $false)) {
                    Write-Verbose ("Current Auth Certificate doesn't fullfil the requirements to be exportable on this machine")
                    $certificatesUnableToExportList.Add($currentAuthCertThumbprint)
                } else {
                    Write-Verbose ("Current Auth Certificate was detected on the local machine and is ready to be exported")
                    $certificatesReadyToExportList.Add($currentAuthCertificate)
                }
            }

            if (-not([System.String]::IsNullOrEmpty($nextAuthCertThumbprint))) {
                Write-Verbose ("NextCertificateThumbprint is: $($nextAuthCertThumbprint) - trying to find it on the local computer")
                $nextAuthCertificate = $allExchangeCertificates | Where-Object {
                    ($_.Thumbprint -eq $nextAuthCertThumbprint)
                }

                if (($null -eq $nextAuthCertificate) -or
                    ($nextAuthCertificate.HasPrivateKey -eq $false) -or
                    ($nextAuthCertificate.PrivateKeyExportable -eq $false)) {
                    Write-Verbose ("Next Auth Certificate doesn't fullfil the requirements to be exportable on this machine")
                    $certificatesUnableToExportList.Add($nextAuthCertThumbprint)
                } else {
                    Write-Verbose ("Next Auth Certificate was detected on the local machine and is ready to be exported")
                    $certificatesReadyToExportList.Add($nextAuthCertificate)
                }
            }

            Write-Verbose ("There are: $($certificatesReadyToExportList.Count) certificates on the list that will be exported now")
            $dateTimeAppendix = (Get-Date -Format "yyyyMMddhhmmss")
            foreach ($cert in $certificatesReadyToExportList) {
                Write-Verbose ("Exporting the certificate with thumbprint: $($cert.Thumbprint) now...")
                try {
                    if ($PSCmdlet.ShouldProcess($cert.Thumbprint, "Export-CertificateAndPrivateKey")) {
                        $exportExchangeCertificateParams = @{
                            Thumbprint          = $cert.Thumbprint
                            Password            = $Password
                            CatchActionFunction = $CatchActionFunction
                        }
                        $authCert = Export-CertificateAndPrivateKey @exportExchangeCertificateParams

                        if (-not $authCert) {
                            Write-Verbose "Export of the Auth Certificate was not possible"
                            return
                        }
                    }
                    $certExportPath = "$($PSScriptRoot)\$($cert.Thumbprint)-$($dateTimeAppendix).pfx"
                    if ($PSCmdlet.ShouldProcess("Export certificate: $($cert.Thumbprint) To: $certExportPath", "[System.IO.File]::WriteAllBytes")) {
                        [System.IO.File]::WriteAllBytes($certExportPath, $authCert)
                    }
                    Write-Verbose ("Certificate exported to: $certExportPath")
                } catch {
                    Write-Verbose ("We hit an issue during certificate export - Exception $($Error[0].Exception.Message)")
                    $certificatesUnableToExportList.Add($cert.Thumbprint)
                    Invoke-CatchActionError $CatchActionFunction
                }
            }
        } else {
            Write-Verbose ("No valid Auth Config returned")
            return
        }
    } catch {
        Write-Verbose ("Unable to query the Exchange Auth Config - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return [PSCustomObject]@{
        CertificatesAvailableToExport      = ($certificatesReadyToExportList.Count -gt 0)
        ExportSuccessful                   = (($certificatesReadyToExportList.Count -gt 0) -and ($certificatesUnableToExportList.Count -eq 0))
        NumberOfCertificatesToExport       = $certificatesReadyToExportList.Count
        NumberOfCertificatesUnableToExport = $certificatesUnableToExportList.Count
        UnableToExportCertificatesList     = $certificatesUnableToExportList
    }
}


<#
.DESCRIPTION
    This function can be used to export an Exchange Certificate as byte array and import it to a list of servers
    which were passed to this function via ServersToImportList parameter.
    The function returns a PSCustomObject with the following properties:
        - ExportSuccessful : Indicator if the certificate was successfully exported on the source server (where the script runs)
        - ImportToAllServersSuccessful : Indicator if the certificate was successfully imported to all servers
        - Thumbprint : Thumbprint of the certificate that was imported
        - ImportedToServersList : List of all servers on which the certificate was successfully imported
        - ImportToServersFailedList : List of all serves on which the certificate import failed for whatever reason
#>
function Import-ExchangeAuthCertificateToServers {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ExportFromServer = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$ServersToImportList,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exportSuccessful = $false
        $importFailedList = New-Object System.Collections.Generic.List[string]
        $importSuccessfulList = New-Object System.Collections.Generic.List[string]
    }
    process {
        try {
            # Generate a temporary password to protect the exported private key in memory and on transport
            $bytes = [System.Byte[]]::new(64)
            ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
            $secureString = [System.Security.SecureString]::new()
            foreach ($b in $bytes) {
                $secureString.AppendChar([char]$b)
            }
            $secureString.MakeReadOnly()
            $bytes = $null

            if ($PSCmdlet.ShouldProcess($Thumbprint, "Export-CertificateAndPrivateKey")) {
                # Export the certificate as byte array as we need to pass this to the Import-ExchangeCertificate cmdlet
                $exportExchangeCertificateParams = @{
                    ComputerName        = $ExportFromServer
                    Thumbprint          = $Thumbprint
                    Password            = $secureString
                    CatchActionFunction = $CatchActionFunction
                }
                $exportedAuthCertificate = Export-CertificateAndPrivateKey @exportExchangeCertificateParams
            }

            if ($exportedAuthCertificate -or
                $WhatIfPreference) {
                Write-Verbose ("Certificate with thumbprint: $Thumbprint successfully exported")
                $exportSuccessful = $true

                # Next step is to import the certificate to all Exchange servers passed via $ServersToImportList parameter
                foreach ($server in $ServersToImportList) {
                    try {
                        if ($PSCmdlet.ShouldProcess($server, "Import-ExchangeCertificate")) {
                            $importExchangeCertificateParams = @{
                                Server               = $server
                                FileData             = $exportedAuthCertificate
                                Password             = $secureString
                                PrivateKeyExportable = $true
                                ErrorAction          = "Stop"
                            }
                            Import-ExchangeCertificate @importExchangeCertificateParams
                        }
                        Write-Verbose ("Certificate import to server: $server was successful")
                        $importSuccessfulList.Add($server)
                    } catch {
                        Write-Verbose ("Unable to import the certificate to server: $server - Exception: $($Error[0].Exception.Message)")
                        $importFailedList.Add($server)
                        Invoke-CatchActionError $CatchActionFunction
                    }
                }
            } else {
                Write-Verbose ("Unable to export the certificate with thumbprint: $Thumbprint")
            }
        } catch {
            Write-Verbose ("Something went wrong - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        $exportedAuthCertificate = $null
        $secureString.Dispose()
        return [PSCustomObject]@{
            ExportSuccessful             = $exportSuccessful
            ImportToAllServersSuccessful = (($importFailedList.Count -eq 0) -and ($exportSuccessful))
            Thumbprint                   = $Thumbprint
            ImportedToServersList        = $importSuccessfulList
            ImportToServersFailedList    = $importFailedList
        }
    }
}

function New-AuthCertificateMonitoringLogFolder {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.String])]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInstallPath = $env:ExchangeInstallPath
    if ($null -eq $exchangeInstallPath) {
        Write-Verbose ("ExchangeInstallPath environment variable doesn't exist - fallback to use temp folder to store logs")
        $exchangeInstallPath = $env:TEMP
    }

    if ($null -ne $exchangeInstallPath) {
        $logFilePath = [System.IO.Path]::Combine($exchangeInstallPath, "Logging")
        $finalLogPath = [System.IO.Path]::Combine($logFilePath, "AuthCertificateMonitoring")

        if ((Test-Path -Path $finalLogPath) -eq $false) {
            if ($PSCmdlet.ShouldProcess("$logFilePath\AuthCertificateMonitoring", "New-Item")) {
                New-Item -Path $logFilePath -ItemType Directory -Name "AuthCertificateMonitoring" -ErrorAction SilentlyContinue | Out-Null
            }
        }
        return $finalLogPath
    }

    return
}



<#
.DESCRIPTION
    This helper function must be used if Serialization Data Signing is enabled, but the Auth Certificate
    which is configured has expired or isn't available on the system where the script runs.
    The 'Get-ExchangeCertificate' cmdlet fails to deserialize and so, only RawData (byte[]) will be returned.
    To workaround, we initialize the X509Certificate2 class and import the data by using the Import() method.
#>
function Import-ExchangeCertificateFromRawData {
    [CmdletBinding()]
    param(
        [System.Object[]]$ExchangeCertificates
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeCertificatesList = New-Object 'System.Collections.Generic.List[object]'
    } process {
        if ($ExchangeCertificates.Count -ne 0) {
            Write-Verbose ("Going to process '$($ExchangeCertificates.Count )' Exchange certificates")

            foreach ($c in $ExchangeCertificates) {
                if ($null -eq $c.RawData) {
                    Write-Verbose "Skipping certificate because RawData is null"
                    continue
                }

                # Initialize X509Certificate2 class
                $certObject = New-Object 'System.Security.Cryptography.X509Certificates.X509Certificate2'
                # Use the Import() method to import byte[] RawData
                $certObject.Import($c.RawData)

                if ($null -ne $certObject.Thumbprint) {
                    Write-Verbose ("Certificate with thumbprint: $($certObject.Thumbprint) imported successfully")
                    $exchangeCertificatesList.Add($certObject)
                }
            }
        }
    } end {
        return $exchangeCertificatesList
    }
}

function Get-ExchangeServerCertificate {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [string]$Server = $env:COMPUTERNAME,
        [string]$Thumbprint = $null
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $allExchangeCertificates = New-Object 'System.Collections.Generic.List[object]'
    } process {
        $getExchangeCertificateParams = @{
            Server      = $Server
            ErrorAction = "Stop"
        }

        if (-not([System.String]::IsNullOrEmpty($Thumbprint))) {
            $getExchangeCertificateParams.Add("Thumbprint", $Thumbprint)
        }

        $exchangeCertificates = Get-ExchangeCertificate @getExchangeCertificateParams

        if ($null -ne $exchangeCertificates) {
            if ($null -ne $exchangeCertificates[0].Thumbprint) {
                Write-Verbose ("Deserialization of the Exchange certificates was successful")
                foreach ($c in $exchangeCertificates) {
                    $allExchangeCertificates.Add($c)
                }
            } else {
                Write-Verbose ("Deserialization of the Exchange certificates failed - trying to import from RawData")
                foreach ($c in $exchangeCertificates) {
                    $allExchangeCertificates.Add($(Import-ExchangeCertificateFromRawData $c))
                }
            }

            Write-Verbose ("$($allExchangeCertificates.Count) Exchange Server certificates were returned")
        }
    } end {
        return $allExchangeCertificates
    }
}



function Get-ExchangeContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $exchangeContainer = [ADSI]("LDAP://" + $exchangeContainerPath)
    Write-Verbose "Exchange Container Path: $($exchangeContainer.path)"
    return $exchangeContainer
}

<#
.DESCRIPTION
    This function is used for when you are in a remote context to still be able to have
    debug logging within a secondary function that you just called and returning a object from that function.
    This then prevents all the objects from New-RemoteLoggingPipelineObject to also be stored in your variable.
#>
function Invoke-RemotePipelineHandler {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Object,

        [Parameter(Mandatory = $true)]
        [ref]$Result
    )
    begin {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($null -ne $type -and
                $type.GetType().Name -ne "PSMethod" -and
                $type -match "Verbose|Progress|Host|Warning|Error") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
    }
    end {
        # If only a single result, return that vs a list
        if ($nonLoggingInfo.Count -eq 1) {
            $Result.Value = $nonLoggingInfo[0]
        } elseif ($nonLoggingInfo.Count -eq 0) {
            # Return null value because nothing is in the list.
            # If you still want to return an empty array here, use Invoke-RemotePipelineHandlerList
            $Result.Value = $null
        } else {
            $Result.Value = $nonLoggingInfo
        }
    }
}

<#
.DESCRIPTION
    This does the same as Invoke-RemotePipelineHandler but we will return an empty list and always return the results as a list.
#>
function Invoke-RemotePipelineHandlerList {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Object,

        [Parameter(Mandatory = $true)]
        [ref]$Result
    )
    begin {
        $nonLoggingInfo = New-Object System.Collections.Generic.List[object]
    }
    process {
        foreach ($instance in $Object) {
            $type = $instance.RemoteLoggingType

            if ($null -ne $type -and
                $type.GetType().Name -ne "PSMethod" -and
                $type -match "Verbose|Progress|Host|Warning|Error") {
                #place it back onto the pipeline
                $instance
            } else {
                $nonLoggingInfo.Add($instance)
            }
        }
    }
    end {
        # This could be an empty list, up to the caller to determine this.
        $Result.Value = $nonLoggingInfo
    }
}

function Get-OrganizationContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $exchangeContainer = $null
    Get-ExchangeContainer | Invoke-RemotePipelineHandler -Result ([ref]$exchangeContainer)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=msExchOrganizationContainer)", @("distinguishedName"))
    return $searcher.FindOne().GetDirectoryEntry()
}

function Get-InternalTransportCertificateFromServer {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        Reads the certificate set as internal transport certificate (aka default SMTP certificate) from AD.
        The certificate is specified on a per-server base.

        Returns the X509Certificate2 object if we were able to query it from AD, otherwise it returns $null.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $organizationContainer = $null
        Get-OrganizationContainer | Invoke-RemotePipelineHandler -Result ([ref]$organizationContainer)
        $exchangeServerPath = ("CN=" + $($ComputerName.Split(".")[0]) + ",CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups," + $organizationContainer.distinguishedName)
        $exchangeServer = [ADSI]("LDAP://" + $exchangeServerPath)
        Write-Verbose "Exchange Server path: $($exchangeServerPath)"
        if ($null -ne $exchangeServer.msExchServerInternalTLSCert) {
            $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($exchangeServer.msExchServerInternalTLSCert)
            Write-Verbose ("Internal transport certificate on server: $($ComputerName) is: $($certObject.Thumbprint)")
        }
    } catch {
        Write-Verbose ("Unable to query the internal transport certificate - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return $certObject
}


function New-ExchangeSelfSignedCertificate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateScript({ $_.Length -lt 64 })]
        [string]$SubjectName = $env:COMPUTERNAME,

        [string[]]$DomainName,

        [string]$FriendlyName = "Microsoft Exchange",

        [ValidateScript({ $_ -gt 0 })]
        [int]$LifetimeInDays = 365,

        [ValidateSet("RSA", "ECC")]
        [string]$AlgorithmType = "RSA",

        [bool]$UseRSACryptoServiceProvider = $false,

        [ValidateSet(1024, 2048, 4096)]
        [int]$KeySize = 2048,

        [ValidateSet("nistP256", "nistP384", "nistP521")]
        [string]$CurveName = "nistP384",

        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string]$HashAlgorithm = "SHA256",

        [switch]$AddSubjectKeyIdentifier,

        [switch]$TrustCertificate
    )

    <#
        Generates a self-signed certificate for Exchange with support for RSA/ECC, SANs, and optional import to trusted root store.
        This function supports both legacy CSP and modern CNG key generation models. While CSP (Cryptographic Service Provider) is compatible with older systems,
        CNG (Cryptography Next Generation) offers enhanced algorithm support like ECC and better key storage flexibility.
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if (-not(Confirm-Administrator)) {
            Write-Host "Insufficient permissions to perform the certificate operation" -ForegroundColor Red

            return
        }
    } process {
        # Generate the X500DistinguishedName for the certificate
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
            $(if ($SubjectName.IndexOf("cn=") -eq -1) { "cn=$SubjectName" } else { $SubjectName }),
            [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseUTF8Encoding
        )
        Write-Verbose "Subject: $($subject.Name)"

        # Assign UTF-8 encoded FriendlyName to support non-ASCII characters in multilingual environments
        $utf8FriendlyName = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes($FriendlyName))
        Write-Verbose "FriendlyName: $utf8FriendlyName"

        # Convert the user-specified hash algorithm string into a HashAlgorithmName object required by the CertificateRequest constructor for digital signature generation
        $hashAlgorithmName = [System.Security.Cryptography.HashAlgorithmName]::new($HashAlgorithm)
        Write-Verbose "HashAlgorithm: $($hashAlgorithmName.Name)"

        # Generate a unique name for the key container
        $keyContainerName = "MonitorExchangeAuthCertificate_$((New-Guid).Guid.ToString())"

        if ($AlgorithmType -eq "ECC") {
            Write-Verbose "ECC-based certificate will be created"

            # Generate the public/private ECC key pair
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
            Write-Verbose "Public/private key pair SignatureAlgorithm: $($ecdsa.SignatureAlgorithm) KeySize: $($ecdsa.KeySize)"

            $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($CurveName)
            Write-Verbose "ECC Curve: $($curve.Oid.FriendlyName)"

            try {
                Write-Verbose "Generating key by using $CurveName curve"
                if ($PSCmdlet.ShouldProcess("Generating private key ($AlgorithmType)")) {
                    $ecdsa.GenerateKey($curve)
                }

                # Generate the ECC CertificateRequest
                Write-Verbose "Generating the ECC CertificateRequest..."

                # Initializes a new instance of the CertificateRequest class using the specified subject name, ECDSA key, and hash algorithm
                $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $subject,
                    $ecdsa,
                    $hashAlgorithmName
                )
            } catch {
                Write-Host "Something went wrong while creating the CertificateRequest. Exception $_" -ForegroundColor Red

                return
            }
        } else {
            Write-Verbose "RSA-based certificate will be created..."

            if ($UseRSACryptoServiceProvider) {
                Write-Verbose "Initializing the CspParameters..."

                # Initializes a new instance of CspParameters
                $cspParams = [System.Security.Cryptography.CspParameters]::new()

                # Parameters that are passed to the Cryptographic Service Provider (CSP)
                #cspell:disable
                $cspParams.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                $cspParams.ProviderType = 24 # PROV_RSA_FULL
                $cspParams.KeyNumber = 1 # AT_KEYEXCHANGE
                $cspParams.KeyContainerName = $keyContainerName
                #cspell:enable

                Write-Verbose "Generating the public/private RSA key pair..."
                # Initializes a new instance of RSACryptoServiceProvider to generate a new key pair, pass KeySize and CspParameters
                if ($PSCmdlet.ShouldProcess("Generating private key ($AlgorithmType)")) {
                    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(
                        $KeySize,
                        $cspParams
                    )

                    # Ensure the RSA private key persists beyond the current session (stores the key in the cryptographic service provider container)
                    $rsa.PersistKeyInCsp = $true
                }
            } else {
                Write-Verbose "Initializing the CngKeyCreationParameters..."

                # Initializes a new instance of CngKeyCreationParameters
                $cngKeyCreationParameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()

                # Parameters that are passed to the Cryptography Next Generation (CNG)
                $cngKeyCreationParameters.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
                $cngKeyCreationParameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
                $cngKeyCreationParameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowExport

                # Add RSA-specific CngProperty for the key size
                Write-Verbose "RSA key size: $KeySize"
                $cngKeyLengthProperty = [System.Security.Cryptography.CngProperty]::new(
                    "Length", # Property name
                    [BitConverter]::GetBytes($KeySize), # Property value bytes
                    [System.Security.Cryptography.CngPropertyOptions]::None
                )

                Write-Verbose "Adding RSA-specific KeyLength property"
                $cngKeyCreationParameters.Parameters.Add($cngKeyLengthProperty)

                # Create a new RSA key pair and store it in the CNG key store with the specified parameters
                Write-Verbose "Creating the RSA-based CngKey..."
                $cngKey = [System.Security.Cryptography.CngKey]::Create(
                    [System.Security.Cryptography.CngAlgorithm]::Rsa, # Specifies RSA algorithm
                    $keyContainerName, # Name of the key container
                    $cngKeyCreationParameters # Creation options
                )

                # Wrap the existing CNG key in an RSACng object for cryptographic operations
                Write-Verbose "Generating the public/private RSA key pair..."
                if ($PSCmdlet.ShouldProcess("Generating private key ($AlgorithmType)")) {
                    $rsa = [System.Security.Cryptography.RSACng]::new($cngKey)
                }
            }

            try {
                Write-Verbose "Generating the RSA CertificateRequest..."

                # Initializes a new instance of the CertificateRequest class using the specified subject name, RSA key, hash algorithm, and using PKCS #1 v1.5 padding
                if ($PSCmdlet.ShouldProcess("Generating RSA certificate request")) {
                    $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                        $subject,
                        $rsa,
                        $hashAlgorithmName,
                        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                }
            } catch {
                Write-Host "Something went wrong while creating the CertificateRequest. Exception $_" -ForegroundColor Red

                return
            }
        }

        # Add SubjectAlternativeNames if some were passed via DomainName parameter
        if ($DomainName.Count -gt 0) {
            Write-Verbose "DomainNames that will be added to the certificate: $([System.String]::Join(", ", $DomainName))"

            $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()

            foreach ($name in $DomainName) {
                Write-Verbose "Adding DnsName: $name"
                $sanBuilder.AddDnsName($name)
            }

            if ($PSCmdlet.ShouldProcess("Adding $($DomainName.Count) DnsName(s) to SAN extension")) {
                $certificateRequest.CertificateExtensions.Add(
                    $sanBuilder.Build($true)
                )
            }
        }

        try {
            Write-Verbose "Processing certificate extensions..."

            # Specify the X509KeyUsageExtension
            $keyUsageExtensions = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor # DigitalSignature: The certificate's public key can be used to verify digital signatures
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, # KeyEncipherment: The public key can also be used to encrypt symmetric keys
                $true # critical? marked as critical
            )

            if ($PSCmdlet.ShouldProcess("Adding the X509KeyUsageExtension")) {
                $certificateRequest.CertificateExtensions.Add($keyUsageExtensions)
            }

            # Specify the X509EnhancedKeyUsageExtension
            $oids = [System.Security.Cryptography.OidCollection]::new()
            $oids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1")) | Out-Null  # Server Authentication OID

            $extendedKeyUsageExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $oids, # OID for Server Authentication
                $false # critical? marked as not critical
            )

            if ($PSCmdlet.ShouldProcess("Adding the X509EnhancedKeyUsageExtension")) {
                $certificateRequest.CertificateExtensions.Add($extendedKeyUsageExtension)
            }

            # Specify the X509BasicConstraintsExtension
            $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false, # certificateAuthority: this is not a CA
                $false, # hasPathLengthConstraint: we don't want to enforce one
                0, # pathLengthConstraint: ignored since hasPathLengthConstraint is false
                $true # critical? marked as critical
            )

            if ($PSCmdlet.ShouldProcess("Adding the X509BasicConstraintsExtension")) {
                $certificateRequest.CertificateExtensions.Add($basicConstraints)
            }

            # Add the Subject Key Identifier (SKI) as a non-critical extensions if AddSubjectKeyIdentifier parameter was set to true
            if ($AddSubjectKeyIdentifier) {
                $subjectKeyIdentifier = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new(
                    $certificateRequest.PublicKey,
                    $false
                )

                if ($PSCmdlet.ShouldProcess("Adding Subject Key Identifier (SKI)")) {
                    $certificateRequest.CertificateExtensions.Add($subjectKeyIdentifier)
                }
            }
        } catch {
            Write-Host "Something went wrong while processing certificate extensions. Exception: $_" -ForegroundColor Red

            return
        }

        try {
            # Create the self-signed certificate
            Write-Verbose "Creating the self-signed certificate with a lifetime of $LifetimeInDays days"

            $notBefore = [System.DateTimeOffset]::UtcNow
            $notAfter = $notBefore.AddDays($LifetimeInDays)
            if ($PSCmdlet.ShouldProcess("Creating self-signed certificate for '$($subject.Name)'")) {
                $certificate = $certificateRequest.CreateSelfSigned(
                    $notBefore,
                    $notAfter
                )
            }

            if (-not([System.String]::IsNullOrEmpty($utf8FriendlyName))) {
                if ($PSCmdlet.ShouldProcess("Adding FriendlyName $utf8FriendlyName")) {
                    $certificate.FriendlyName = $utf8FriendlyName
                }
            }

            if ($PSCmdlet.ShouldProcess("Setting certificate thumbprint")) {
                $certificateThumbprint = $certificate.Thumbprint
            } else {
                # Mock certificate thumbprint
                $certificateThumbprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
            }

            Write-Verbose "Certificate was created successfully - Thumbprint: $certificateThumbprint Subject: $($subject.Name)"
        } catch {
            Write-Host "Something went wrong while creating the self-signed certificate. Exception: $_" -ForegroundColor Red

            return
        }

        try {
            # To make the certificate and its private key exportable, we must export and re-import it with the Exportable flag
            Write-Verbose "Exporting and re-importing certificate with Exportable flag to make it exportable..."
            if ($PSCmdlet.ShouldProcess("Making certificate exportable")) {
                $pfxBytes = $certificate.Export(
                    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
                )
                $certificateWithExportableKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
                $certificateWithExportableKey.Import(
                    $pfxBytes,
                    $null,
                    ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)
                )
            }

            # Add it to the LocalMachine store
            Write-Verbose "Adding the certificate to the My/LocalMachine certificate store..."

            $machineStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                "My",
                "LocalMachine"
            )

            if ($PSCmdlet.ShouldProcess("Adding certificate to LocalMachine\My store")) {
                $machineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $machineStore.Add($certificateWithExportableKey)
                $machineStore.Close()
            }

            # Add the certificate to the Trusted Root Certification Authorities if explicitly specified via TrustCertificate parameter
            if ($TrustCertificate) {
                Write-Verbose "Adding the certificate to the Root/LocalMachine store to make it a trusted certificate..."

                $trustedRootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                    "Root",
                    "LocalMachine"
                )

                if ($TrustCertificate -and $PSCmdlet.ShouldProcess("Adding certificate to LocalMachine\Root store")) {
                    $trustedRootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $trustedRootStore.Add($certificateWithExportableKey)
                    $trustedRootStore.Close()
                }
            }
        } catch {
            Write-Host "Something went wrong while adding the certificate to the store. Exception: $_" -ForegroundColor Red

            return
        } finally {
            if ($null -ne $pfxBytes) {
                Write-Verbose "Overwriting temporary .pfx with random data..."

                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($pfxBytes)
                $pfxBytes = $null
            }

            if ($null -ne $certificateWithExportableKey) {
                Write-Verbose "Disposing certificate from memory..."

                $certificateWithExportableKey.Dispose()
            }
        }
    } end {
        if ($null -ne $certificate) {
            Write-Verbose "Disposing X509Certificate2 object..."
            # Call Dispose() to release all resources used by the X509Certificate object
            $certificate.Dispose()
        }

        if ($null -ne $rsa) {
            Write-Verbose "Clearing and disposing RSA key object..."
            # Call Clear() to release resources and delete the key from the container
            $rsa.Clear()
        }

        if ($null -ne $ecdsa) {
            # Call Clear() to release resources and delete the key from the container
            Write-Verbose "Clearing and disposing ECDsa key object..."
            $ecdsa.Clear()
        }

        if ($null -ne $cngKey) {
            # Call Delete() to remove the key that is associated with the object
            Write-Verbose "Deleting CngKey object..."
            $cngKey.Delete()
        }

        return [PSCustomObject]@{
            Subject    = $subject.Name
            Thumbprint = $certificateThumbprint
        }
    }
}

function New-ExchangeAuthCertificate {
    [CmdletBinding(DefaultParameterSetName = "NewPrimaryAuthCert", SupportsShouldProcess = $true, ConfirmImpact = "High")]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = "NewPrimaryAuthCert")]
        [switch]$ReplaceExpiredAuthCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = "NewNextAuthCert")]
        [switch]$ConfigureNextAuthCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "NewNextAuthCert")]
        [int]$CurrentAuthCertificateLifetimeInDays,

        [Parameter(Mandatory = $false, ParameterSetName = "NewPrimaryAuthCert")]
        [Parameter(Mandatory = $false, ParameterSetName = "NewNextAuthCert")]
        [ValidateScript({ $_ -ge 0 })]
        [int]$NewAuthCertificateLifetimeInDays,

        [Parameter(Mandatory = $false, ParameterSetName = "NewPrimaryAuthCert")]
        [Parameter(Mandatory = $false, ParameterSetName = "NewNextAuthCert")]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        function GetCertificateBoundToDefaultWebSiteThumbprints {
            [CmdletBinding()]
            param()

            <#
                Returns the thumbprint of the certificate which is bound to the 'Default Web Site' in IIS
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                # Remove empty elements from array as they could be returned if no certificate is bound to a binding in between, then sort
                # the array and remove duplicates.
                $hashes = ((Get-Website -Name "Default Web Site" -ErrorAction Stop).bindings.collection.CertificateHash) | Where-Object {
                    $_
                } | Sort-Object -Unique
            } catch {
                Write-Verbose ("Unable to query 'Default Web Site' SSL binding information")
                Invoke-CatchActionError $CatchActionFunction
            }

            return $hashes
        }

        function GenerateNewAuthCertificate {
            [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
            [OutputType([System.Object])]
            param()

            <#
                Generates a new Auth Certificate which can then be configured via 'Set-AuthConfig'
                Returns a PSCustomObject with the information of the newly generated certificate
                which can then be consumed by the next function which configures the certificate as
                new Auth Certificate.
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $confirmationMessage = "The following actions will be performed without the need to reconfirm:" +
            "`r`n    - The internal transport certificate will be queried" +
            "`r`n    - A new certificate will be generated, it overrides the internal transport certificate" +
            "`r`n    - The internal transport certificate will be set back to the previous one" +
            "`r`n      or" +
            "`r`n    - A new internal transport certificate will be generated if the previous one is invalid"

            $operationSuccessful = $false
            $internalTransportCertificateFoundOnServer = $false
            $errorCount = $Error.Count

            $authCertificateFriendlyName = ("Microsoft Exchange Server Auth Certificate - $(Get-Date -Format yyyyMMddhhmmss)")

            try {
                $newInternalTransportCertificateParams = @{
                    Server               = $env:COMPUTERNAME
                    KeySize              = 2048
                    PrivateKeyExportable = $true
                    FriendlyName         = $env:COMPUTERNAME
                    DomainName           = $env:COMPUTERNAME
                    IncludeServerFQDN    = $true
                    Services             = "SMTP"
                    Force                = $true
                    ErrorAction          = "Stop"
                }

                $newAuthCertificateParams = @{
                    Server               = $env:COMPUTERNAME
                    KeySize              = 2048
                    PrivateKeyExportable = $true
                    SubjectName          = "cn=Microsoft Exchange Server Auth Certificate"
                    FriendlyName         = $authCertificateFriendlyName
                    DomainName           = @()
                    ErrorAction          = "Stop"
                }

                $newCustomAuthCertificateParams = @{
                    AlgorithmType               = "RSA"
                    UseRSACryptoServiceProvider = $true # Make sure to set this to true as the certificate can't be used as Auth Certificate otherwise
                    KeySize                     = 2048
                    LifetimeInDays              = $NewAuthCertificateLifetimeInDays
                    SubjectName                 = "Microsoft Exchange Server Auth Certificate"
                    FriendlyName                = $authCertificateFriendlyName
                    DomainName                  = @()
                }

                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $confirmationMessage, "Unattended Exchange certificate generation")) {
                    Write-Verbose ("Internal transport certificate will be overwritten for a short time and then reset to the previous one")
                    $internalTransportCertificate = Get-InternalTransportCertificateFromServer $env:COMPUTERNAME
                    $defaultWebSiteCertificateThumbprints = GetCertificateBoundToDefaultWebSiteThumbprints
                    [string]$internalTransportCertificateThumbprint = $internalTransportCertificate.Thumbprint

                    if (($null -ne $internalTransportCertificate) -and
                        ($null -ne $defaultWebSiteCertificateThumbprints)) {
                        $newAuthCertificateParams.Add("Force", $true)
                        $servicesToEnable = $null
                        $servicesToEnableList = New-Object 'System.Collections.Generic.List[object]'
                        try {
                            $internalTransportCertificate = Get-ExchangeServerCertificate -Server $env:COMPUTERNAME -Thumbprint $internalTransportCertificateThumbprint -ErrorAction Stop

                            if ($null -ne $internalTransportCertificate) {
                                $internalTransportCertificateFoundOnServer = $true
                                $isInternalTransportBoundToIisFe = $defaultWebSiteCertificateThumbprints.Contains($internalTransportCertificateThumbprint)

                                if (($null -ne $internalTransportCertificate.Services) -and
                                    ($internalTransportCertificate.Services -ne 0)) {
                                    $transportCertificateServices = ($internalTransportCertificate.Services).ToString().ToUpper().Split(",").Trim()
                                    if ($transportCertificateServices.Count -eq 1) {
                                        # Use the Add() method if only one service is bound to the transport certificate
                                        $servicesToEnableList.Add($transportCertificateServices)
                                    } else {
                                        # Use the AddRange() method otherwise
                                        $servicesToEnableList.AddRange($transportCertificateServices)
                                    }

                                    # Make sure to remove IIS from list if the certificate was not bound to Front End Website before
                                    if (($isInternalTransportBoundToIisFe -eq $false) -and
                                        ($servicesToEnableList.Contains("IIS"))) {
                                        Write-Verbose ("Internal transport certificate is bound to Back End Website - avoid to enable it for IIS to prevent it being bound to Front End")
                                        $servicesToEnableList.Remove("IIS")
                                    }
                                } elseif ($null -eq $internalTransportCertificate.Services) {
                                    Write-Verbose ("No service information returned for internal transport certificate")
                                    if ($isInternalTransportBoundToIisFe) {
                                        Write-Verbose ("Internal transport certificate was bound to Front-End Website and will be rebound to it again")
                                        $servicesToEnableList.Add("IIS")
                                    }
                                    $servicesToEnableList.Add("SMTP")
                                }

                                $servicesToEnable = $([string]::Join(", ", $servicesToEnableList))
                            }
                        } catch {
                            Invoke-CatchActionError $CatchActionFunction
                            Write-Verbose ("Internal transport certificate wasn't detected on server: $($env:COMPUTERNAME)")
                            Write-Verbose ("We will generate a new internal transport certificate now")
                            try {
                                if ($PSCmdlet.ShouldProcess("New-ExchangeCertificate", "Generate new internal transport certificate")) {
                                    $newSelfSignedTransportCertificate = New-ExchangeCertificate @newInternalTransportCertificateParams
                                    if ($null -ne $newSelfSignedTransportCertificate) {
                                        $internalTransportCertificateFoundOnServer = $true
                                        if ($null -ne $newSelfSignedTransportCertificate.Thumbprint) {
                                            Write-Verbose ("Certificate object successfully deserialized")
                                            [string]$internalTransportCertificateThumbprint = $newSelfSignedTransportCertificate.Thumbprint
                                        } else {
                                            Write-Verbose ("Looks like deserialization of the certificate object failed - trying to import from RawData")
                                            [string]$internalTransportCertificateThumbprint = (Import-ExchangeCertificateFromRawData $newSelfSignedTransportCertificate).Thumbprint
                                            if ($null -ne $internalTransportCertificateThumbprint) {
                                                Write-Verbose ("Import from RawData was successful")
                                            } else {
                                                throw ("Import from RawData failed")
                                            }
                                        }

                                        Write-Verbose ("A new internal transport certificate with thumbprint: $($internalTransportCertificateThumbprint) was generated")
                                        $servicesToEnable = "SMTP"
                                    }
                                } else {
                                    $newInternalTransportCertificateParams.GetEnumerator() | ForEach-Object {
                                        Write-Host ("What if: Key: $($_.key) - Value: $($_.value)")
                                    }
                                }
                            } catch {
                                Write-Verbose ("Hit an exception while trying to generate a new internal transport certificate - Exception: $(Error[0].Exception.Message)")
                                Invoke-CatchActionError $CatchActionFunction
                            }
                        }
                    }
                }

                Write-Verbose ("Starting Auth Certificate creation process")
                try {
                    if ($PSCmdlet.ShouldProcess("New-ExchangeCertificate", "Generate new Auth Certificate")) {
                        if ($NewAuthCertificateLifetimeInDays -gt 0) {
                            Write-Verbose "Creating a custom self-signed certificate with a lifetime of $NewAuthCertificateLifetimeInDays days"
                            $newAuthCertificate = New-ExchangeSelfSignedCertificate @newCustomAuthCertificateParams
                        } else {
                            Write-Verbose "Creating a default self-signed certificate with a lifetime of 5 years"
                            $certObject = New-ExchangeCertificate @newAuthCertificateParams

                            $newAuthCertificate = [PSCustomObject]@{
                                Thumbprint = $certObject.Thumbprint
                                Subject    = $certObject.Subject
                                RawData    = $certObject.RawData # We need to include RawData in case the deserialization of the cert object fails
                            }
                        }
                        Write-Verbose "Certificate with thumbprint: $($newAuthCertificate.Thumbprint) was generated"
                        Start-Sleep -Seconds 5
                    } else {
                        $newAuthCertificateParams.GetEnumerator() | ForEach-Object {
                            Write-Host ("What if: Key: $($_.key) - Value: $($_.value)")
                        }
                        # Create dummy object to pass the following checks if -WhatIf was used as we don't create a new certificate in this mode
                        $newAuthCertificate = @{
                            Thumbprint = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
                        }
                    }
                } catch {
                    Write-Verbose ("Hit an exception while trying to generate a new Exchange Server Auth Certificate - Exception: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }

                if ($internalTransportCertificateFoundOnServer) {
                    if ($PSCmdlet.ShouldProcess("Certificate: $internalTransportCertificateThumbprint on: $env:COMPUTERNAME for: $servicesToEnable", "Enable-ExchangeCertificate")) {
                        Write-Verbose ("Resetting internal transport certificate back to previous one")
                        Enable-ExchangeCertificate -Server $env:COMPUTERNAME -Thumbprint $internalTransportCertificateThumbprint -Services $servicesToEnable -Force | Out-Null
                        Start-Sleep -Seconds 10
                        Write-Verbose ("Internal transport certificate was reset back to: $((Get-InternalTransportCertificateFromServer $env:COMPUTERNAME).Thumbprint)")
                    }
                }

                if ($null -ne $newAuthCertificate) {
                    $operationSuccessful = $true
                    if (-not([System.String]::IsNullOrWhiteSpace($newAuthCertificate.Thumbprint))) {
                        Write-Verbose ("Certificate object successfully deserialized")
                        [string]$newAuthCertificateThumbprint = $newAuthCertificate.Thumbprint
                    } else {
                        Write-Verbose ("Looks like deserialization of the certificate object failed - trying to import from RawData")
                        [string]$newAuthCertificateThumbprint = (Import-ExchangeCertificateFromRawData $newAuthCertificate).Thumbprint
                        if ($null -ne $newAuthCertificateThumbprint) {
                            Write-Verbose ("Import from RawData was successful")
                        } else {
                            throw ("Import from RawData failed")
                        }
                    }
                    Write-Verbose ("New Auth Certificate was successfully created. Thumbprint: $($newAuthCertificateThumbprint)")
                }
            } catch {
                Write-Verbose ("We hit an exception during Auth Certificate creation process - Exception: $($Error[0].Exception.Message)")
                Invoke-CatchActionError $CatchActionFunction
            }

            return [PSCustomObject]@{
                ComputerName                = $env:COMPUTERNAME
                InternalTransportThumbprint = $internalTransportCertificateThumbprint
                FriendlyName                = $authCertificateFriendlyName
                Thumbprint                  = $newAuthCertificateThumbprint
                Successful                  = $operationSuccessful
                ErrorOccurred               = if ($Error.Count -gt $errorCount) { $($Error[0].Exception.Message) }
            }
        }

        function ConfigureNextAuthCertificate {
            [CmdletBinding()]
            [OutputType([System.Object])]
            param(
                [int]$CurrentAuthCertificateLifetimeInDays,
                [int]$EnableDaysInFuture = 30
            )

            <#
                We must generate a new self-signed certificate and set it as new certificate by the help of the
                -NewCertificateThumbprint parameter. We must also specify a DateTime (via -NewCertificateEffectiveDate)
                when the new certificate becomes active.

                Returns $true if renewal was successful, returns $false if it wasn't
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $renewalSuccessful = $false
            $newAuthCertificateObject = GenerateNewAuthCertificate
            $nextAuthCertificateActiveOn = (Get-Date).AddDays($EnableDaysInFuture)

            if ($null -ne $CurrentAuthCertificateLifetimeInDays) {
                Write-Verbose ("Current Auth Certificate will expire in: $($CurrentAuthCertificateLifetimeInDays) days")

                if ($CurrentAuthCertificateLifetimeInDays -lt ($EnableDaysInFuture + 2)) {
                    Write-Verbose ("Need to re-calculate the EnableDaysInFuture value to ensure a smooth Auth Certificate rotation")
                    # Assuming that there is not much time (< 2 days) until the current Auth Certificate expires,
                    # the next Auth Certificate should become active as soon as the AuthAdmin servicelet runs on the server
                    $EnableDaysInFuture = 0

                    if (($CurrentAuthCertificateLifetimeInDays - 4) -gt 0) {
                        $EnableDaysInFuture = 4
                    } elseif (($CurrentAuthCertificateLifetimeInDays - 2) -gt 0) {
                        $EnableDaysInFuture = 2
                    }

                    $nextAuthCertificateActiveOn = (Get-Date).AddDays($EnableDaysInFuture)
                    Write-Verbose ("The new Auth Certificate will become active in: $($EnableDaysInFuture) days")
                } else {
                    Write-Verbose ("There is enough time to initiate the Auth Certificate rotation - no need to adjust EnableDaysInFuture")
                }
            }

            if (($null -ne $newAuthCertificateObject) -and
                ($newAuthCertificateObject.Successful)) {
                [string]$newAuthCertificateThumbprint = $newAuthCertificateObject.Thumbprint
                Write-Verbose ("New Auth Certificate with thumbprint: $($newAuthCertificateThumbprint) generated - the new one will replace the existing one in: $($EnableDaysInFuture) days")
                try {
                    Write-Verbose ("[Required] Step 1: Set certificate: $($newAuthCertificateThumbprint) as the next Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("Certificate: $newAuthCertificateThumbprint Date: $nextAuthCertificateActiveOn", "Set-AuthConfig")) {
                        $setAuthConfigParams = @{
                            NewCertificateThumbprint    = $newAuthCertificateThumbprint
                            NewCertificateEffectiveDate = if ($EnableDaysInFuture -eq 0) { Get-Date } else { $nextAuthCertificateActiveOn }
                            Force                       = $true
                            ErrorAction                 = "Stop"
                        }
                        Set-AuthConfig @setAuthConfigParams
                    }

                    if ($EnableDaysInFuture -eq 0) {
                        # Restart MSExchangeServiceHost service to ensure that the new Auth Certificate is used immediately as don't have time
                        # to wait until the AuthAdmin servicelet runs on the server due to the limited time until the current Auth Certificate expires
                        Write-Verbose ("[Optional] Step 2: Restart service 'MSExchangeServiceHost' on computer: $($env:COMPUTERNAME)")
                        Restart-Service -Name "MSExchangeServiceHost" -ErrorAction Stop
                    }
                    Write-Verbose ("Done - Certificate: $($newAuthCertificateThumbprint) set as the next Auth Certificate")
                    Write-Verbose ("Effective date is: $($nextAuthCertificateActiveOn)")
                    $renewalSuccessful = $true
                } catch {
                    Write-Verbose ("Error while enabling the next Auth Certificate. Error: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }
            }

            return [PSCustomObject]@{
                RenewalSuccessful           = $renewalSuccessful
                NextCertificateActiveOnDate = $nextAuthCertificateActiveOn
                NewCertificateThumbprint    = $newAuthCertificateThumbprint
            }
        }

        function ReplaceExpiredAuthCertificate {
            [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
            [OutputType([System.Object])]
            param()

            <#
                We must generate a new self-signed certificate and replace the existing Auth Certificate
                if it's already expired. We must also set it as active by specifying the current DateTime via
                -NewCertificateEffectiveDate parameter.
                To speed things up, restarting 'MSExchangeServiceHost' service is needed as well as 'MSExchangeOWAAppPool'
                and 'MSExchangeECPAppPool' app pools. However, it shouldn't become a problem if restarting the service or
                app pools fails.

                Returns $true if renewal was successful, returns $false if it wasn't
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $newAuthCertificateActiveOn = $null
            $renewalSuccessful = $false
            $newAuthCertificateObject = GenerateNewAuthCertificate

            if (($null -ne $newAuthCertificateObject) -and
                ($newAuthCertificateObject.Successful)) {
                [string]$newAuthCertificateThumbprint = $newAuthCertificateObject.Thumbprint
                Write-Verbose ("New Auth Certificate with thumbprint: $($newAuthCertificateThumbprint) generated - the existing one will be replaced immediately with the new one")
                try {
                    Write-Verbose ("[Required] Step 1: Set certificate: $($newAuthCertificateThumbprint) as new Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("Certificate: $newAuthCertificateThumbprint Date: immediately", "Set-AuthConfig")) {
                        # We must use Get-Date here to ensure that the date which is passed to NewCertificateEffectiveDate parameter is a valid one
                        $setAuthConfigParams = @{
                            NewCertificateThumbprint    = $newAuthCertificateThumbprint
                            NewCertificateEffectiveDate = ($newAuthCertificateActiveOn = Get-Date)
                            Force                       = $true
                            ErrorAction                 = "Stop"
                        }
                        Set-AuthConfig @setAuthConfigParams
                    }

                    Write-Verbose ("[Required] Step 2: Publish the new Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("PublishCertificate", "Set-AuthConfig")) {
                        Set-AuthConfig -PublishCertificate -ErrorAction Stop
                    }

                    Write-Verbose ("[Required] Step 3: Clear previous Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("ClearPreviousCertificate", "Set-AuthConfig")) {
                        Set-AuthConfig -ClearPreviousCertificate -ErrorAction Stop
                    }

                    try {
                        # Run these commands in a separate try / catch as it isn't a terminating issue if they fail
                        Write-Verbose ("[Optional] Step 4: Restart service 'MSExchangeServiceHost' on computer: $($env:COMPUTERNAME)")
                        Restart-Service -Name "MSExchangeServiceHost" -ErrorAction Stop

                        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Restart-WebAppPool")) {
                            Write-Verbose ("[Optional] Step 5: Restart WebApp Pools 'MSExchangeOWAAppPool' and 'MSExchangeECPAppPool' on computer $($env:COMPUTERNAME)")
                            Restart-WebAppPool -Name "MSExchangeOWAAppPool" -ErrorAction Stop
                            Restart-WebAppPool -Name "MSExchangeECPAppPool" -ErrorAction Stop
                        }
                    } catch {
                        Write-Warning ("Error while restarting service 'MSExchangeServiceHost' or WebApp Pools")
                        Write-Warning ("However, these steps are optional and not required - the Auth Certificate was replaced with a new one")
                        Invoke-CatchActionError $CatchActionFunction
                    }

                    Write-Verbose ("Done - Certificate: $($newAuthCertificateThumbprint) is the new Auth Certificate")
                    $renewalSuccessful = $true
                } catch {
                    Write-Verbose ("Error while enabling the new Auth Certificate - Exception: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }
            }

            return [PSCustomObject]@{
                RenewalSuccessful           = $renewalSuccessful
                NextCertificateActiveOnDate = $newAuthCertificateActiveOn
                NewCertificateThumbprint    = $newAuthCertificateThumbprint
            }
        }
    }
    process {
        if ($ReplaceExpiredAuthCertificate) {
            Write-Verbose ("Calling function to replace an already expired or invalid Auth Certificate")
            $renewalActionPerformed = ReplaceExpiredAuthCertificate
        } elseif ($ConfigureNextAuthCertificate) {
            Write-Verbose ("Calling function to state the next Auth Certificate for rotation")
            $renewalActionPerformed = ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays $CurrentAuthCertificateLifetimeInDays
        } else {
            Write-Verbose ("No Auth Certificate configuration action was specified")
        }
    }
    end {
        return [PSCustomObject]@{
            RenewalActionPerformed        = ($renewalActionPerformed.RenewalSuccessful -eq $true)
            AuthCertificateActivationDate = ($renewalActionPerformed.NextCertificateActiveOnDate)
            NewCertificateThumbprint      = ($renewalActionPerformed.NewCertificateThumbprint)
        }
    }
}


function Register-AuthCertificateRenewalTask {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [string]$TaskName = "Daily Auth Certificate Check",
        [string]$Username,
        [SecureString]$Password,
        [string]$WorkingDirectory,
        [string]$ScriptName,
        [bool]$IgnoreOfflineServers = $false,
        [bool]$IgnoreHybridConfig = $false,
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$SendEmailNotificationTo,
        [switch]$TrustAllCertificates,
        [string]$DailyRuntime = "10am",
        [string]$TaskDescription = "AutoGeneratedViaMonitorExchangeAuthCertificateScript",
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $fullPathToScript = [System.IO.Path]::Combine($WorkingDirectory, $ScriptName)
    try {
        $existingScheduledTask = Get-ScheduledTask -TaskName $($TaskName) -ErrorAction Stop | Where-Object {
            ($_.Description -eq $TaskDescription)
        }
    } catch {
        Write-Verbose ("No scheduled task with name: $($TaskName) was found - we don't need to unregister it")
        Invoke-CatchActionError $CatchActionFunction
    }

    if ($null -ne $existingScheduledTask) {
        Write-Verbose ("Scheduled task already exists - will be deleted now to re-create a new one")
        try {
            foreach ($t in $existingScheduledTask) {
                if ($PSCmdlet.ShouldProcess($t.TaskName, "Unregister-ScheduledTask")) {
                    Unregister-ScheduledTask -TaskPath $($t.TaskPath) -TaskName $($t.TaskName) -Confirm:$false -ErrorAction Stop
                }
                Write-Verbose ("Scheduled task: $($t.TaskName) successfully unregistered")
            }
        } catch {
            Write-Verbose ("The scheduled task already exists and we were unable to unregister it - Exception $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
            return $false
        }
    }

    if (($WhatIfPreference) -or
        (Test-Path -Path $fullPathToScript)) {
        $passwordAsPlaintextString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

        if ($PSCmdlet.ShouldProcess($DailyRuntime, "New-ScheduledTaskTrigger")) {
            $schTaskTrigger = New-ScheduledTaskTrigger -Daily -At $DailyRuntime
        }

        $newScheduledTaskParams = @{
            Execute          = "powershell.exe"
            WorkingDirectory = "$($WorkingDirectory)"
        }

        $basicArgumentParameters = "-NonInteractive -NoLogo -NoProfile -Command `".\$($ScriptName) -ValidateAndRenewAuthCertificate `$true -IgnoreUnreachableServers `$$($IgnoreOfflineServers) -IgnoreHybridConfig `$$($IgnoreHybridConfig)"
        if ($null -ne $SendEmailNotificationTo) {
            if ($TrustAllCertificates) {
                $newScheduledTaskParams.Add("Argument", "$($basicArgumentParameters) -SendEmailNotificationTo $([string]::Join(", ", $SendEmailNotificationTo)) -TrustAllCertificates -Confirm:`$false`"")
            } else {
                $newScheduledTaskParams.Add("Argument", "$($basicArgumentParameters) -SendEmailNotificationTo $([string]::Join(", ", $SendEmailNotificationTo)) -Confirm:`$false`"")
            }
        } else {
            $newScheduledTaskParams.Add("Argument", "$($basicArgumentParameters) -Confirm:`$false`"")
        }

        if ($PSCmdlet.ShouldProcess($TaskName, "New-ScheduledTaskAction")) {
            $schTaskAction = New-ScheduledTaskAction @newScheduledTaskParams

            $registerSchTaskParams = @{
                TaskName    = $TaskName
                Trigger     = $schTaskTrigger
                Action      = $schTaskAction
                Description = $TaskDescription
                RunLevel    = "Highest"
                User        = $Username
                Password    = $passwordAsPlaintextString
                Force       = $true
                ErrorAction = "Stop"
            }
        }

        try {
            Write-Verbose ("Scheduled Task: $($TaskName) successfully created")
            if ($PScmdlet.ShouldProcess($TaskName, "Register-ScheduledTask")) {
                Register-ScheduledTask @registerSchTaskParams | Out-Null
            }
            return $true
        } catch {
            Write-Verbose ("Error while creating Scheduled Task: $($TaskName) - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    } else {
        Write-Verbose ("Script: $($fullPathToScript) doesn't exist")
    }

    return $false
}


function Get-ExchangeAuthCertificateStatus {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [bool]$IgnoreUnreachableServers = $false,

        [bool]$IgnoreHybridSetup = $false,

        [bool]$EnforceNewNextAuthCertificateCreation = $false,

        [ScriptBlock]$CatchActionFunction
    )

    <#
        Returns an object which contains information if the current Auth Certificate and/or the next Auth Certificate must be renewed.
        The object contains the following properties:
            - CurrentAuthCertificateLifetimeInDays
            - ReplaceRequired
            - ConfigureNextAuthRequired
            - NumberOfUnreachableServers
            - UnreachableServerList
            - HybridSetupDetected
            - StopProcessingDueToHybrid
            - MultipleExchangeADSites
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $replaceRequired = $false
        $importCurrentAuthCertificateRequired = $false
        $configureNextAuthRequired = $false
        $importNextAuthCertificateRequired = $false

        # Make sure to initialize this with -1 as this is needed to properly run the validation in case that we're unable to query this information
        $currentAuthCertificateValidInDays = -1
        $nextAuthCertificateValidInDays = -1

        $exchangeServersUnreachableList = New-Object 'System.Collections.Generic.List[string]'
        $exchangeServersReachableList = New-Object 'System.Collections.Generic.List[string]'
        $currentAuthCertificateFoundOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $nextAuthCertificateFoundOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $currentAuthCertificateMissingOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $nextAuthCertificateMissingOnServersList = New-Object 'System.Collections.Generic.List[string]'
    } process {
        $authConfiguration = Get-AuthConfig -ErrorAction SilentlyContinue
        $allMailboxServers = Get-ExchangeServer | Where-Object {
            ((($_.IsMailboxServer) -or
                ($_.IsClientAccessServer)) -and
            ($_.AdminDisplayVersion -match "^Version 15"))
        }

        $multipleExchangeSites = (($allMailboxServers.Site.Name | Sort-Object -Unique).Count -gt 1)
        Write-Verbose ("Exchange deployed to multiple AD sites? $($multipleExchangeSites)")

        try {
            $hybridConfiguration = Get-HybridConfiguration -ErrorAction Stop
        } catch {
            Write-Verbose ("We hit an exception while querying the Exchange Hybrid configuration state - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }

        if ($null -ne $authConfiguration) {
            Write-Verbose ("AuthConfig returned via 'Get-AuthConfig' call")

            if (-not([string]::IsNullOrEmpty($authConfiguration.CurrentCertificateThumbprint))) {
                Write-Verbose ("CurrentCertificateThumbprint is: $($authConfiguration.CurrentCertificateThumbprint)")
                foreach ($mbxServer in $allMailboxServers) {
                    try {
                        Write-Verbose ("Trying to query current Auth Certificate on server: $($mbxServer)")
                        $currentAuthCertificate = Get-ExchangeServerCertificate -Server $($mbxServer.Fqdn) -Thumbprint $authConfiguration.CurrentCertificateThumbprint -ErrorAction Stop
                        $exchangeServersReachableList.Add($mbxServer.Fqdn)
                        $currentAuthCertificateFoundOnServersList.Add($mbxServer.Fqdn)
                    } catch {
                        Write-Verbose ("We hit an exception - going to determine the reason")
                        Invoke-CatchActionError $CatchActionFunction

                        if ((($error[0].CategoryInfo).Reason) -eq "InvalidOperationException") {
                            # Auth Certificate must exist on all servers, if it doesn't, generate a new one and replace the existing one
                            Write-Verbose ("Current Auth Certificate not found on server: $($mbxServer)")
                            $exchangeServersReachableList.Add($mbxServer.Fqdn)
                            $currentAuthCertificateMissingOnServersList.Add($mbxServer.Fqdn)
                        } else {
                            Write-Verbose ("Computer: $($mbxServer.Fqdn) is unreachable and cannot take into account")
                            $exchangeServersUnreachableList.Add($mbxServer.Fqdn)
                        }
                    }
                }
            }

            if (-not([string]::IsNullOrEmpty($authConfiguration.NextCertificateThumbprint))) {
                Write-Verbose ("NextCertificateThumbprint is: $($authConfiguration.NextCertificateThumbprint)")
                foreach ($mbxServer in $exchangeServersReachableList) {
                    try {
                        Write-Verbose ("Trying to query next Auth Certificate on server: $($mbxServer)")
                        $nextAuthCertificate = Get-ExchangeServerCertificate -Server $mbxServer -Thumbprint $authConfiguration.NextCertificateThumbprint -ErrorAction Stop
                        $nextAuthCertificateFoundOnServersList.Add($mbxServer)
                    } catch {
                        Invoke-CatchActionError $CatchActionFunction

                        if ((($error[0].CategoryInfo).Reason) -eq "InvalidOperationException") {
                            # Next Auth Certificate must exist on all servers, if it doesn't, generate a new one and replace the existing
                            Write-Verbose ("Next Auth Certificate not found on server: $($mbxServer)")
                            $nextAuthCertificateMissingOnServersList.Add($mbxServer)
                        } else {
                            Write-Verbose ("Exception reason is: $(($error[0].CategoryInfo).Reason)")
                            Write-Verbose ("Do nothing as we can't say for sure if the Auth Certificate exists or not")
                        }
                    }
                }
            }

            Write-Verbose ("Number of unreachable servers: $($exchangeServersUnreachableList.Count) - IgnoreUnreachableServers? $($IgnoreUnreachableServers)")

            if (($exchangeServersUnreachableList.Count -eq 0) -or
                (($exchangeServersUnreachableList.Count -gt 0) -and
                ($IgnoreUnreachableServers))) {

                if ($exchangeServersReachableList.Count -gt $currentAuthCertificateMissingOnServersList.Count) {
                    if ($null -ne $currentAuthCertificate.NotAfter) {
                        $currentAuthCertificateValidInDays = (($currentAuthCertificate.NotAfter) - (Get-Date)).Days

                        if (($currentAuthCertificate.NotAfter).Date -lt (Get-Date)) {
                            if ($currentAuthCertificateValidInDays -eq 0) {
                                Write-Verbose ("The current Auth Certificate has expired today")
                                $currentAuthCertificateValidInDays = -1
                            } else {
                                Write-Verbose ("The current Auth Certificate has already expired {0} days ago" -f [System.Math]::Abs($currentAuthCertificateValidInDays))
                            }
                        } else {
                            Write-Verbose ("The current Auth Certificate is still valid")
                        }
                    } else {
                        Write-Verbose ("There is no Auth Certificate configured")
                    }
                }

                if ($exchangeServersReachableList.Count -gt $nextAuthCertificateMissingOnServersList.Count) {
                    if ($null -ne $nextAuthCertificate.NotAfter) {
                        $nextAuthCertificateValidInDays = (($nextAuthCertificate.NotAfter) - (Get-Date)).Days

                        if (($nextAuthCertificate.NotAfter).Date -lt (Get-Date)) {
                            if ($nextAuthCertificateValidInDays -eq 0) {
                                Write-Verbose ("The next Auth Certificate has expired today")
                                $nextAuthCertificateValidInDays = -1
                            } else {
                                Write-Verbose ("The next Auth Certificate has already expired {0} days ago" -f [System.Math]::Abs($nextAuthCertificateValidInDays))
                            }
                        } else {
                            Write-Verbose ("The next Auth Certificate is still valid")
                        }
                    } else {
                        Write-Verbose ("There is no next Auth Certificate configured")
                    }
                }

                if (($currentAuthCertificateValidInDays -lt 0) -and
                    ($nextAuthCertificateValidInDays -lt 0)) {
                    # Scenario 1: Current Auth Certificate has expired and no next Auth Certificate defined or the next Auth Certificate has expired
                    $replaceRequired = $true
                } elseif (((($currentAuthCertificateValidInDays -ge 0) -and
                            ($currentAuthCertificateValidInDays -le 60)) -and
                        (($nextAuthCertificateValidInDays -le 0) -or
                        ($nextAuthCertificateValidInDays -le 120)) -and
                        ($currentAuthCertificateMissingOnServersList.Count -eq 0) -and
                        ($nextAuthCertificateMissingOnServersList.Count -eq 0)) -or
                    $EnforceNewNextAuthCertificateCreation) {
                    # Scenario 2: Current Auth Certificate is valid but no next Auth Certificate defined or next Auth Certificate will expire in < 120 days
                    # or EnforceNewNextAuthCertificateCreation was explicitly set to true
                    $configureNextAuthRequired = $true
                } elseif (($currentAuthCertificateValidInDays -le 0) -and
                    ($nextAuthCertificateValidInDays -ge 0)) {
                    # Scenario 3: Unlikely but possible - current Auth Certificate has expired and next Auth Certificate is set but not yet active
                    $replaceRequired = $true
                } else {
                    if ($currentAuthCertificateMissingOnServersList.Count -gt 0) {
                        # Scenario 4: Current Auth Certificate is missing on at least one (1) mailbox or CAS server
                        $importCurrentAuthCertificateRequired = $true
                    }
                    if ($nextAuthCertificateMissingOnServersList.Count -gt 0) {
                        # Scenario 5: Next Auth Certificate is missing on at least one (1) mailbox or CAS server
                        $importNextAuthCertificateRequired = $true
                    }
                }

                $stopProcessingDueToHybrid = ((($null -ne $hybridConfiguration) -and ($IgnoreHybridSetup -eq $false)) -and
                    (($replaceRequired) -or ($configureNextAuthRequired)))

                Write-Verbose ("Replace of the primary Auth Certificate required? $($replaceRequired)")
                Write-Verbose ("Import of the primary Auth Certificate required? $($importCurrentAuthCertificateRequired)")
                Write-Verbose ("Replace of the next Auth Certificate required or explicitly desired? $($configureNextAuthRequired)")
                Write-Verbose ("Import of the next Auth Certificate required? $($importNextAuthCertificateRequired)")
                Write-Verbose ("Hybrid Configuration detected? $($null -ne $hybridConfiguration)")
                Write-Verbose ("Stop processing due to hybrid? $($stopProcessingDueToHybrid)")
            } else {
                Write-Verbose ("Unable to reach the following Exchange Servers: $([string]::Join(", ", $exchangeServersUnreachableList))")
                Write-Verbose ("No renewal action will be performed as we can't for sure validate the Auth Certificate state on the offline servers")
            }
        } else {
            Write-Verbose ("Unable to query AuthConfig - therefore no action will be executed")
        }
    } end {
        return [PSCustomObject]@{
            CurrentAuthCertificateThumbprint     = $authConfiguration.CurrentCertificateThumbprint
            CurrentAuthCertificateLifetimeInDays = $currentAuthCertificateValidInDays
            ReplaceRequired                      = $replaceRequired
            CurrentAuthCertificateImportRequired = $importCurrentAuthCertificateRequired
            NextAuthCertificateThumbprint        = $authConfiguration.NextCertificateThumbprint
            NextAuthCertificateLifetimeInDays    = $nextAuthCertificateValidInDays
            ConfigureNextAuthRequired            = $configureNextAuthRequired
            NextAuthCertificateImportRequired    = $importNextAuthCertificateRequired
            NumberOfUnreachableServers           = $exchangeServersUnreachableList.Count
            UnreachableServersList               = $exchangeServersUnreachableList
            AuthCertificateFoundOnServers        = $currentAuthCertificateFoundOnServersList
            AuthCertificateMissingOnServers      = $currentAuthCertificateMissingOnServersList
            NextAuthCertificateFoundOnServers    = $nextAuthCertificateFoundOnServersList
            NextAuthCertificateMissingOnServers  = $nextAuthCertificateMissingOnServersList
            HybridSetupDetected                  = ($null -ne $hybridConfiguration)
            StopProcessingDueToHybrid            = $stopProcessingDueToHybrid
            MultipleExchangeADSites              = $multipleExchangeSites
        }
    }
}


function Test-IsServerValidForAuthCertificateGeneration {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        Validates that the server on which the script runs is a mailbox server running Exchange major version 15 or greater
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $isValid = $false
        Write-Verbose ("Trying to query Exchange Server details")
        $exchangeServerDetails = Get-ExchangeServer -Identity $ComputerName -ErrorAction Stop

        if (($exchangeServerDetails.IsMailboxServer) -and
            (($exchangeServerDetails.AdminDisplayVersion -match "^Version 15"))) {
            Write-Verbose ("Exchange Server role and version is VALID to renew the Auth Certificate")
            $isValid = $true
        } else {
            Write-Verbose ("Exchange Server role or version is INVALID to renew the Auth Certificate")
        }
    } catch {
        Write-Verbose ("Unable to query Exchange Server details - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return $isValid
}

function Write-DebugLog($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Main {
    param()

    if (-not(Confirm-Administrator)) {
        Write-Warning ("The script must be executed in elevated mode. Start the Exchange Management Shell as an administrator.")
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    Invoke-ErrorMonitoring

    $versionsUrl = "https://aka.ms/MEAC-VersionsUrl"
    Write-Host ("Monitor Exchange Auth Certificate script version $($BuildVersion)") -ForegroundColor Green

    $currentErrors = $Error.Count

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl $versionsUrl -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and
        (Test-ScriptVersion -AutoUpdate -VersionsUrl $versionsUrl -Confirm:$false)) {
        Write-Host ("Script was updated. Please rerun the command") -ForegroundColor Yellow
        return
    }

    Invoke-ErrorCatchActionLoopFromIndex $currentErrors

    if ($PrepareADForAutomationOnly) {
        Write-Host ("Mode: Prepare AD account to run the script as scheduled task")
        $newAuthCertificateParamsAccountOnly = @{
            Password            = $Password
            DomainToUse         = $ADAccountDomain
            CatchActionFunction = ${Function:Invoke-CatchActions}
            WhatIf              = $WhatIfPreference
        }
        $adAccountSuccessfullyCreated = New-AuthCertificateManagementAccount @newAuthCertificateParamsAccountOnly

        if ($adAccountSuccessfullyCreated) {
            Write-Host ("Account: 'SM_ad0b1fe3a1a3' successfully created - please run the script as follows:") -ForegroundColor Green
            Write-Host ""
            Write-Host (".\MonitorExchangeAuthCertificate.ps1 -ConfigureScriptToRunViaScheduledTask -AutomationAccountCredential (Get-Credential)") -ForegroundColor Green
        } else {
            Write-Host ("Unable to prepare the Auth Certificate automation account - please check the verbose script log for more details") -ForegroundColor Yellow
        }
        return
    }

    $exchangeShell = Confirm-ExchangeShell -CatchActionFunction ${Function:Invoke-CatchActions}
    $exitScriptDueToShellRequirementsNotFullFilled = $false
    if (-not($exchangeShell.ShellLoaded)) {
        Write-Warning ("Unable to load Exchange Management Shell")
        $exitScriptDueToShellRequirementsNotFullFilled = $true
    } else {
        if ($exchangeShell.ToolsOnly) {
            Write-Warning ("The script must be run on an Exchange server")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.EdgeServer) {
            Write-Warning ("The script cannot be run on an Edge Transport server")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.RemoteShell) {
            Write-Warning ("Running the script via Remote Shell is not supported")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }

        if ($exchangeShell.Major -lt 15) {
            Write-Warning ("The script must be run on Exchange 2013 or higher")
            $exitScriptDueToShellRequirementsNotFullFilled = $true
        }
    }

    if ($exitScriptDueToShellRequirementsNotFullFilled) {
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    Set-ADServerSettings -ViewEntireForest $true
    $localServerFqdn = (([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName).ToLower()

    if ($ExportAuthCertificatesAsPfx) {
        Write-Host ("Mode: Export all Exchange Auth Certificates available on this system")

        if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
            Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
            return
        }

        $authCertificateExportParams = @{
            Password            = $Password
            CatchActionFunction = ${Function:Invoke-CatchActions}
            WhatIf              = $WhatIfPreference
        }

        $authCertificateExportStatusObject = Export-ExchangeAuthCertificate @authCertificateExportParams

        if ($authCertificateExportStatusObject.CertificatesAvailableToExport) {
            Write-Host ("There is/are $($authCertificateExportStatusObject.NumberOfCertificatesToExport) certificate(s) that could be exported")
            if ($authCertificateExportStatusObject.ExportSuccessful) {
                Write-Host ("All of them were successfully exported to the following directory: $($PSScriptRoot)") -ForegroundColor Green
            } else {
                Write-Host ("Some of the certificates couldn't be exported - please check the verbose log") -ForegroundColor Yellow
                Write-Host ("Thumbprints of the certificates that couldn't be exported:") -ForegroundColor Yellow
                Write-Host ("$([string]::Join(", ", $authCertificateExportStatusObject.UnableToExportCertificatesList))") -ForegroundColor Yellow
            }
        } else {
            Write-Host ("There are no Auth Certificates on the system that are available to export")
        }

        return
    }

    if ($TestEmailNotification) {
        Write-Host ("Mode: Test email notification feature")

        $sendEmailNotificationTestParams = @{
            To                  = $SendEmailNotificationTo
            Subject             = "[Test] An Exchange Auth Certificate maintenance action was performed"
            Importance          = "Low"
            Body                = "This is a test message sent by the MonitorExchangeAuthCertificate.ps1 script.<BR><B>No action is required!</B>"
            EwsServiceUrl       = (Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly).InternalUrl.AbsoluteUri
            BodyAsHtml          = $true
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }

        if ($TrustAllCertificates) {
            $sendEmailNotificationTestParams.Add("IgnoreCertificateMismatch", $true)
        }

        # Check for the last value as Send-EwsMailMessage returns the SendAndSaveCopy() result too (not sure how to suppress this yet)
        if (Send-EwsMailMessage @sendEmailNotificationTestParams) {
            Write-Host ("Please check if the test message was received by the following recipient(s): $($SendEmailNotificationTo)")
        } else {
            Write-Host ("We hit an exception while processing your test email message. Please check the log file") -ForegroundColor Yellow
            Write-Host ("`n$($Error[0].Exception.Message)") -ForegroundColor Red
        }
        return
    }

    if ($ConfigureScriptToRunViaScheduledTask) {
        Write-Host ("Mode: Configure monitoring script to run via scheduled task")

        if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
            Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
            return
        }

        try {
            try {
                $dcToUseAsConfigDC = (Get-ExchangeServer -Identity $env:COMPUTERNAME -Status -ErrorAction Stop).CurrentConfigDomainController
            } catch {
                $dcToUseAsConfigDC = Get-GlobalCatalogServer -CatchActionFunction ${Function:Invoke-CatchActions}
            }
            Write-Host ("We use the following Domain Controller: $($dcToUseAsConfigDC)")

            $buildExchangeAuthManagementAccountParams = @{
                DomainController    = $dcToUseAsConfigDC
                CatchActionFunction = ${Function:Invoke-CatchActions}
                WhatIf              = $WhatIfPreference
            }

            if ($null -ne $AutomationAccountCredential) {
                $buildExchangeAuthManagementAccountParams.Add("UseExistingAccount", $true)
                $buildExchangeAuthManagementAccountParams.Add("AccountCredentialObject", $AutomationAccountCredential)
            } elseif ($null -ne $Password) {
                $buildExchangeAuthManagementAccountParams.Add("PasswordToSet", $Password)
            } else {
                Write-Host ("Please provide a password for the automation account") -ForegroundColor Yellow
                Write-Host ("You can do so by using the '-Password' parameter or by using the '-AutomationAccountCredential' parameter") -ForegroundColor Yellow
                return
            }

            $adAccountInfo = Build-ExchangeAuthCertificateManagementAccount @buildExchangeAuthManagementAccountParams

            if ($null -ne $adAccountInfo) {
                Write-Host ("Account for automation was successfully created: $($adAccountInfo.UserPrincipalName)")
                $Username = $adAccountInfo.UserPrincipalName
                $Password = $adAccountInfo.Password

                $scriptInfo = Copy-ScriptToExchangeDirectory -CatchActionFunction ${Function:Invoke-CatchActions} -WhatIf:$WhatIfPreference
                if ($null -ne $scriptInfo) {
                    Write-Host ("Script: $($scriptInfo.ScriptName) was successfully copied over to: $($scriptInfo.WorkingDirectory)")
                    $registerSchTaskParams = @{
                        Username             = $Username
                        Password             = $Password
                        WorkingDirectory     = $scriptInfo.WorkingDirectory
                        ScriptName           = $scriptInfo.ScriptName
                        IgnoreOfflineServers = $IgnoreUnreachableServers
                        IgnoreHybridConfig   = $IgnoreHybridConfig
                        CatchActionFunction  = ${Function:Invoke-CatchActions}
                        WhatIf               = $WhatIfPreference
                    }

                    if ($null -ne $SendEmailNotificationTo) {
                        Write-Host ("We're trying to notify the following recipient(s): $($SendEmailNotificationTo)")
                        $registerSchTaskParams.Add("SendEmailNotificationTo", $SendEmailNotificationTo)

                        if ($TrustAllCertificates) {
                            Write-Host ("We trust all certificates when connecting to EWS service")
                            $registerSchTaskParams.Add("TrustAllCertificates", $true)
                        }
                    }

                    $schTaskResults = Register-AuthCertificateRenewalTask @registerSchTaskParams
                } else {
                    Write-Host ("We couldn't copy the script: $($scriptInfo.ScriptName) to: $($scriptInfo.WorkingDirectory)") -ForegroundColor Red
                }
            } else {
                Write-Host ("Something went wrong while preparing the automation account") -ForegroundColor Red
            }

            if ($schTaskResults) {
                Write-Host ("The scheduled task was created successfully") -ForegroundColor Green
            } else {
                Write-Host ("The scheduled task wasn't created - please check the verbose script log for more details") -ForegroundColor Red
            }
        } catch {
            Write-Verbose ("Exception: $($Error[0].Exception.Message)")
        }
        return
    }

    if ($ValidateAndRenewAuthCertificate) {
        Write-Host ("Mode: Testing and replacing or importing the Auth Certificate (if required)")
    } elseif ($EnforceNewAuthCertificateCreation) {
        Write-Host ("Mode: Enforce new next Auth Certificate creation")
    } else {
        Write-Host ("The script was run without parameter therefore, only a check of the Auth Certificate configuration is performed and no change will be made")
    }

    if ((Test-IsServerValidForAuthCertificateGeneration -CatchActionFunction ${Function:Invoke-CatchActions}) -eq $false) {
        Write-Host ("This server does not meet the requirements to run the script.") -ForegroundColor Yellow
        return
    }

    if ($null -ne $SendEmailNotificationTo) {
        $sendEmailNotificationParams = @{
            To                  = $SendEmailNotificationTo
            Subject             = "[Action required] An Exchange Auth Certificate maintenance action was performed"
            Importance          = "High"
            EwsServiceUrl       = (Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly).InternalUrl.AbsoluteUri
            BodyAsHtml          = $true
            CatchActionFunction = ${Function:Invoke-CatchActions}
        }

        $emailBodyBase = "On $(Get-Date) we performed an Exchange Auth Certificate maintenance action.<BR>" +
        "Due to your Exchange Server or organization configuration, manual actions may be required.<BR><BR>"
    }

    $authCertificateStatusParams = @{
        IgnoreUnreachableServers              = $IgnoreUnreachableServers
        IgnoreHybridSetup                     = $IgnoreHybridConfig
        EnforceNewNextAuthCertificateCreation = $EnforceNewAuthCertificateCreation
        CatchActionFunction                   = ${Function:Invoke-CatchActions}
    }
    $authCertStatus = Get-ExchangeAuthCertificateStatus @authCertificateStatusParams

    $noRenewalDueToUnreachableServers = (($authCertStatus.NumberOfUnreachableServers -gt 0) -and ($IgnoreUnreachableServers -eq $false))
    $stopProcessingDueToHybrid = $authCertStatus.StopProcessingDueToHybrid
    $renewalActionRequired = (($authCertStatus.ReplaceRequired) -or
        ($authCertStatus.ConfigureNextAuthRequired) -or
        ($authCertStatus.CurrentAuthCertificateImportRequired) -or
        ($authCertStatus.NextAuthCertificateImportRequired))

    if ($authCertStatus.ReplaceRequired) {
        $renewalActionWording = "The Auth Certificate in use must be replaced by a new one."
    } elseif ($authCertStatus.ConfigureNextAuthRequired) {
        $renewalActionWording = "The Auth Certificate configured as next Auth Certificate must be configured or replaced by a new one or is created on express request."
    } elseif (($authCertStatus.CurrentAuthCertificateImportRequired) -or
        ($authCertStatus.NextAuthCertificateImportRequired)) {
        $renewalActionWording = "The current or next Auth Certificate is missing on some servers and must be imported."
    } else {
        $renewalActionWording = "No renewal action is required"
    }

    if ($noRenewalDueToUnreachableServers) {
        Write-Host ("We couldn't validate if the Auth Certificate is properly configured because $($authCertStatus.NumberOfUnreachableServers) servers were unreachable.") -ForegroundColor Yellow
        Write-Host ("The unreachable servers are: $([string]::Join(", ", $authCertStatus.UnreachableServersList))") -ForegroundColor Yellow
    } elseif ($stopProcessingDueToHybrid) {
        Write-Host ("We have not made any configuration change because Exchange Hybrid has been detected in your environment.") -ForegroundColor Yellow
        Write-Host ("Please rerun the script using the '-IgnoreHybridConfig `$true' parameter to perform the renewal action.") -ForegroundColor Yellow
        Write-Host ("It's also required to run the Hybrid Configuration Wizard (HCW) after the primary Auth Certificate was replaced.") -ForegroundColor Yellow
    } else {
        if (($ValidateAndRenewAuthCertificate -or
                $EnforceNewAuthCertificateCreation) -and
            ($renewalActionRequired)) {
            Write-Host ("Renewal scenario: $($renewalActionWording)")
            if ($authCertStatus.ReplaceRequired) {
                $replaceExpiredAuthCertificateParams = @{
                    ReplaceExpiredAuthCertificate    = $true
                    NewAuthCertificateLifetimeInDays = $CustomCertificateLifetimeInDays
                    CatchActionFunction              = ${Function:Invoke-CatchActions}
                    WhatIf                           = $WhatIfPreference
                }
                $renewalActionResult = New-ExchangeAuthCertificate @replaceExpiredAuthCertificateParams

                $emailBodyRenewalScenario = "The Auth Certificate in use was invalid (expired) or not available on all Exchange Servers within your organization.<BR>" +
                "It was immediately replaced by a new one which is already active.<BR><BR>"
            } elseif ($authCertStatus.ConfigureNextAuthRequired) {
                # Set CurrentAuthCertificateLifetimeInDays to 2 in case that EnforceNewAuthCertificateCreation was used
                # We do that to ensure that the new Auth Certificate will become active next time the AuthAdmin servicelet processes it
                $configureNextAuthCertificateParams = @{
                    ConfigureNextAuthCertificate         = $true
                    NewAuthCertificateLifetimeInDays     = $CustomCertificateLifetimeInDays
                    CurrentAuthCertificateLifetimeInDays = if ($EnforceNewAuthCertificateCreation) { 2 } else { $authCertStatus.CurrentAuthCertificateLifetimeInDays }
                    CatchActionFunction                  = ${Function:Invoke-CatchActions}
                    WhatIf                               = $WhatIfPreference
                }
                $renewalActionResult = New-ExchangeAuthCertificate @configureNextAuthCertificateParams

                $emailBodyRenewalScenario = "The new Auth Certificate will replace the current one on: <B>$($renewalActionResult.AuthCertificateActivationDate)</B>, " +
                "as soon as the AuthAdmin servicelet runs the next time (from the mentioned date within 12 hours).<BR><BR>"
            } elseif (($authCertStatus.CurrentAuthCertificateImportRequired) -or
                ($authCertStatus.NextAuthCertificateImportRequired)) {

                if ($authCertStatus.CurrentAuthCertificateImportRequired) {
                    $importCurrentAuthCertificateParams = @{
                        Thumbprint          = $authCertStatus.CurrentAuthCertificateThumbprint
                        ServersToImportList = $authCertStatus.AuthCertificateMissingOnServers
                        CatchActionFunction = ${Function:Invoke-CatchActions}
                        WhatIf              = $WhatIfPreference
                    }

                    if ($authCertStatus.AuthCertificateMissingOnServers.ToLower().Contains($localServerFqdn)) {
                        Write-Verbose ("Current Auth Certificate can't be exported from the local system - must be exported from another server")
                        $importCurrentAuthCertificateParams.Add("ExportFromServer", $authCertStatus.AuthCertificateFoundOnServers[0])
                    }
                    $importCurrentAuthCertificateResults = Import-ExchangeAuthCertificateToServers @importCurrentAuthCertificateParams

                    $emailBodyImportCurrentAuthCertificateResult = "The current Auth Certificate is valid but was missing on some servers.<BR>" +
                    "It was imported to the following server(s): <B>$([string]::Join(", ", $importCurrentAuthCertificateResults.ImportedToServersList))</B><BR><BR>"

                    if ($importCurrentAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                        $emailBodyImportCurrentAuthCertificateResult += "We failed to import it to the following servers: <B>$([string]::Join(", ", $importCurrentAuthCertificateResults.ImportToServersFailedList))</B><BR>" +
                        "Please export the Auth Certificate manually and import it on these Exchange server(s).<BR><BR>"
                    }
                }

                if ($authCertStatus.NextAuthCertificateImportRequired) {
                    $importNextAuthCertificateParams = @{
                        Thumbprint          = $authCertStatus.NextAuthCertificateThumbprint
                        ServersToImportList = $authCertStatus.NextAuthCertificateMissingOnServers
                        CatchActionFunction = ${Function:Invoke-CatchActions}
                        WhatIf              = $WhatIfPreference
                    }

                    if ($authCertStatus.NextAuthCertificateMissingOnServers.ToLower().Contains($localServerFqdn)) {
                        Write-Verbose ("Next Auth Certificate can't be exported from the local system - must be exported from another server")
                        $importNextAuthCertificateParams.Add("ExportFromServer", $authCertStatus.NextAuthCertificateFoundOnServers[0])
                    }
                    $importNextAuthCertificateResults = Import-ExchangeAuthCertificateToServers @importNextAuthCertificateParams

                    $emailBodyImportNextAuthCertificateResult = "The next Auth Certificate is valid but was missing on some servers.<BR>" +
                    "It was imported to the following server(s): <B>$([string]::Join(", ", $importNextAuthCertificateResults.ImportedToServersList))</B><BR><BR>"

                    if ($importNextAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                        $emailBodyImportNextAuthCertificateResult += "We failed to import it to the following servers: <B>$([string]::Join(", ", $importNextAuthCertificateResults.ImportToServersFailedList))</B><BR>" +
                        "Please export the next Auth Certificate manually and import it on these Exchange server(s).<BR><BR>"
                    }
                }
            }

            if ($authCertStatus.HybridSetupDetected) {
                $emailBodyHybrid = "Please ensure to run the Hybrid Configuration Wizard (HCW) as soon as the new Auth Certificate replaces the active one."
            }

            if ($renewalActionResult.RenewalActionPerformed) {
                $emailBodyRenewalAction = "New Exchange Auth Certificate thumbprint: <B>$($renewalActionResult.NewCertificateThumbprint)</B><BR>" +
                $emailBodyRenewalScenario
            }

            if ($authCertStatus.MultipleExchangeADSites) {
                $emailBodyMultiADSites = "Please validate that the newly created Auth Certificate was successfully replicated to all Exchange Servers (except Edge Transport) " +
                "which are located in another Active-Directory site.<BR>" +
                "You can do so by running the following command against one Exchange Server per AD site:<BR><BR>" +
                "Get-ExchangeCertificate -Server 'ServerName' -Thumbprint $($renewalActionResult.NewCertificateThumbprint)<BR><BR>" +
                "If you run the script again, it will try to import the newly created certificate to all servers where it's missing.<BR><BR>" +
                "However, if you still find that the Auth Certificate is missing on a server in a different AD site, please follow these steps:<BR><BR>" +
                "1. Export the Auth Certificate: .\MonitorExchangeAuthCertificate.ps1 -ExportAuthCertificatesAsPfx<BR>" +
                "2. Import it to the Computer Accounts 'Personal' certificate store on an Exchange Server per other AD site<BR><BR>" +
                "The Auth Certificate will then be automatically replicated to all Exchange Servers within this AD site.<BR><BR>"
            }

            $emailBodyFailure = "We ran into an issue while trying to renew the Exchange Auth Certificate. Please check the verbose script log for more details.<BR>" +
            "You can find it under: '$($Script:Logger.FullPath)' on computer: $($env:COMPUTERNAME)"

            if (($renewalActionResult.RenewalActionPerformed) -and
                ($authCertStatus.HybridSetupDetected -eq $false)) {
                if ($null -ne $emailBodyBase) {
                    if ($authCertStatus.MultipleExchangeADSites) {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyMultiADSites
                    } else {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + "No further action is required on your part."
                    }
                }
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed") -ForegroundColor Green
            } elseif (($renewalActionResult.RenewalActionPerformed) -and
                ($authCertStatus.HybridSetupDetected)) {
                if ($null -ne $emailBodyBase) {
                    if ($authCertStatus.MultipleExchangeADSites) {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyMultiADSites + $emailBodyHybrid
                    } else {
                        $finalEmailBody = $emailBodyBase + $emailBodyRenewalAction + $emailBodyHybrid
                    }
                }
                Write-Host ("")
                Write-Host ("The renewal action was successfully performed - the new Auth Certificate will become active on: $($renewalActionResult.AuthCertificateActivationDate)") -ForegroundColor Green
                Write-Host ("Please ensure to run the Hybrid Configuration Wizard (HCW) as soon as the new Auth Certificate becomes active.") -ForegroundColor Green
            } elseif (($null -ne $importCurrentAuthCertificateResults) -or
                ($null -ne $importNextAuthCertificateResults)) {
                $importFailedAppendixWording = (
                    "Our approach to automatically import the certificate failed." +
                    "`r`nPlease export the Auth Certificate manually and import it to the Exchange servers where it's missing." +
                    "`r`nIt's sufficient to import it to at least one Exchange server per AD site." +
                    "`r`nIt will then be automatically deployed to all Exchange servers within that particular AD site."
                )
                $importTriedWording = "`r`nWe've tried to import it to those Exchange servers and this is the result:"
                $importFailedWording = "Import failed: {0}"
                $importSuccessfulWording = "Import successful: {0}"

                if ($null -ne $importCurrentAuthCertificateResults) {
                    Write-Host ("")
                    if ($null -ne $emailBodyBase) {
                        $finalEmailBody = $emailBodyBase + $emailBodyImportCurrentAuthCertificateResult
                    }

                    Write-Host ("The current Auth Certificate: $($authCertStatus.CurrentAuthCertificateThumbprint) is valid but missing on the following server(s):") -ForegroundColor Yellow
                    Write-Host ([string]::Join(", ", $authCertStatus.AuthCertificateMissingOnServers)) -ForegroundColor Yellow
                    if ($importCurrentAuthCertificateResults.ExportSuccessful) {
                        Write-Host ($importTriedWording)
                        if ($importCurrentAuthCertificateResults.ImportedToServersList.Count -gt 0) {
                            Write-Host ($importSuccessfulWording -f [string]::Join(", ", $importCurrentAuthCertificateResults.ImportedToServersList)) -ForegroundColor Green
                        }

                        if ($importCurrentAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                            Write-Host ($importFailedWording -f [string]::Join(", ", $importCurrentAuthCertificateResults.ImportToServersFailedList)) -ForegroundColor Yellow
                            Write-Host ($importFailedAppendixWording) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host $importFailedAppendixWording -ForegroundColor Yellow
                    }
                }

                if ($null -ne $importNextAuthCertificateResults) {
                    Write-Host ("")
                    if (($null -ne $emailBodyBase) -and
                        ($null -eq $finalEmailBody)) {
                        # No email content available as the current Auth Certificate wasn't imported before
                        $finalEmailBody = $emailBodyBase + $emailBodyImportNextAuthCertificateResult
                    } elseif (($null -ne $emailBodyBase) -and
                        ($null -ne $finalEmailBody)) {
                        # Email content available as the current Auth Certificate was imported too
                        $finalEmailBody = $finalEmailBody + $emailBodyImportNextAuthCertificateResult
                    }

                    Write-Host ("The next Auth Certificate: $($authCertStatus.NextAuthCertificateThumbprint) is valid but missing on the following server(s):") -ForegroundColor Yellow
                    Write-Host ([string]::Join(", ", $authCertStatus.NextAuthCertificateMissingOnServers)) -ForegroundColor Yellow
                    if ($importNextAuthCertificateResults.ExportSuccessful) {
                        Write-Host ($importTriedWording)
                        if ($importNextAuthCertificateResults.ImportedToServersList.Count -gt 0) {
                            Write-Host ($importSuccessfulWording -f [string]::Join(", ", $importNextAuthCertificateResults.ImportedToServersList)) -ForegroundColor Green
                        }

                        if ($importNextAuthCertificateResults.ImportToServersFailedList.Count -gt 0) {
                            Write-Host ($importFailedWording -f [string]::Join(", ", $importNextAuthCertificateResults.ImportToServersFailedList)) -ForegroundColor Yellow
                            Write-Host ($importFailedAppendixWording) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host $exportFailedWording -ForegroundColor Yellow
                    }
                }
            } else {
                if ($null -ne $emailBodyBase) {
                    $finalEmailBody = $emailBodyBase + $emailBodyFailure
                }
                Write-Host ("")
                Write-Host ("There was an issue while performing the appropriate action - please check the verbose script log for more details.") -ForegroundColor Red
            }
        } else {
            Write-Host ""
            Write-Host ("Current Auth Certificate thumbprint: $($authCertStatus.CurrentAuthCertificateThumbprint)") -ForegroundColor Cyan
            Write-Host ("Current Auth Certificate is valid for $($authCertStatus.CurrentAuthCertificateLifetimeInDays) day(s)") -ForegroundColor Cyan
            if (-not([string]::IsNullOrEmpty($authCertStatus.NextAuthCertificateThumbprint))) {
                Write-Host ("Next Auth Certificate thumbprint: $($authCertStatus.NextAuthCertificateThumbprint)") -ForegroundColor Cyan
                Write-Host ("Next Auth Certificate is valid for $($authCertStatus.NextAuthCertificateLifetimeInDays) day(s)") -ForegroundColor Cyan
            }
            if ($authCertStatus.MultipleExchangeADSites) {
                Write-Host ("We've detected Exchange servers in multiple AD sites") -ForegroundColor Cyan
            }
            if ($authCertStatus.HybridSetupDetected) {
                Write-Host ("Exchange Hybrid was detected in this environment") -ForegroundColor Cyan
            }
            if ($authCertStatus.NumberOfUnreachableServers -gt 0) {
                Write-Host ("Number of unreachable Exchange servers: $($authCertStatus.NumberOfUnreachableServers)") -ForegroundColor Cyan
            }
            if ($authCertStatus.AuthCertificateMissingOnServers.Count -gt 0) {
                Write-Host ("`r`nThe actively used Auth Certificate is missing on the following servers:") -ForegroundColor Cyan
                Write-Host ("$([string]::Join(", ", $authCertStatus.AuthCertificateMissingOnServers))") -ForegroundColor Cyan
            }
            if ($authCertStatus.NextAuthCertificateMissingOnServers.Count -gt 0) {
                Write-Host ("`r`nThe certificate which is configured as next Auth Certificate is missing on the following servers:") -ForegroundColor Cyan
                Write-Host ("$([string]::Join(", ", $authCertStatus.NextAuthCertificateMissingOnServers))") -ForegroundColor Cyan
            }
            Write-Host ("")
            Write-Host ("Test result: $($renewalActionWording)") -ForegroundColor Cyan
            if ((($authCertStatus.AuthCertificateMissingOnServers.Count -gt 0) -and
                    ($authCertStatus.CurrentAuthCertificateImportRequired)) -or
                (($authCertStatus.NextAuthCertificateMissingOnServers.Count -gt 0) -and
                ($authCertStatus.NextAuthCertificateImportRequired))) {
                Write-Host ("`rThe script will try to import the certificate to the missing servers automatically (as long as it's valid).") -ForegroundColor Cyan
            }
        }

        if (($renewalActionRequired) -and
            ($renewalActionResult.RenewalActionPerformed) -and
            ($authCertStatus.MultipleExchangeADSites)) {
            $multipleExchangeADSitesWording = (
                "We've successfully created a new certificate which was then configured as Auth Certificate." +
                "`r`nThe new certificate has the following thumbprint: $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nWe've also detected that Exchange is installed in multiple Active Directory sites. In rare cases the Exchange certificate servicelet " +
                "will fail to deploy the certificate to the other AD sites. `r`nYou can validate that the certificate was deployed by running the following command " +
                "on an Exchange server located in a different AD site than this server:" +
                "`r`n`nGet-ExchangeCertificate -Server <ServerFqdn> -Thumbprint $($renewalActionResult.NewCertificateThumbprint)" +
                "`r`n`nIf you run the script again, it will try to import the certificate to the server(s) where it's missing." +
                "`r`nHowever, we recommend to wait for at least 24 hours to let Exchange Server perform the certificate replication task."
            )

            Write-Host ""
            Write-Host ($multipleExchangeADSitesWording) -ForegroundColor Yellow
        }

        if ((-not($WhatIfPreference)) -and
            (($renewalActionResult.RenewalActionPerformed) -or
            ($null -ne $importCurrentAuthCertificateResults) -or
            ($null -ne $importNextAuthCertificateResults)) -and
            (-not([System.String]::IsNullOrEmpty($SendEmailNotificationTo)))) {
            Write-Host ("`r`nTrying to send out email notification to the following recipients: $($SendEmailNotificationTo)")
            $sendEmailNotificationParams.Add("Body", $finalEmailBody)

            if ($TrustAllCertificates) {
                $sendEmailNotificationParams.Add("IgnoreCertificateMismatch", $true)
            }

            if (Send-EwsMailMessage @sendEmailNotificationParams) {
                Write-Host ("An email message was successfully sent")
            } else {
                Write-Host ("We ran into an issue while trying to notify you via email - please check the log of the script") -ForegroundColor Yellow
            }
        }
    }
}

try {
    $loggerParams = @{
        LogName        = "AuthCertificateMonitoringLog"
        LogDirectory   = (New-AuthCertificateMonitoringLogFolder -WhatIf:$WhatIfPreference)
        AppendDateTime = $true
        ErrorAction    = "SilentlyContinue"
    }

    if (-not($WhatIfPreference)) {
        $Script:Logger = Get-NewLoggerInstance @loggerParams
        SetProperForegroundColor
        SetWriteHostAction ${Function:Write-DebugLog}
        SetWriteVerboseAction ${Function:Write-DebugLog}
    }

    Main
} finally {
    Write-Host ""
    if (-not($WhatIfPreference)) {
        Write-Host ("Log file written to: $($Script:Logger.FullPath)")
    } else {
        Write-Host ("Script was executed by using '-WhatIf' parameter - no action was performed and no log file was generated")
    }
    Write-Host ""
    Write-Host ("Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com.") -ForegroundColor Green
    Write-Host ""

    if ($Error.Count -ne 0) {
        foreach ($e in (Get-UnhandledErrors)) {
            Write-Host ("Unhandled error hit:") -ForegroundColor Red
            Write-Host ($e.ErrorInformation) -ForegroundColor Red
        }
    } else {
        Write-Verbose ("No errors occurred within the script")
    }
    if (-not($WhatIfPreference)) {
        RevertProperForegroundColor
    }
}

# SIG # Begin signature block
# MIInSAYJKoZIhvcNAQcCoIInOTCCJzUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7PqxgDPwPFiDs
# /DI1g2KASIQPlq/IaV9tNdu6E8c7daCCDLowggX1MIID3aADAgECAhMzAAACHU0Z
# yE7XD1dIAAAAAAIdMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBD
# b2RlIFNpZ25pbmcgUENBIDIwMjQwHhcNMjYwNDE2MTg1OTQzWhcNMjcwNDE1MTg1
# OTQzWjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYD
# VQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDQvewXxx9gZZFC6Ys1WBay8BJ8kGA4JQnH5CMafqOASlTpK9H8
# o5ZXTXt0caVQTNMUPt445wXYD+dFtaKWTwDn1I52oUSrC9vJin1Gsqt+zyKJL5Dg
# 3eQXbQNR61DmMy20GLTIO3SFed9Rfi/ophgCLGFLDR3r0KvHjwMb/jYWS0celV/4
# Lz27LfAekm8v9E5IXaeiXbAUYZKK090n4CVl3JBtbN+9DtI9SNu/yjvozW52/u7R
# X/Ttpa/KDlpuokZ+Zcbvmtd9ur9gFLvZzh41o9MsE/clQtdaFWGvuo6Jua/ntpgk
# ey3E5/vBFe+MJPG6phdnuo6r57ZudCudiI1bAgMBAAGjggGbMIIBlzAOBgNVHQ8B
# Af8EBAMCB4AwHwYDVR0lBBgwFgYKKwYBBAGCN0wIAQYIKwYBBQUHAwMwHQYDVR0O
# BBYEFH6QuMwqcPG0hQlQ6c5jCtTTLrVeMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTIzMDAxMis1MDc1NTkw
# HwYDVR0jBBgwFoAUf1k/VCHarU/vBeXmo9ctBpQSCDEwYAYDVR0fBFkwVzBVoFOg
# UYZPaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDI0LmNybDBtBggrBgEFBQcBAQRh
# MF8wXQYIKwYBBQUHMAKGUWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y2VydHMvTWljcm9zb2Z0JTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDI0LmNy
# dDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBKTbYOjzwTG/DXGaz9
# s6+fQeaTtDcFmMY+5UyVFCyj7Pv+5i37qfX8lSL/tBIfYQfWsMuBQlfZurJD6r4H
# VJ2CeH+1fgiq8dcHdVKoZ3Sa2qXoX3cq9iS8cVb06B7+5/XJ7I0OxHH9fDsvJ3T3
# w5V/ZtAIFmLrl+P0CtG+92uzRsn0nTbdFjOkLMLWPLAU3THohKRlSEMgFJpPkm5n
# 5UAZ35xX6FWCrDLsSKb555bTifwa8mJBwdlof0bmfYidH+dxZ1FdDxvLnNl9zeKs
# A4kejaaIqqIPguhwAti5Ql7BlTNoJNwxCvBmqW2MQLnCkYN/VVUsR3V2x/rcTNzo
# Bf/Z/SpROvdaA2ZOOd1uioXJt3tdLQ7vHpqpib0KfWr/FWXW10q38VxfCnRQBqzb
# SuztR7nEMuzX7Ck+B/XaPDXd1qh72+QYyB0Z2VzWmO9zsnb9Uq/dwu8LGeQqnyu6
# 7SDGACvnXii2fb9+US492VTnXSnFKyqwgzUyFMtZK1/sHYTv6bG4TtQUygQxTN+Z
# V+aJIlKO2MqZ7bKrAnOzS9m6NgoTdWOq11bTOZwKlIEV/EhV9SWkDmdpR/hPPT2v
# 6TEj4F8PT/zHjRezIU5c/DGlt/VhY/pK0XkJtEyMmmS1BMtjU/rqBZVMIm3dnxQs
# /TBByr+Cf8Z1r7aifQVQ+WSqzjCCBr0wggSloAMCAQICEzMAAAA5O7Y3Gb8GHWcA
# AAAAADkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDExMB4XDTI0MDgwODIwNTQxOFoXDTM2MDMyMjIyMTMwNFow
# VzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEo
# MCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAyNDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBANgBnB7jOMeqlRYHNa265v4IY9fH8TKh
# emHfPINe1gpLaV3dhg324WwH06LcHbpnsBukCDNitryo0dtS/EW6I/yEL/bLSY8h
# KpbfQuWusBPr9qazYcDxCW/qnjb5JsI1s8bNOg3bVATvQVL4tcf03aTycsz8QeCd
# M0l/yHRObJ9QqazM1r6VPEOJ7LL+uEEb73w6QCuhs89a1uv1zerOYMnsneRRwCbp
# yW11IcggU0cRKDDq1pjVJzIbIF6+oiXXbReOsgeI8zu1FyQfK0fVkaya8SmVHQ/t
# Of23mZ4W9k0Ri22QW9p3UgSC5OUDktKxxcCmGL6tXLfOGSWHIIV4YrTJTT6PNty5
# REojHJuZHArkF9VnHTERWoTjAzfI3kP+5b4alUdhgAZ7ttOu1bVnXfHaqPYl2rPs
# 20ji03LOVWsh/radgE17es5hL+t6lV0eVHrVhsssROWJuz2MXMCt7iw7lFPG9LXK
# Gjsmonn2gotGdHIuEg5JnJMJVmixd5LRlkmgYRZKzhxSCwyoGIq0PhaA7Y+VPct5
# pCHkijcIIDm0nlkK+0KyepolcqGm0T/GYQRMhHJlGOOmVQop36wUVUYklUy++vDW
# eEgEo4s7hxN6mIbf2MSIQ/iIfMZgJxC69oukMUXCrOC3SkE/xIkgpfl22MM1itkZ
# 35nNXkMolU1lAgMBAAGjggFOMIIBSjAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGC
# NxUBBAMCAQAwHQYDVR0OBBYEFH9ZP1Qh2q1P7wXl5qPXLQaUEggxMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# ci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAx
# MV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAx
# MV8yMDExXzAzXzIyLmNydDANBgkqhkiG9w0BAQwFAAOCAgEAFJQfOChP7onn6fLI
# MKrSlN1WYKwDFgAddymOUO3FrM8d7B/W/iQ6DxXsDn7D5W4wMwYeLystcEqfkjz4
# NURRgazyMu5yRzQh4LqjA4tStTcJh1opExo7nn5PuPBYnbu0+THSuVHTe0VTTPVh
# ily/piFrDo3axQ9P4C+Ol5yet+2gTfekICS5xS+cYfSIvgn0JksVBVMYVI5QFu/q
# hnLhsEFEUzG8fvv0hjgkO+lkpV9ty6GkN4vdnd7ya6Q6aR9y34aiM1qmxaxBi6OU
# nyNl6fkuun/diTFnYDLTppOkr/mg5WSfCiDVMNCxtj4wPKC5OmHm1DQIt/MNokbb
# H3UGsFP1QbzsLocuSqLCvH09Io3fDPTmscR9Y75G4qX7RTX8AdBPo0I6OEojf39z
# uFZt0qOHm65YWQE69cZM2ueE1MB05dNNgHK9gTE7zKvK/fg8B2qjW88MT/WF5V5u
# vZGtqa9FSL2RazArA+rDPuf6JGYz4HpgMZHB4S6szWSKYBv0VisCzfxgeU+dquXW
# 9bd0auYlOB58DPcOYKdc3Se94g+xL4pcEhbB54JOgAkwYTu/9dLeH2pDqeJZAABV
# DWRQCaXfO5LgyKwKCLYXpigrZYCjUSBcr+Ve8PFWMhVTQl0v4q8J/AUmQN5W4n10
# 1cY2L4A7GTQG1h32HHAvfQESWP0xghnkMIIZ4AIBATBuMFcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jv
# c29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMjQCEzMAAAIdTRnITtcPV0gAAAAAAh0w
# DQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPlT+5gS
# B9XerB4PKOs8gT43kFZVSlQGnXOK7Q2xKOSqMEIGCisGAQQBgjcCAQwxNDAyoBSA
# EgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20w
# DQYJKoZIhvcNAQEBBQAEggEASSTLGP5uG7zRI8DkiZUoD9qtExqGBUPgMwR7SpB/
# npqu3fqBz/vo5Rv4ZgtNSDD/KrdZ8NBydkrrlT/z3nsZmZDpKEWNc3JwdXhixh6Y
# UFN1qSY9S6tYVQWuuErWkhBVvpXIUA31q2KgpPAiNhiAzj4/r4WC3gdhiAvQDOP1
# BYXyWi1BVuLDgJ4+lY+kdEdIDrfNZUL0yugbVMJ1GHqwslGPYnG2RR0msMagbdOT
# uULzi+sEtFUwQQ+zlkM6zbXM3cF7ZCWY5hoWEmLrN11X4oOgYJspbLPzFYPNi/Md
# YqSx1JKGhonkvDP9KGsa4sSdSx9VdstQRsM+rccbmedURaGCF5YwgheSBgorBgEE
# AYI3AwMBMYIXgjCCF34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoD
# ATAxMA0GCWCGSAFlAwQCAQUABCAXlyciOwBN0wbqk/gGhT7qqhs9FcLvisGD2YZA
# pstEJQIGagxCaGwTGBMyMDI2MDUxOTE1MDYxMC4yMzFaMASAAgH0oIHRpIHOMIHL
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRT
# UyBFU046QTQwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghHsMIIHIDCCBQigAwIBAgITMwAAAijwpYfX88geQAABAAAC
# KDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yNjAyMTkxOTQwMDZaFw0yNzA1MTcxOTQwMDZaMIHLMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0wNUUw
# LUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCujvbk/sqcCSReZaJfCuf1NwRc
# c7XknhE6wkLofkNj1mxEAg35qy2xcFjgjartVvA09W8QHcpyMqVSXOTxNHJsmk0q
# P2CDLvUAulWg7aS5oBORpEX1oz3n0R2nPqeH0IHK1zJxjxaHW21AbuZ0Z+wM3WYN
# zkBlcHmVe03ZG7rlk28h72r5P5ME8FGpFmYW5Hl7psKbgLEfrYAitpttsb+sZsBU
# I+hMKl4uLJYotKyZv1ewOIinBfRU8QosivjofaBezUf9NdV+iGrWh321WnSsK3A/
# Jl6GLtbSWXcJWULgbxuqnobPK+YlB3174TMWTgX4YWjG7o0Otz/pjHNCKBbB788d
# ynhLdGY6B08E9+4SGrRpsty4iJHOydHCA5M4i5yYRwsdut+gmvxIpT8yNXJcjJCg
# 0vO8mv/nFY9Wytv2qmCtCFFivGUWqU20/sUeRooQZGiQOJQn095Cj3isIsvRP8KU
# 7hN/EDI8HVsb/NPzMFLvRznrRnj0TOnDiOTUcnYwmk+XfoS1owskcCCCwHnbC00D
# 58z83y7K5ZJB745hcn4CE2nR3e6RGsr42y5qtt6Mdz/s7MTnDS2UmVHWX1X/HZe3
# UlX8gj/t63L50xIPqkRCBEdM1ADNUaSfo9OQiKb/bj1diZCGTfEDUBBLop1mhkwI
# F82faplV2busZ+U4kQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFKrJpYz48tzouvVk
# BVthASFpQ93DMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1Ud
# HwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3Js
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggr
# BgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIw
# MTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# DgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCQ6NfLmrRahgVtgWg3
# 83GaS07fHyod6bhcUONt2tet+6BaNuH0r7ABkVHheOpxBdrUrOEYVEaIii9dK3cu
# ZLNmp1iUAx/VbmOZYl7xz+tNrjCWqrg1jQmq0oRB8iE4QJpwNhGP67oY5huYIU0D
# 4lhDoahqfgKJn/0Bk+9UKDPw5XlUYmreFmJlj9YQzcPPep8MxBXxh/Y5I7vQeRaW
# 5SjtiLQOLRk3ggvraDs5Sf49MJV6/BwxXC2rvUfEFX6SUDooqKIE9NgVIRq0RZu7
# Ot0i0Is+HvPP0hB6KwOxMg1SWKOfTtFpWpdo8MJvgKCHkPpXEzgprP+pyIHuO7gV
# RlSTsbYBFLh2yId/itM4uYL0R+2SSBBTpSSRthrGuEmElI5BCHMxzMg/oqHSPwZA
# IAkM2C4xxi0St7qMuA+m+ZzFYkfoF41QoSJn+HjqhqWYQ0m/SO9/KnJRJJUwMd5T
# iMnjZ+E/DJiUry5udiWyQpvfj2hQFI0djhahoAXDazeEciLF2uEnTur9UfjcwOun
# /oMY+ULftnOi2jKLMrreV097akzz/JxpnDgYJU/tgU7fQflg7IqiL9+0276+joQH
# o21mVeY5YD8Kh/kUaY6Jm/OTM88G7evTz/qnRumxovTjMStvpbAHNRhmSTdIPTV3
# 2CyuxDKS/V5a5iwA+f9ViBo+wjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkA
# AAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVow
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX
# 9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1q
# UoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8d
# q6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byN
# pOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2k
# rnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4d
# Pf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgS
# Uei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8
# QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6Cm
# gyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzF
# ER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQID
# AQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU
# KqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1
# GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbL
# j+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
# Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwU
# tj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN
# 3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU
# 5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5
# KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGy
# qVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB6
# 2FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltE
# AY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFp
# AUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcd
# FYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRb
# atGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQd
# VTNYs6FwZvKhggNPMIICNwIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE0MDAtMDVFMC1E
# OTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQB1rbmFkzS7qAK1Oav08AUnhbNIUqCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7bbA4jAiGA8y
# MDI2MDUxOTEwNTg0MloYDzIwMjYwNTIwMTA1ODQyWjB2MDwGCisGAQQBhFkKBAEx
# LjAsMAoCBQDttsDiAgEAMAkCAQACAV8CAf8wBwIBAAICEn0wCgIFAO24EmICAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEADF6cTrs+3Zo30djK7gV5uNCk4Il1
# 1axTq+S4QDjWqS9bkgebI+8z/Drt/4HbLDwxBB9sYG38yXaoEqaMYmquaU6l/pzu
# X8OLFbEODVJcJHdXYIqbAQRxdH57k2matiMLft9yMIraeLHrtn/Fcr9Wox7CuMie
# mHWSg8S0drLRQApUps2pLetrx86c7/J/biTQeS7OWHuPhVsa1XRyBLl2DWvDElcr
# zdhxxR3kvg+/6yUiQMOS9BscKcrlumLIQYDMo1HGL3TRXYiWgsHFevtqqyvuRleV
# V0FQzpsMXCgcWhf5HbndsXOXPghn2HcW1VR2lyFpw5dTgNrn0CRVHv3CczGCBA0w
# ggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAACKPCl
# h9fzyB5AAAEAAAIoMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIDo/d6S5hB+gJt2vLc4voduP9FqA
# oanfXv5seFzGyf3AMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgVbGKRlFg
# Y1/igRVkrV5Pjkf7cZDf+rFXvlXC4G36ItcwgZgwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAijwpYfX88geQAABAAACKDAiBCCOxU9iiesR
# QVlmfbbYlw24KneXeQgYg89JAe/WSuP/GDANBgkqhkiG9w0BAQsFAASCAgCEC+pv
# 7l14xBld/Zb45SUh66JmPoYnYxO3/R6yHQBcMFf5U4x+gn1sfkWtIN3y/qXgLV9u
# Yh7R1xj4sayTtxsr+5LO7L1TG992m2lIYDndbqaX0GVKs8ixr9iK7eBW0oKvT5W1
# 1lVsV+5tuP1FMKVZ9dO81bIdWRR4mFZU4KG3+NKwTE6HsoqEiTK5VnRRWvr7nd2Y
# w/t2Vd297Q2TmuRaaY8EHB3DI/0Ah4BTsba2p9AriG2hLoQHwC2dyyODVel9HNBV
# CLpyOrmIlUS7qn6VvAaZLwXuELYobb0mIAjOjK0+WYcMgXkdB0dhwY46wAST/AzM
# Dbjkb4ogydRQ58BXvzdcM8K868MpfvsEpSql6HyzIBJf8UDHD2BAEqq82lsMtbUO
# wVYqTHNwPWP5AroK4id7doXJP3H+bo6/SlZ3VWEXvMbW7qVWhkizj05ENKYB2Er7
# VWtuDISe6zV7QbsAGV785JPNsjzYyL29DGdcmUTG6f7FpHrTRaGekKfIX2PKmjU9
# U8k57ZLxJuVQfrEjY4Zijvlkjac4o4Ak6e31Rnwbzhbl3aKcijg4j/EBl6lnyIUE
# UQ7Gd2VkznL4z+4bvureMC3KBczY5J/35x/Sfhw7KzaWsbY+7gMHrWdtB9y85yw+
# AlxXM0Yn4qpUgMuVnZWB6VS9DRPQo0QE8+7JSQ==
# SIG # End signature block
