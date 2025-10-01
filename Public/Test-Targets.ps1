# Function performing specified test(s) on provided IPs in a concurrent manner
# Expects list of single IPv4, one per line
# See Get-TargetList.ps1 to obtain such a list from more complex inputs
# Developped by Powett
# Distributed under MIT License https://opensource.org/license/mit

# Example usage
# $Targets = Get-Content -Path $OutputIpFile
# Test-Targets -Targets $Targets -OutputFile $OutputFile -Credential $(Get-Credential) -Force

[CmdletBinding()]
param()


function Test-Targets {

    param (
        [string[]]$Targets = $null,
        [string]$TargetsFile = $null,
        [Parameter(Mandatory = $true)] [string]$OutputFile,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [string]$DomainController,
        [switch]$Force,
        [switch]$UseSSL = $false,
        [string]$FailureFile = $null
    )

    Write-Verbose  "Targets: $Targets"
    Write-Verbose  "Targets file: $TargetsFile"
    Write-Verbose  "Output File: $OutputFile"
    Write-Verbose  "Username: $($Credential.UserName)"
    Write-Verbose "Domain Controller IP: $DomainController"
    Write-Verbose "Failure File: $FailureFile"

    if (-not $Targets -and (-not $TargetsFile -or -not (Test-Path $TargetsFile))) {
        Write-Error "Provide either a Targets array, either a valid TargetFile"
        return
    }

    if ($TargetsFile -and $Targets) {
        Write-Error "Provide only a Targets array or a valid TargetsFile"
        return
    }

    if ($TargetsFile -and -not $Targets) {
        $Targets = Get-Content $TargetsFile
    }

    if ((Test-Path $OutputFile) -and -not $Force) {
        Write-Warning "Output file '$OutputFile' already exists. Use -Force to overwrite."
        return $null
    }
    elseif ((Test-Path $OutputFile) -and $Force) {
        Write-Verbose  "Overwriting existing output file '$OutputFile'"
        Remove-Item $OutputFile -Force
    }

    if (-not $FailureFile) {
        $FailureFile = "$($OutputFile)_failure"
    }

    $Jobs = @{}
    $moduleInfo = Get-Module FigJuicer
    $moduleFolder = Split-Path -Path $moduleInfo.Path -Parent


    if ($DomainController) {
        # Create a specific job for the Domain parsing
        $Job = Start-Job -ArgumentList $DomainController, $Credential, $VerbosePreference, $moduleInfo.Path -ScriptBlock {
            param(
                [string]$DomainController,
                [PSCredential]$Credential,
                $vp,
                $mp
            )

            Import-Module $mp -Verbose:$false
            $VerbosePreference = $vp
            # Function logic here
            Write-Verbose  "[*] Domain Controller $DomainController - Connection..."
            try {
                Get-ADStatus -Credential $Credential -DomainController $DomainController
            }
            catch {
                Write-Warning  "[$DomainController][-] - Error"
                Write-Verbose  "[$DomainController][-] - Reason: $_"
            }
        }
        $Jobs["DC"] = @{
            Job    = $Job
            Target = "Domain"
        }
    }


    # Start jobs
    # CHANGE OPTIONS HERE
    $options = New-PSSessionOption
    $UseSSL = $false
    # $options = New-PSSessionOption -SkipCACheck -SkipCNCheck

    $totalCount = $Targets.Count
    $attemptedCount = 0
    $successCount = 0
    $percent = 0
    $Sessions = foreach ($Target in $Targets) {
        try {
            New-PSSession -ComputerName $Target -Credential $Credential -ErrorAction Stop -UseSSL:$UseSSL -SessionOption:$options    
            Write-Verbose "[$Target] Connected"
            $successCount++
        }
        catch {
            Write-Warning "[$Target][-] Failed to connect"
            Add-Content -Path $FailureFile -Value "$Target"
        }
        $attemptedCount++
        $percent = ($attemptedCount / $totalCount) * 100
        Write-Progress -Activity "Creating sessions" `
            -Status "Tried $attemptedCount/$totalCount sessions, successfully created $successCount/$totalCount sessions, failed $($attemptedCount-$successCount)/$totalCount" `
            -PercentComplete $percent
    }


    # Get script contents (workaround not to copy module remotely)
    $ScriptsTable = @{}
    $ScriptsFiles = Get-ChildItem -Path $moduleFolder/Public/Get-*.ps1
    foreach ($file in $ScriptsFiles) {
        Write-Verbose "[*] Scanning script file $($file.Name)" 
        $ScriptsTable[$file.Name] = Get-Content $file.FullName -Raw
    }

    foreach ($Session in $Sessions) {
        $Job = Invoke-Command -Session $Session -AsJob -ArgumentList $Session.ComputerName, $VerbosePreference, $ScriptsTable -ScriptBlock {
            param(
                $SessionName,
                $vp,
                $ScriptsTable
            )
            $VerbosePreference = $vp
            Write-Verbose "Got scripts: $ScriptsTable"
            foreach ($scriptName in $ScriptsTable.Keys) {
                Write-Verbose "[$SessionName][+] Loaded $scriptName"
                Invoke-Expression $ScriptsTable[$scriptName]
            }
            
            Write-Verbose  "[$SessionName][+] Connected"
            try {
                Write-Output "========== BitLocker check =========="
                Write-Verbose  "[$SessionName][*] BitLocker check"
                Get-BitLockerStatus -SessionName $SessionName
            }
            catch {
                Write-Warning  "[$SessionName][-] Error"
                Write-Verbose  "[$SessionName][-] Reason: $_"
            }
            try {
                Write-Output "========== AV check =========="
                Write-Verbose  "[$SessionName][+] AV check"
                Get-AVStatus -SessionName $SessionName
            }
            catch {
                Write-Warning  "[$SessionName][-] Error"
                Write-Verbose  "[$SessionName][-] Reason: $_"
            }
        }
        $Jobs[$Job.Id] = @{
            Job    = $Job
            Target = $Session.ComputerName
        }
    }
    
    # 5-minute timeout
    $Timeout = [TimeSpan]::FromMinutes(5)
    $CompletedCount = 0
    $TimedOutCount = 0
    $TotalJobs = $Jobs.Count
    
    Write-Host "[*] $TotalJobs remote jobs started, waiting for completion" -ForegroundColor Cyan
    while ($Jobs.Count -gt 0) {
        foreach ($entry in @($Jobs.Values)) {
            $job = $entry.Job
            $Target = $entry.Target
            $Elapsed = (Get-Date) - $job.PSBeginTime

            if ($job.State -eq 'Completed') {
                # Fetch results
                $Result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            
                # Append results to file immediately
                Add-Content -Path $OutputFile -Value "============================================================ $Target ============================================================"
                Add-Content -Path $OutputFile -Value $Result
                Add-Content -Path $OutputFile -Value ""  # Blank line separator

                Write-Host "[$Target][+] finished" -ForegroundColor Green
            
                # Cleanup
                Remove-Job -Job $job -Force
                $Jobs.Remove($job.Id)
                $CompletedCount++
            }
            elseif ($Elapsed -ge $Timeout) {
                # Timeout: kill job
                Stop-Job -Job $job -Force
                Remove-Job -Job $job -Force
                Write-Warning "[-][$Target] timed out after $($Timeout.TotalMinutes) minutes"


                Add-Content -Path $OutputFile -Value "============================================================ $Target ============================================================"
                Add-Content -Path $OutputFile -Value "[$Target] TIMED OUT"
                Add-Content -Path $OutputFile -Value ""  # Blank line separator

                $Jobs.Remove($job.Id)
                $CompletedCount++
                $TimedOutCount++
            }
        }
        $percent = ($CompletedCount / $TotalJobs) * 100
        Write-Progress -Activity "Processing remote jobs" `
            -Status "$CompletedCount of $TotalJobs completed" `
            -PercentComplete $percent
        Start-Sleep -Seconds 5
    }

    # Cleanup sessions
    if ($Sessions) {
        Remove-PSSession -Session $Sessions -ErrorAction SilentlyContinue
    }
    
    Write-Host "All jobs completed ($($CompletedCount-$TimedOutCount)) or timed out ($TimedOutCount).`nResults stored in $OutputFile" -ForegroundColor Cyan
}