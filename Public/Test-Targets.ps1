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
        [switch]$UseSSL=$false
    )

    Write-Verbose  "Targets: $Targets"
    Write-Verbose  "Targets file: $TargetsFile"
    Write-Verbose  "Output File: $OutputFile"
    Write-Verbose  "Username: $($Credential.UserName)"
    Write-Verbose "Domain Controller IP: $DomainController"

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

    $Jobs = @{}
    $moduleInfo = Get-Module FigJuicer

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
                Write-Warning  "[-] $DomainController - Error"
                Write-Verbose  "[-] $DomainController - Reason: $_"
            }
        }
        $Jobs["DC"] = @{
            Job    = $Job
            Target = "Domain"
        }
    }


    # Start a job per target
    foreach ($Target in $Targets) {
        Write-Verbose "Starting job for target $Target"
        $Job = Start-Job -ArgumentList $Target, $Credential, $VerbosePreference, $moduleInfo.Path -ScriptBlock {
            param(
                [string]$Target,
                [PSCredential]$Credential,
                $vp,
                $mp
            )

            Import-Module $mp -Verbose:$false
            $VerbosePreference = $vp
            # Function logic here
            Write-Verbose  "[*] $Target - Connection..."
            try {
                # CHANGE OPTIONS HERE
                $options = New-PSSessionOption
                $UseSSL = $false
                # $options = New-PSSessionOption -SkipCACheck -SkipCNCheck
                
                $Session = New-PSSession -ComputerName $Target -Credential $Credential -ErrorAction Stop -UseSSL:$UseSSL -SessionOption:$options
                Write-Verbose  "[+] $Target - Connected"
            }
            catch {
                Write-Warning "[$($Target)] Could not connect as $($Credential.UserName) on $($Target)"
                Write-Verbose "Options: UseSSL:$($UseSSL), Options:$($options)"
                Write-Verbose "Reason: $_"
                return
            }
            try {
                Write-Output "========== BitLocker check =========="
                Get-BitLockerStatus -Session $Session
                Write-Output "========== AV check =========="
                Get-AVStatus -Session $Session
            }
            catch {
                Write-Warning  "[-] $Target - Error"
                Write-Verbose  "[-] $Target - Reason: $_"
                Remove-PSSession $Session
            }
        }
        $Jobs[$Job.Id] = @{
            Job    = $Job
            Target = $Target
        }
    }

    # Monitor progress
    do {
        $RunningJobs = $Jobs.Keys | Where-Object { $Jobs[$_].Job.State -eq 'Running' }
        $FinishedJobs = $Jobs.Keys | Where-Object { $Jobs[$_].Job.State -in @('Completed', 'Failed', 'Stopped') }
        $Total = $Jobs.Count
        $Running = $RunningJobs.Count
        $Finished = $FinishedJobs.Count
        $Percent = $percent = [int](([Math]::Min(($Finished / $Total * 100), 100)))


        Write-Progress -Activity "Running jobs, one per target..." `
            -Status "$Finished of $Total complete, $Running Running..." `
            -PercentComplete $Percent

        Start-Sleep -Milliseconds 200
    } while ($Finished -lt $Total)

    Write-Progress -Activity "Running jobs, one per target..." -Completed


    foreach ($Entry in $Jobs.Values) {
        $Target = $Entry.Target
        $Job = $Entry.Job

        $Result = Receive-Job -Job $Job | Out-String
        Add-Content -Path $OutputFile -Value "============================================================ $Target ============================================================"
        Add-Content -Path $OutputFile -Value $Result
        Add-Content -Path $OutputFile -Value ""  # Blank line separator

        Remove-Job -Job $Job
    }

}