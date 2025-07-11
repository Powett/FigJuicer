
# Powershell script checking status of BitLocker through PSSession
# Developped by Powett
# Distributed under MIT License https://opensource.org/license/mit

# Example usage:
# Get-BitLockerStatus -Session $session | Format-Table -AutoSize


[CmdletBinding()]
param()
function Get-BitLockerStatus {
    # Helper to translate EncryptionMethod codes
    param (
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session
    )

    $EnumMap = @{
        0 = "None"
        1 = "AES 128 with Diffuser"
        2 = "AES 256 with Diffuser"
        3 = "AES 128"
        4 = "AES 256"
        5 = "Hardware Encryption"
        6 = "XTS AES 128"
        7 = "XTS AES 256"
    }
    # --------------- Get-BitLockerVolume Method ---------------
    $Volumes = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName { 
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            Get-BitLockerVolume -ErrorAction Stop
        }
        catch {
            Write-Warning  "[$ComputerName][-] Get-BitLockerVolume method failed"
            Write-Verbose  "[$ComputerName][-] Reason: $_"
        }
    }
    if ($Volumes) {
        foreach ($Vol in $Volumes) {
            $EncMethodKey = [int]$Vol.EncryptionMethod
            $EncMethod = if ($EnumMap.ContainsKey($EncMethodKey)) {
                $EnumMap[$EncMethodKey]
            }
            else {
                "Unknown ($EncMethodKey)"
            }
            [PSCustomObject]@{
                DriveLetter      = $Vol.MountPoint
                ProtectionStatus = switch ($Vol.ProtectionStatus) {
                    'Off' { 0 }
                    'On' { 1 }
                    default { 'Unknown' }
                }
                EncryptionMethod = $EncMethod
            }
        }
        return $Volumes
    }
    Write-Verbose  "[$($Session.ComputerName)][*] Falling back to WMI Method"
    
    # --------------- Fallback WMI Method ---------------
    $Volumes = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName { 
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction Stop
        }
        catch {
            Write-Warning  "[$ComputerName][-] WMI method failed"
            Write-Verbose  "[$ComputerName][-] Reason: $_"
        }
    }
    if ($Volumes) {
        foreach ($Vol in $Volumes) {
            $EncMethodKey = [int]$Vol.EncryptionMethod
            $EncMethod = if ($EnumMap.ContainsKey($EncMethodKey)) {
                $EnumMap[$EncMethodKey]
            }
            else {
                "Unknown ($EncMethodKey)"
            }
            [PSCustomObject]@{
                DriveLetter      = $Vol.DriveLetter
                ProtectionStatus = switch ($Vol.ProtectionStatus) {
                    0 { 'Off' }
                    1 { 'On' }
                    default { 'Unknown' }
                }
                EncryptionMethod = $EncMethod
            } | Format-Table
        }
        return $Volumes
    }
    Write-Host  "[$($Session.ComputerName)][-] BitLocker likely disabled" -ForegroundColor Red
    Write-Output  "[-] BitLocker likely disabled"
}