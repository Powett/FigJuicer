
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
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$SessionName
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
    if (-not $Session -and -not $SessionName) {
        $SessionName = "localhost"
    }
    if ( $Session ) {
        $SessionName = $Session.ComputerName
    }

    # --------------- Get-BitLockerVolume Method ---------------    
    $Command = { 
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            Get-BitLockerVolume -ErrorAction Stop
        }
        catch {
            Write-Host "[$ComputerName][-] Get-BitLockerVolume method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName][-] Reason: $_"
        }
    }
    
    
    $Volumes = if ($Session) {
        Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $SessionName -ScriptBlock $Command
    }
    else {
        & $Command $VerbosePreference $SessionName
    }


    $Volumes | ForEach-Object {
        if ($_.ProtectionStatus -eq "Off" -or -not ($_.VolumeStatus -eq "FullyEncrypted")) {
            Write-Host "[$($SessionName)][-] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Red
            Write-Output "[$($SessionName)][-] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)"
        }
        else {
            Write-Host "[$($SessionName)][+] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Green
            Write-Output "[$($SessionName)][+] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)"
        }
    }
    if ($Volumes) {
        return $Volumes
    }
    Write-Verbose  "[$($SessionName)][*] Falling back to WMI Method"
    
    # --------------- Fallback WMI Method ---------------
    $Command = { 
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction Stop
        }
        catch {
            Write-Host "[$ComputerName][-] WMI method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName][-] Reason: $_"
        }
    }
    $Volumes = if ($Session) {
        Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $SessionName -ScriptBlock $Command
    }
    else {
        & $Command $VerbosePreference $SessionName
    }

    $Volumes | ForEach-Object {
        $EncMethodKey = [int]$_.EncryptionMethod
        $EncMethod = if ($EnumMap.ContainsKey($EncMethodKey)) {
            $EnumMap[$EncMethodKey]
        }
        else {
            "Unknown ($EncMethodKey)"
        }
        if ($_.ProtectionStatus -eq 0 -or -not ($_.ConversionStatus -eq 1)) {
            Write-Output "[$($SessionName)][-] WMI check: $($_.DriveLetter) conversion status: $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)"
            Write-Host "[$($SessionName)][-] WMI check: $($_.DriveLetter) conversion status $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Red
        }
        else {
            Write-Output "[$($SessionName)][+] WMI check: $($_.DriveLetter) conversion status: $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)"
            Write-Host "[$($SessionName)][+] WMI check: $($_.DriveLetter) conversion status $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Green        
        }
    }
    if ($Volumes) {
        return $Volumes
    }   
    Write-Host  "[$($SessionName)][-] BitLocker likely disabled" -ForegroundColor Red
    Write-Output "[$($SessionName)][-] BitLocker likely disabled"
}