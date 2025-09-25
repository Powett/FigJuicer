
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
            Write-Host "[$ComputerName][-] Get-BitLockerVolume method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName][-] Reason: $_"
        }
    }
    
    $Volumes | ForEach-Object {
        if ($_.ProtectionStatus -eq "Off" -or -not ($_.VolumeStatus -eq "FullyEncrypted")) {
            Write-Host "[$($Session.ComputerName)][-] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Red
            Write-Output "[-] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)"
        }
        else {
            Write-Host "[$($Session.ComputerName)][+] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Green
            Write-Output "[+] Get-BitLockerVolume check: $($_.MountPoint) is $($_.VolumeStatus), method: $($_.EncryptionMethod), protection status: $($_.ProtectionStatus)"
        }
    }
    if ($Volumes) {
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
            Write-Host "[$ComputerName][-] WMI method failed" -ForegroundColor Yellow
            Write-Verbose  "[-] Reason: $_"
        }
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
            Write-Output "[$($Session.ComputerName)][-] WMI check: $($_.DriveLetter) conversion status: $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)"
            Write-Host "[-] WMI check: $($_.DriveLetter) conversion status $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Red
        }
        else {
            Write-Output "[$($Session.ComputerName)][+] WMI check: $($_.DriveLetter) conversion status: $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)"
            Write-Host "[+] WMI check: $($_.DriveLetter) conversion status $($_.ConversionStatus), method: $($EncMethod), protection status: $($_.ProtectionStatus)" -ForegroundColor Green        
        }
    }
    if ($Volumes) {
        return $Volumes
    }   
    Write-Host  "[$($Session.ComputerName)][-] BitLocker likely disabled" -ForegroundColor Red
    Write-Output  "[-] BitLocker likely disabled"
}