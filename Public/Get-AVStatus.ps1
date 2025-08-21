# Powershell script checking status of anti-virus or EDR solution
# Leverages following checks
# - WMI Namespace query
# - Security Provider registry key
# - Known processes
# - Known services
# - Known installed drivers
# Developped by Powett
# Distributed under MIT License https://opensource.org/license/mit


# Example usage:
# Get-AVStatus | Format-List

[CmdletBinding()]
param()
function Get-AVStatus {
    # Returns an object with detected AV info locally, including registry subkeys and driver detection
    # Helper to translate EncryptionMethod codes
    param (       
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session
    )
    $Result = [PSCustomObject]@{
        WMI_Method      = ""
        Registry_Method = ""
        Process_Method  = ""
        Service_Method  = ""
        Drivers_Method  = ""
    }

    # --------------- WMI Antivirus products ---------------
    Write-Host  "[$($Session.ComputerName)][*] WMI Method..." -ForegroundColor Cyan
    $AvWmi = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName {
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        }
        catch {
            Write-Host  "[$ComputerName] WMI Security method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName] Reason: $_"
        }
    }
    if ($AvWmi) {
        $AvWmi | ForEach-Object {
            Write-Host  "[$ComputerName][+] WMI check: found $($_.displayName)." -ForegroundColor Green
            Write-Output  "[+] WMI check: found $($_.displayName)."
        }
        $RESULT.WMI_Method = ($AvWmi | Select-Object -ExpandProperty displayName) -join "; "
    }

    # --------------- Registry Antivirus providers ---------------
    Write-Host  "[$($Session.ComputerName)][*] Registry Method..." -ForegroundColor Cyan
    $AvRegNames = @()
    $Subkeys = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName {
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\AV"
            Get-ChildItem -Path $RegPath -ErrorAction Stop
        }
        catch {
            Write-Host  "[$ComputerName] Registry method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName] Reason: $_"
        }
    }
    foreach ($Subkey in $Subkeys) {
        try {
            $DispName = (Get-ItemProperty -Path $Subkey.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            if ($DispName) { $AvRegNames += $DispName }
        }
        catch {}
    }
    if ($AvRegNames.Count) {
        $AvRegNames | ForEach-Object {
            Write-Host  "[$ComputerName][+] Registry check: found $_." -ForegroundColor Green
            Write-Output  "[+] Registry check: found $_."
        }
        $Result.Registry_Method = $AvRegNames -join "; "
    }

    # --------------- Known Antivirus processes running ---------------
    Write-Host  "[$($Session.ComputerName)][*] Process Method..." -ForegroundColor Cyan
    
    $AvProc = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName {
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp 
        try {
            $KnownProcPatterns = 'msmpeng|ekrn|avp|sophos|sentinel'
            Get-Process | Where-Object { $_.Name -match $KnownProcPatterns } -ErrorAction Stop
        }
        catch {
            Write-Host  "[$ComputerName] Known processes method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName] Reason: $_"

        }
    }
    if ($AvProc) {
        $AvProc | ForEach-Object {
            Write-Host  "[$($Session.ComputerName)][+] Process method: found $($_.Name)." -ForegroundColor Green
            Write-Output  "[+] Process method: found $($_.Name)."
        }
        $Result.Process_Method = ($AvProc | Select-Object -ExpandProperty Name) -join "; "
    }


    # --------------- Known Antivirus services running ---------------
    Write-Host  "[$($Session.ComputerName)][*] Services Method..." -ForegroundColor Cyan
    $AvSvc = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName {
        param(
            $vp,
            $ComputerName
        )
        $VerbosePreference = $vp
        try {
            $KnownSvcPatterns = 'Defend|ekrn|avp|sophos|sentinel'
            Get-Service | Where-Object { $_.Name -match $KnownSvcPatterns } -ErrorAction Stop
        }
        catch {
            Write-Host  "[$ComputerName] Known services method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName] Reason: $_"
        }
    }
    if ($AvSvc) {
        $AvSvc | ForEach-Object {
            Write-Host  "[$($Session.ComputerName)][+] Service method: found $($_.Name)."  -ForegroundColor Green
            Write-Output  "[+] Service method: found $($_.Name)." 
        }
        $Result.Service_Method = ($AvSvc | Select-Object -ExpandProperty DisplayName) -join "; "
    }

    # --------------- Driver detection ---------------
    Write-Host  "[*] Drivers method..." -ForegroundColor Cyan

    # Define known EDR drivers
    $Edrs = @{
        "atrsdfw.sys"          = "Altiris Symantec"
        "avgtpx86.sys"         = "AVG Technologies"
        "avgtpx64.sys"         = "AVG Technologies"
        "naswSP.sys"           = "Avast"
        "edrsensor.sys"        = "BitDefender SRL"
        "CarbonBlackK.sys"     = "Carbon Black"
        "parity.sys"           = "Carbon Black"
        "cbk7.sys"             = "Carbon Black"
        "cbstream"             = "Carbon Black"
        "csacentr.sys"         = "Cisco"
        "csaenh.sys"           = "Cisco"
        "csareg.sys"           = "Cisco"
        "csascr.sys"           = "Cisco"
        "csaav.sys"            = "Cisco"
        "csaam.sys"            = "Cisco"
        "rvsavd.sys"           = "CJSC Returnil Software"
        "cfrmd.sys"            = "Comodo Security"
        "cmdccav.sys"          = "Comodo Security"
        "cmdguard.sys"         = "Comodo Security"
        "CmdMnEfs.sys"         = "Comodo Security"
        "MyDLPMF.sys"          = "Comodo Security"
        "im.sys"               = "CrowdStrike"
        "csagent.sys"          = "CrowdStrike"
        "CybKernelTracker.sys" = "CyberArk Software"
        "CRExecPrev.sys"       = "Cybereason"
        "CyOptics.sys"         = "Cylance Inc."
        "CyProtectDrv32.sys"   = "Cylance Inc."
        "CyProtectDrv64.sys"   = "Cylance Inc."
        "groundling32.sys"     = "Dell Secureworks"
        "groundling64.sys"     = "Dell Secureworks"
        "esensor.sys"          = "Endgame"
        "edevmon.sys"          = "ESET"
        "ehdrv.sys"            = "ESET"
        "FeKern.sys"           = "FireEye"
        "WFP_MRT.sys"          = "FireEye"
        "xfsgk.sys"            = "F-Secure"
        "fsatp.sys"            = "F-Secure"
        "fshs.sys"             = "F-Secure"
        "HexisFSMonitor.sys"   = "Hexis Cyber Solutions"
        "klifks.sys"           = "Kaspersky"
        "klifaa.sys"           = "Kaspersky"
        "Klifsm.sys"           = "Kaspersky"
        "mbamwatchdog.sys"     = "Malwarebytes"
        "mfeaskm.sys"          = "McAfee"
        "mfencfilter.sys"      = "McAfee"
        "PSINPROC.SYS"         = "Panda Security"
        "PSINFILE.SYS"         = "Panda Security"
        "amfsm.sys"            = "Panda Security"
        "amm8660.sys"          = "Panda Security"
        "amm6460.sys"          = "Panda Security"
        "eaw.sys"              = "Raytheon Cyber Solutions"
        "SAFE-Agent.sys"       = "SAFE-Cyberdefense"
        "SentinelMonitor.sys"  = "SentinelOne"
        "SAVOnAccess.sys"      = "Sophos"
        "sld.sys"              = "Sophos"
        "pgpwdefs.sys"         = "Symantec"
        "GEProtection.sys"     = "Symantec"
        "diflt.sys"            = "Symantec"
        "sysMon.sys"           = "Symantec"
        "ssrfsf.sys"           = "Symantec"
        "emxdrv2.sys"          = "Symantec"
        "reghook.sys"          = "Symantec"
        "spbbcdrv.sys"         = "Symantec"
        "bhdrvx86.sys"         = "Symantec"
        "bhdrvx64.sys"         = "Symantec"
        "SISIPSFileFilter.sys" = "Symantec"
        "symevent.sys"         = "Symantec"
        "vxfsrep.sys"          = "Symantec"
        "VirtFile.sys"         = "Symantec"
        "SymAFR.sys"           = "Symantec"
        "symefasi.sys"         = "Symantec"
        "symefa.sys"           = "Symantec"
        "symefa64.sys"         = "Symantec"
        "SymHsm.sys"           = "Symantec"
        "evmf.sys"             = "Symantec"
        "GEFCMP.sys"           = "Symantec"
        "VFSEnc.sys"           = "Symantec"
        "pgpfs.sys"            = "Symantec"
        "fencry.sys"           = "Symantec"
        "symrg.sys"            = "Symantec"
        "ndgdmk.sys"           = "Verdasys Inc"
        "ssfmonm.sys"          = "Webroot Software"
        "dlpwpdfltr.sys"       = "Trend Micro Software"
    }

    $DetectedDrivers = @()

    $Drivers = Invoke-Command -Session $Session -ArgumentList $VerbosePreference, $Session.ComputerName {
        param(
            $vp,
            $ComputerName
        )
        try {
            $DriverPath = "C:\Windows\System32\drivers\"
            $VerbosePreference = "SilentlyContinue"
            Get-ChildItem -Path $DriverPath -File -Recurse -ErrorAction SilentlyContinue
            $VerbosePreference = $vp
        }
        catch {
            Write-Host  "[$ComputerName] Drivers method failed" -ForegroundColor Yellow
            Write-Verbose  "[$ComputerName] Reason: $_"

        }
    }
    Write-Host "[*] Results:" -ForegroundColor Cyan
    $Drivers | ForEach-Object {
        $FileName = $_.Name
        if ($Edrs.ContainsKey($FileName)) {
            Write-Host  "[$($Session.ComputerName)][+] Driver method: found $DriverPath$FileName." -ForegroundColor Green
            Write-Output  "[+] Driver method: found $DriverPath$FileName."
            $DetectedDrivers += $Edrs[$FileName]
        }
        elseif ($FileName -like "EcatService*") {
            Write-Host  "[$($Session.ComputerName)][+] Driver method: found $DriverPath$FileName." -ForegroundColor Green
            Write-Output "[+] Driver method: found $DriverPath$FileName."
            $DetectedDrivers += "RSA NetWitness Endpoint"
        }
    }
    if ($DetectedDrivers.Count) {
        $Result.Drivers_Method = ($DetectedDrivers | Select-Object -Unique) -join "; "
    }
    return $Result
}