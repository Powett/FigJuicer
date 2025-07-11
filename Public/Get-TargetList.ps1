# Helper function for target acquisition: parses a file containing, per line:
# - Single IPv4
# - Hostname (resolvable only)
# - IPv4 range, subnet notation XXX.XXX.XXX.XXX/YY
# - IPv4 range, basic notation XXX.XXX.XXX.XXX-YYYY.YYYY.YYYY.YYYY
# Performs basic sanity checks (including DNS resolving)
# Developped by Powett
# Distributed under MIT License https://opensource.org/license/mit

# Example use:
# Get-TargetList -TargetsFile $TargetsFile -OutputFile $OutputFile | Format-Table

[CmdletBinding()]
param(
    [string]$TargetsFile = "ranges.txt",
    [string]$OutputFile = "out_ips.txt"
)

function Get-TargetList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetsFile,
    
        [Parameter(Mandatory = $true)]
        [string]$OutputFile,
    
        [switch]$Force
    
    )

    Write-Verbose  "Targets File: $TargetsFile"
    Write-Verbose  "Username: $Username"
    Write-Verbose  "Output File: $OutputFile"

    if (-Not (Test-Path $TargetsFile)) {
        Write-Error "Targets file '$TargetsFile' does not exist."
        return
    }

    if ((Test-Path $OutputFile) -and -not $Force) {
        Write-Warning "Output file '$OutputFile' already exists. Use -Force to overwrite."
        return    
    }
    elseif ((Test-Path $OutputFile) -and $Force) {
        Write-Verbose  "Overwriting existing output file '$OutputFile'"
        Remove-Item $OutputFile -Force
    }


    $Targets = @()
    $Unparsed = @()
    
    # IP regex: matches 0.0.0.0 to 255.255.255.255
    $ValidIpRegex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

    # CIDR regex: IP + '/' + prefix 0–32
    $ValidCidrRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([0-9]|[1-2][0-9]|3[0-2])$"

    # IP range regex: IP + '-' + IP
    $ValidIpRangeRegex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

    # Hostname regex
    $ValidHostnameRegex = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'

    foreach ($Line in Get-Content $TargetsFile) {
        $Line = $Line.Trim()
        try {
            if ($Line -match $ValidIpRegex) {
                Write-Verbose  "Line $Line is: Single IP"
                $Targets += $Line
            }
            elseif ($Line -match $ValidCidrRegex) {
                Write-Verbose  "Line $Line is: CIDR range"
                $Ip, $Prefix = $Line -split "/"
                $Prefix = [int]$Prefix
                $IpBytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
                [Array]::Reverse($IpBytes)
                $IpInt = [BitConverter]::ToUInt32($IpBytes, 0)
                $HostCount = [math]::Pow(2, 32 - $Prefix)
                if ($HostCount -gt 1024) {
                    Write-Warning "IP range $Line includes $HostCount IPs, which might be more than expected."
                }
                for ($I = 0; $I -lt $HostCount; $I++) {
                    $NextIP = $IpInt + $I
                    $Bytes = [BitConverter]::GetBytes($NextIP)
                    [Array]::Reverse($Bytes)
                    $IteratedIp = [System.Net.IPAddress]::new($Bytes).ToString()
                    $Targets += $IteratedIp
                }
            }
            elseif ($Line -match $ValidIpRangeRegex) {
                Write-Verbose  "Line $Line is: IP range"
                $StartIP, $EndIP = $Line -split "-"
                try {
                    $StartBytes = [System.Net.IPAddress]::Parse($StartIP).GetAddressBytes()
                    $EndBytes = [System.Net.IPAddress]::Parse($EndIP).GetAddressBytes()
                }
                catch {
                    throw "Invalid IP address in range: $Line"
                }

                [Array]::Reverse($StartBytes)
                [Array]::Reverse($EndBytes)

                $StartInt = [BitConverter]::ToUInt32($StartBytes, 0)
                $EndInt = [BitConverter]::ToUInt32($EndBytes, 0)

                if ($StartInt -gt $EndInt) {
                    throw "Start IP must be less than or equal to End IP in range: $Line"
                }

                $HostCount = $EndInt - $StartInt + 1
                if ($HostCount -gt 1024) {
                    Write-Warning "IP range $Line includes $HostCount IPs, which might be more than expected."
                }

                for ($I = $StartInt; $I -le $EndInt; $I++) {
                    $Bytes = [BitConverter]::GetBytes($I)
                    [Array]::Reverse($Bytes)
                    $IteratedIp = [System.Net.IPAddress]::new($Bytes).ToString()
                    $Targets += $IteratedIp
                }

            }
            elseif ($Line -match $ValidHostnameRegex) {
                Write-Verbose  "Line $Line is: potential hostname"
                $Records = Resolve-DnsName -Name $Line -ErrorAction Stop
                Write-Verbose  "Found IP: $($Records[0].Address)"
                $Targets += $Records[0].Address          
            }
            else {
                throw "Line $Line is: unknown format"
            }
        }
        catch {
            Write-Warning $_
            $Unparsed += $Line
        }
    }   
    
    $Targets | Out-File -FilePath $OutputFile
    Write-Host "Finished parsing, $($Targets.Count) IPs identified, wrote to $OutputFile"
    if ($Unparsed.Count -gt 0) {
        Write-Warning "Finished parsing, $($Unparsed.Count) unparsed Lines"
    }
    return @{Parsed = $Targets; Unparsed = $Unparsed }
}