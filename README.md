<p align="center"><img src="./figjuicer.png" width="256" alt="FigJuicer"></p>

<h1 align="center">FigJuicer</h1>

<p align="center">PowerShell toolkit squeezing configuration of remote Windows targets to extract potential vulnerabilities. Currently supports various Active Directory domain checks, BitLocker status and AV/EDR enumeration.</p>

<hr>

# Prerequisites

- PowerShell 5.1 or later (PowerShell 7+ recommended)  
- FigJuicer module imported
- Valid credentials with permissions on targets  

---

# Usage
## TL;DR
```powershell
Import-Module .\FigJuicer.psm1
Get-TargetList -TargetsFile "ranges.txt" -OutputFile "parsed_ips.txt"
Test-Targets -Credential $(Get-Credential) -OutputFile "output.txt" -TargetsFile "parsed_ips.txt"
Get-Content "output.txt"
```
## Import module
```powershell
Import-Module .\FigJuicer.psm1
```

## Juice all 'figs
### Prepare targets List

Parses a target file containing:
- Single IPv4s: `192.168.0.1`
- IPv4 CIDR ranges: `192.168.0.1/23`
- IPv4 "human" ranges: `192.168.0.1-192.168.0.10`
- Hostnames: `test.company.com`

and transforms it to a list of single IPs, ready to be used by other tools. Errors are filtered out.

```powershell
Get-TargetList -TargetsFile "ranges_file.txt" -OutputFile "single_ip_file.txt"
```
- `-TargetsFile`: file with target IPs/ranges
- `-OutputFile`: file to save expanded single IPs

### [OPTIONAL] Test PSSession compability
- PSSession connection to your targets might need some configuration
```powershell
# Input your credentials
$cred = Get-Credential
# Vanilla, HTTP on tcp/5985
$s = New-PSSession -Credential $cred -ComputerName 192.168.56.10
# SSL, tcp/5986
$s = New-PSSession -Credential $cred -ComputerName 192.168.56.10 -UseSSL
# SSL with options to ignore self-signed certificate and CN check
$options = New-PSSessionOption -SkipCACheck -SkipCNCheck
$s = New-PSSession -Credential $cred -ComputerName 192.168.56.10 -UseSSL -SessionOption $options
```
- Once you found the proper configuration, edit the first lines of `Test-Targets.ps1` in accordance, and add `-UseSSL` argument if necessary.

### Juice targets
```powershell
$Credential = Get-Credential

# Using IP array
Test-Targets -Credential $Credential -OutputFile "global_output.txt" -Targets $Targets

# Or using targets file
Test-Targets -Credential $Credential -OutputFile "global_output.txt" -TargetsFile "single_ip_file.txt"

# Including AD tests
Test-Targets -Credential $Credential -OutputFile "global_output.txt" -TargetsFile "single_ip_file.txt"  -DomainController $DCIP
```
- Provide either `-Targets` or `-TargetsFile`
- `-Credential`: Credentials to connect to remote machines using WinRM (`PSSession`), acquire interactively using the following
```powershell
$cred = Get-Credential
```
- `-OutputFile`: location of results

## Juice a single 'fig

Single checks can be performed by passing a `Target` and a `PSSession` to the following functions:
```powershell
# Create a PSSession
$Session = New-PSSession -ComputerName $Target -Credential $Credential

Get-BitLockerStatus -Session $Session
Get-AVStatus -Session $Session

# Exception for AD 'fig, use credentials & IP
Get-ADStatus -Credential $Credential -DomainController $DomainControllerIP
```
# Notes
Credentials must have proper permissions:
- All remote, non-AD tests require WinRM privileges on the targeted machines
- AD tests require LDAP connection to the Domain controller (non-privileged)
- AV enumeration does not require privileges
- AD enumeration does not require privileges
- BitLocker enumeration **does** require Local Administrator privileges.
