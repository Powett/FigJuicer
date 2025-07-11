# FigJuicer

![FigJuicer Icon](./icon.png)

---

## About

**FigJuicer** is a PowerShell toolkit squeezing configuration of remote Windows targets to extract potential vulnerabilities. Currently supports various Active Directory domain checks, BitLocker status and AV/EDR enumeration.

---

## Prerequisites

- PowerShell 5.1 or later (PowerShell 7+ recommended)  
- FigJuicer module imported
- Valid credentials with permissions on targets  

---

## Usage
### Import module
```powershell
Import-Module FigJuicer
```

### Juice all 'figs
#### Prepare targets List

Parses a target file containing:
- Single IPv4s: `192.168.0.1`
- IPv4 CIDR ranges: `192.168.0.1/23`
- IPv4 "human" ranges: `192.168.0.1-192.168.0.10`
- Hostnames: `test.company.com`

and transforms it to a list of single IPs, ready to be used by other tools. Errors are filtered out.

```powershell
Get-TargetList -TargetsFile "ranges_file.txt" -OutputFile "single_ip_file.txt"
```
-`TargetsFile`: file with target IPs/ranges
-`OutputFile`: file to save expanded single IPs

#### Juice targets
```powershell
$Credential = Get-Credential

# Using IP array
Test-Targets -Credential $Credential -OutputFile "global_output.txt" -Targets $Targets

# Or using targets file
Test-Targets -Credential $Credential -OutputFile "global_output.txt" -TargetsFile "single_ip_file.txt"
```
- Provide either `-Targets` or `-TargetsFile`
- `-Credential`: Credentials to connect to remote machines using WinRM (`PSSession`), acquire interactively using the following
```powershell
$cred = Get-Credential
```
- `-OutputFile`: location of results

### Juice a single 'fig

Single checks can be performed by passing a `Target` and a `PSSession` to the following functions:
```powershell
# Create a PSSession
$Session = New-PSSession -ComputerName $Target -Credential $Credential

Get-BitLockerStatus -Session $Session
Get-AVStatus -Session $Session

# Exception for AD 'fig, use credentials & IP
Get-ADStatus -Credential $Credential -DomainController $DomainControllerIP
```
## Notes
Credentials must have proper permissions:
- All remote, non-AD tests require WinRM privileges on the targeted machines
- AD tests require LDAP connection to the Domain controller (non-privileged)
- AV enumeration does not require privileges
- AD enumeration does not require privileges
- BitLocker enumeration **does** require Local Administrator privileges.