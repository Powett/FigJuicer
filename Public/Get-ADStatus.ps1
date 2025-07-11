# Powershell script doing superficial Active Directory hardening tests
# Developped by Powett
# Distributed under MIT License https://opensource.org/license/mit

# Example use
# Get-ADStatus -DomainController $IP -Credential $(Get-Credential)

[CmdletBinding()]
param ()
function Get-ADStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$DomainController,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "[*] Connecting to domain controller: $DomainController" -ForegroundColor Cyan

    # --------- Users security
    Write-Host "[**] Checking for user security" -ForegroundColor Cyan

    # --- Users with PASSWD_NOTREQD flag
    Write-Host "[*] Checking for users with PASSWD_NOTREQD..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties PasswordNotRequired |
    Where-Object { $_.PasswordNotRequired } |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "has PASSWD_NOTREQD" -ForegroundColor Yellow }
    
    # --- Users with PasswordNeverExpires flag
    Write-Host "[*] Checking users with PasswordNeverExpires set..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "has PasswordNeverExpires" -ForegroundColor Yellow }

    # --- Users never used
    Write-Host "`n[*] Checking for users never used..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties LastLogonDate |
    Where-Object { -not $_.LastLogonDate } |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "never used" -ForegroundColor Yellow }

    # --- Users unused in last 6 months
    $SixMonthsAgo = (Get-Date).AddMonths(-6)
    Write-Host "`n[*] Checking for users not used in the last 6 months..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $SixMonthsAgo } |
    Select-Object SamAccountName, LastLogonDate |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "last logon:" $_.LastLogonDate -ForegroundColor Yellow }

    # --- Users with reversible password encryption enabled
    Write-Host "`n[*] Checking for users with reversible password encryption enabled..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties AllowReversiblePasswordEncryption |
    Where-Object { $_.AllowReversiblePasswordEncryption } |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "has reversible password encryption enabled" -ForegroundColor Yellow }

    # --- Users with PreAuth disabled
    Write-Host "`n[*] Checking for users with pre-authentication disabled..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter 'DoesNotRequirePreAuth -eq $true' |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "has pre-authentication disabled" -ForegroundColor Yellow }

    # --- Users with weak crypto
    Write-Host "[*] Detecting accounts using DES-only keys..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter { UseDESKeyOnly -eq $true } -Properties UseDESKeyOnly |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "uses DES-only key" -ForegroundColor Yellow }

    # --------- Privileges
    Write-Host "[**] Checking for privileges issues" -ForegroundColor Cyan
    
    # --- Privileged users with SPNs
    Write-Host "[*] Listing privileged users (AdminCount>0) with SPNs set..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName, AdminCount |
    Where-Object { $_.ServicePrincipalName.Count -gt 0 -and $_.AdminCount -gt 0 } |
    Select-Object SamAccountName, ServicePrincipalName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "has SPNs and is privileged" -ForegroundColor Yellow }
    
    # --- Users trusted for delegation
    Write-Host "[*] Finding accounts Trusted for Delegation..." -ForegroundColor Cyan
    Get-ADUser -Server $DomainController -Credential $Credential -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object SamAccountName |
    ForEach-Object { Write-Host "[+]" $_.SamAccountName "is trusted for delegation" -ForegroundColor Yellow }

    # --- Users with AdminCount>0 but not in any "admin" groups
    Write-Host "[*] Checking users with AdminCount>0 but no obvious admin group membership..." -ForegroundColor Cyan
    $AdminUsers = Get-ADUser -Server $DomainController -Credential $Credential -Filter { AdminCount -gt 0 } -Properties MemberOf, AdminCount
    foreach ($User in $AdminUsers) {
        $Groups = ($User.MemberOf | ForEach-Object { ($_ -split ',')[0] }) -join ','
        if ($Groups -notmatch '(?i)admin') {
            Write-Host "[+]" $User.SamAccountName "has AdminCount>0 but is not in any obvious admin groups: $Groups" -ForegroundColor Yellow
        }
    }

    # --------- Domain trusts
    Write-Host "[*] Enumerating domain trusts..." -ForegroundColor Cyan
    $Trusts = Get-ADTrust -Server $DomainController -Credential $Credential -Filter *
    $Trusts | ForEach-Object { Write-Host "[+] Found" $_.Direction "trust to $($_.Name)" -ForegroundColor Yellow }
    $Trusts | Format-Table


    # --------- Password policy
    Write-Host "[**] Checking for domain password policy" -ForegroundColor Cyan
    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainController -Credential $Credential
    Write-Host "[*] ComplexityEnabled: $($PwdPolicy.ComplexityEnabled)" -ForegroundColor Yellow 
    Write-Host "[*] LockoutDuration: $($PwdPolicy.LockoutDuration)" -ForegroundColor Yellow 
    Write-Host "[*] LockoutObservationWindow: $($PwdPolicy.LockoutObservationWindow)" -ForegroundColor Yellow 
    Write-Host "[*] LockoutThreshold: $($PwdPolicy.LockoutThreshold)" -ForegroundColor Yellow 
    Write-Host "[*] MaxPasswordAge: $($PwdPolicy.MaxPasswordAge)" -ForegroundColor Yellow 
    Write-Host "[*] MinPasswordAge: $($PwdPolicy.MinPasswordAge)" -ForegroundColor Yellow 
    Write-Host "[*] MinPasswordLength: $($PwdPolicy.MinPasswordLength)" -ForegroundColor Yellow 
    Write-Host "[*] PasswordHistoryCount: $($PwdPolicy.PasswordHistoryCount)" -ForegroundColor Yellow 
    Write-Host "[*] ReversibleEncryptionEnabled: $($PwdPolicy.ReversibleEncryptionEnabled)" -ForegroundColor Yellow 
}