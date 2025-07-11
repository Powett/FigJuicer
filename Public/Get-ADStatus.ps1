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
        [Parameter(Mandatory = $true)][string]$DomainController,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential
    )
    $vp = $VerbosePreference
    $VerbosePreference = "SilentlyContinue"
    Import-Module ActiveDirectory -Verbose:$false -Server $DomainController
    $VerbosePreference = $vp
    Write-Host "[*] Connecting to domain controller: $DomainController" -ForegroundColor Cyan

    # --------- Users security
    Write-Host "`n[*] Checking for user security" -ForegroundColor Cyan

    # --- Users with PASSWD_NOTREQD flag
    Write-Host "[**] Checking for users with PASSWD_NOTREQD..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties PasswordNotRequired |
    Where-Object { $_.PasswordNotRequired } |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) have PASSWD_NOTREQD" -ForegroundColor Yellow 
    
    Write-Output "========== Users with PASSWD_NOTREQD =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }
    
    # --- Users with PasswordNeverExpires flag
    Write-Host "`n[**] Checking users with PasswordNeverExpires set..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) have PasswordNeverExpires" -ForegroundColor Yellow

    Write-Output "========== Users with PasswordNeverExpires =========="
    $Users | ForEach-Object {
        Write-Output $_.SamAccountName
    }

    # --- Users never used
    Write-Host "`n[**] Checking for users never used..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties LastLogonDate |
    Where-Object { -not $_.LastLogonDate } |
    Select-Object SamAccountName 
    Write-Host "[-] $($Users.Count) have never been used" -ForegroundColor Yellow
    
    Write-Output "========== Users never used =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }

    # --- Users unused in last 6 months
    $SixMonthsAgo = (Get-Date).AddMonths(-6)
    Write-Host "`n[**] Checking for users not used in the last 6 months..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $SixMonthsAgo } |
    Select-Object SamAccountName, LastLogonDate
    Write-Host "[-] $($Users.Count) have not been used in the last 6 months" -ForegroundColor Yellow

    Write-Output "========== Users unused in the last 6 months =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName ", Last login: $_.LastLogonDate"
    }

    # --- Users with reversible password encryption enabled
    Write-Host "`n[**] Checking for users with reversible password encryption enabled..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter * -Properties AllowReversiblePasswordEncryption |
    Where-Object { $_.AllowReversiblePasswordEncryption } |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) have reversable password encryption enabled" -ForegroundColor Yellow

    Write-Output "========== Users with reversable password encryption enabled =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }

    # --- Users with PreAuth disabled
    Write-Host "`n[**] Checking for users with pre-authentication disabled..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter 'DoesNotRequirePreAuth -eq $true' |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) have pre-authentication disabled" -ForegroundColor Yellow

    Write-Output "========== Users with pre-authentication disabled =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }

    # --- Users with weak crypto
    Write-Host "`n[**] Detecting accounts using DES-only keys..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { UseDESKeyOnly -eq $true } -Properties UseDESKeyOnly |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) using DES-only keys" -ForegroundColor Yellow

    Write-Output "========== Users using DES-only keys =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }

    # --------- Privileges
    Write-Host "[*] Checking for privileges issues" -ForegroundColor Cyan
    
    # --- Privileged users with SPNs
    Write-Host "`n[**] Listing privileged users (AdminCount>0) with SPNs set..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName, AdminCount |
    Where-Object { $_.ServicePrincipalName.Count -gt 0 -and $_.AdminCount -gt 0 } |
    Select-Object SamAccountName, ServicePrincipalName

    Write-Host "[-] $($Users.Count) are privileged and have SPNs" -ForegroundColor Yellow

    Write-Output "========== Users that are privileged and have SPNs =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName, $_.ServicePrincipalName
    }
    
    # --- Users trusted for delegation
    Write-Host "`n[**]  Finding accounts Trusted for Delegation..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object SamAccountName
    Write-Host "[-] $($Users.Count) are Trusted for Delegation" -ForegroundColor Yellow

    Write-Output "========== Users that are Trusted for Delegation =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName
    }

    # --- Users with AdminCount>0 but not in any "admin" groups
    Write-Host "`n[**]  Checking users with AdminCount>0 but no obvious admin group membership..." -ForegroundColor Cyan
    $AdminUsers = Get-ADUser -Server $DomainController -Credential $Credential -Filter { AdminCount -gt 0 } -Properties MemberOf, AdminCount
    $Users = @()
    foreach ($User in $AdminUsers) {
        $Groups = ($User.MemberOf | ForEach-Object { ($_ -split ',')[0] }) -join ','
        if ($Groups -notmatch '(?i)admin') {
            $Users += $User
        }
    }

    Write-Host "[-] $($Users.Count) are orphaned admin accounts" -ForegroundColor Yellow

    Write-Output "========== Users that are orphaned admin account =========="
    $Users | ForEach-Object { 
        Write-Output $_.SamAccountName, $_.MemberOf
    }

    # --------- Domain trusts
    Write-Host "`n[*] Enumerating domain trusts..." -ForegroundColor Cyan
    $Trusts = Get-ADTrust -Server $DomainController -Credential $Credential -Filter *
    Write-Host "[-] Found $($Trusts.Count) trusts configured" -ForegroundColor Yellow
        
    Write-Output "========== Trusts =========="
    Write-Output $Trusts


    # --------- Password policy
    Write-Host "`n[*] Checking for domain password policy" -ForegroundColor Cyan

    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainController -Credential $Credential
    Write-Host "[**] ComplexityEnabled: $($PwdPolicy.ComplexityEnabled)" -ForegroundColor Yellow 
    Write-Host "[**] LockoutDuration: $($PwdPolicy.LockoutDuration)" -ForegroundColor Yellow 
    Write-Host "[**] LockoutObservationWindow: $($PwdPolicy.LockoutObservationWindow)" -ForegroundColor Yellow 
    Write-Host "[**] LockoutThreshold: $($PwdPolicy.LockoutThreshold)" -ForegroundColor Yellow 
    Write-Host "[**] MaxPasswordAge: $($PwdPolicy.MaxPasswordAge)" -ForegroundColor Yellow 
    Write-Host "[**] MinPasswordAge: $($PwdPolicy.MinPasswordAge)" -ForegroundColor Yellow 
    Write-Host "[**] MinPasswordLength: $($PwdPolicy.MinPasswordLength)" -ForegroundColor Yellow 
    Write-Host "[**] PasswordHistoryCount: $($PwdPolicy.PasswordHistoryCount)" -ForegroundColor Yellow 
    Write-Host "[**] ReversibleEncryptionEnabled: $($PwdPolicy.ReversibleEncryptionEnabled)" -ForegroundColor Yellow 

    Write-Output "========== Password policy =========="
    Write-Output "ComplexityEnabled: $($PwdPolicy.ComplexityEnabled)" 
    Write-Output "LockoutDuration: $($PwdPolicy.LockoutDuration)" 
    Write-Output "LockoutObservationWindow: $($PwdPolicy.LockoutObservationWindow)" 
    Write-Output "LockoutThreshold: $($PwdPolicy.LockoutThreshold)" 
    Write-Output "MaxPasswordAge: $($PwdPolicy.MaxPasswordAge)" 
    Write-Output "MinPasswordAge: $($PwdPolicy.MinPasswordAge)" 
    Write-Output "MinPasswordLength: $($PwdPolicy.MinPasswordLength)" 
    Write-Output "PasswordHistoryCount: $($PwdPolicy.PasswordHistoryCount)" 
    Write-Output "ReversibleEncryptionEnabled: $($PwdPolicy.ReversibleEncryptionEnabled)"

}