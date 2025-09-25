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
    Import-Module ActiveDirectory -Verbose:$false
    $VerbosePreference = $vp
    Write-Host "[$DomainController][*] Connecting to domain controller: $DomainController" -ForegroundColor Cyan

    # --------- Users security
    Write-Host "`n[$DomainController][*] Checking for common (enabled) users security" -ForegroundColor Cyan
    Write-Output "==================== Common users ===================="


    # --- Users with PASSWD_NOTREQD flag
    Write-Output "========== Users with PASSWD_NOTREQD =========="
    Write-Host "[$DomainController][**] Checking for users with PASSWD_NOTREQD..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true } -Properties PasswordNotRequired |
    Where-Object { $_.PasswordNotRequired } |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) users have PASSWD_NOTREQD" -ForegroundColor Yellow 
    Write-Output "[$DomainController][-] $($Users.Count) users have PASSWD_NOTREQD" 
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }
    
    # --- Users with PasswordNeverExpires flag
    Write-Output "========== Users with PasswordNeverExpires =========="
    Write-Host "`n[$DomainController][**] Checking users with PasswordNeverExpires set..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) users have PasswordNeverExpires" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have PasswordNeverExpires"
    $Users | ForEach-Object {
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users never used
    Write-Output "========== Users never used =========="
    Write-Host "`n[$DomainController][**] Checking for users never used..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object { -not $_.LastLogonDate } |
    Select-Object SamAccountName 
    
    Write-Host "[$DomainController][-] $($Users.Count) users have never been used" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have never been used"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users unused in last 3 months
    Write-Output "========== Users unused in the last 3 months =========="
    Write-Host "`n[$DomainController][**] Checking for users not used in the last 3 months..." -ForegroundColor Cyan
    $ThreeMonthsAgo = (Get-Date).AddDays(-90)
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -lt $ThreeMonthsAgo } |
    Select-Object SamAccountName, LastLogonDate
    
    Write-Host "[$DomainController][-] $($Users.Count) users have not been used in the last 3 months" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have not been used in the last 3 months"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName), last login: $($_.LastLogonDate)"
    }

    # --- Users with password older than 3 months
    Write-Output "========== Users with password older than 3 months =========="
    Write-Host "`n[$DomainController][**] Checking for users with password older than 3 months..." -ForegroundColor Cyan
    $ThreeMonthsAgo = (Get-Date).AddDays(-90)
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true } -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt $ThreeMonthsAgo } |
    Select-Object SamAccountName, PasswordLastSet
    
    Write-Host "[$DomainController][-] $($Users.Count) users have not rotated their password in the last 3 months" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have not rotated their password in the last 3 months"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName), last password set: $($_.PasswordLastSet)"
    }

    # --- Users with reversible password encryption enabled
    Write-Output "========== Users with reversable password encryption enabled =========="
    Write-Host "`n[$DomainController][**] Checking for users with reversible password encryption enabled..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true } -Properties AllowReversiblePasswordEncryption |
    Where-Object { $_.AllowReversiblePasswordEncryption } |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) users have reversable password encryption enabled" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have reversable password encryption enabled"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users with PreAuth disabled
    Write-Output "========== Users with pre-authentication disabled =========="
    Write-Host "`n[$DomainController][**] Checking for users with pre-authentication disabled..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and DoesNotRequirePreAuth -eq $true } |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) users have pre-authentication disabled" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users have pre-authentication disabled"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users with weak crypto
    Write-Output "========== Users using DES-only keys =========="
    Write-Host "`n[**] Detecting accounts using DES-only keys..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and UseDESKeyOnly -eq $true } -Properties UseDESKeyOnly |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) users using DES-only keys" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users using DES-only keys"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }
    
    # --- Users trusted for delegation
    Write-Output "========== Users that are Trusted for Delegation =========="
    Write-Host "`n[**]  Finding accounts Trusted for Delegation..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object SamAccountName
    Write-Host "[$DomainController][-] $($Users.Count) users are Trusted for Delegation" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) users are Trusted for Delegation"

    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }

    # --------- Admin users security
    Write-Host "`n[$DomainController][-] Checking for admin (adminCount>0) users security" -ForegroundColor Cyan
    Write-Output "==================== Admin users ===================="
    
    # --- Privileged users with SPNs
    Write-Output "========== Admin users with SPNs =========="
    Write-Host "`n[**] Checking for admin users with SPNs set..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and ServicePrincipalName -like "*" -and AdminCount -gt 0 } -Properties ServicePrincipalName, AdminCount |
    Where-Object { $_.ServicePrincipalName.Count -gt 0 } |
    Select-Object SamAccountName, ServicePrincipalName

    Write-Host "[$DomainController][-] $($Users.Count) admin users have SPNs" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users have have SPNs"

    $Users | ForEach-Object { 
        Write-Output "* $($_.samAccountName) => $($_.ServicePrincipalName[0]),..."
    }

    # --- Users with AdminCount>0 but not in any "admin" groups
    Write-Output "========== Potential orphan admin users (no obvious group membership) admin account =========="
    Write-Host "`n[**]  Checking for admin users with no obvious admin group membership..." -ForegroundColor Cyan
    $AdminUsers = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and AdminCount -gt 0 } -Properties MemberOf, AdminCount
    $Users = @()
    foreach ($User in $AdminUsers) {
        $Groups = ($User.MemberOf | ForEach-Object { ($_ -split ',')[0] }) -join ','
        if ($Groups -notmatch '(?i)admin') {
            $Users += $User
        }
    }

    Write-Host "[$DomainController][-] $($Users.Count) admin users are potentially orphaned" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users are potentially orphaned"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName) : $($_.MemberOf)"
    }


    # --- Users with PASSWD_NOTREQD flag
    Write-Output "========== Admin users with PASSWD_NOTREQD =========="
    Write-Host "[**] Checking for admin users with PASSWD_NOTREQD..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and AdminCount -gt 0 } -Properties PasswordNotRequired |
    Where-Object { $_.PasswordNotRequired } |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) admin users have PASSWD_NOTREQD" -ForegroundColor Yellow 
    Write-Output "[$DomainController][-] $($Users.Count) admin users have PASSWD_NOTREQD" 
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }
    
    # --- Users with PasswordNeverExpires flag
    Write-Output "========== Admin users with PasswordNeverExpires =========="
    Write-Host "`n[**] Checking for admin users with PasswordNeverExpires set..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true -and AdminCount -gt 0 } -Properties PasswordNeverExpires |
    Select-Object SamAccountName

    Write-Host "[$DomainController][-] $($Users.Count) admin users have PasswordNeverExpires" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users have PasswordNeverExpires"
    $Users | ForEach-Object {
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users never used
    Write-Output "========== Admin users never used =========="
    Write-Host "`n[**] Checking for admin users never used..." -ForegroundColor Cyan
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and AdminCount -gt 0 } -Properties LastLogonDate |
    Where-Object { -not $_.LastLogonDate } |
    Select-Object SamAccountName 
    
    Write-Host "[$DomainController][-] $($Users.Count) admin users have never been used" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users have never been used"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName)"
    }

    # --- Users unused in last 3 months
    Write-Output "========== Admin users unused in the last 3 months =========="
    Write-Host "`n[**] Checking for admin users not used in the last 3 months..." -ForegroundColor Cyan
    $ThreeMonthsAgo = (Get-Date).AddDays(-90)
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and AdminCount -gt 0 } -Properties LastLogonDate, AdminCount |
    Where-Object { $_.LastLogonDate -lt $ThreeMonthsAgo } |
    Select-Object SamAccountName, LastLogonDate
    
    Write-Host "[$DomainController][-] $($Users.Count) admin users have not been used in the last 3 months" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users have not been used in the last 3 months"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName), last login: $($_.LastLogonDate)"
    }

    # --- Users with password older than 3 months
    Write-Output "========== Admin users with password older than 3 months =========="
    Write-Host "`n[**] Checking for admin users with password older than 3 months..." -ForegroundColor Cyan
    $ThreeMonthsAgo = (Get-Date).AddDays(-90)
    $Users = Get-ADUser -Server $DomainController -Credential $Credential -Filter { Enabled -eq $true -and AdminCount -gt 0 } -Properties PasswordLastSet, AdminCount |
    Where-Object { $_.PasswordLastSet -lt $ThreeMonthsAgo } |
    Select-Object SamAccountName, PasswordLastSet
    
    Write-Host "[$DomainController][-] $($Users.Count) admin users have not rotated their password in the last 3 months" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] $($Users.Count) admin users have not rotated their password in the last 3 months"
    $Users | ForEach-Object { 
        Write-Output "* $($_.SamAccountName), last password set: $($_.PasswordLastSet)"
    }


    # --------- Domain trusts
    Write-Output "==================== Trusts ===================="
    Write-Host "`n[$DomainController][-] Enumerating domain trusts..." -ForegroundColor Cyan
    $Trusts = Get-ADTrust -Server $DomainController -Credential $Credential -Filter *

    Write-Host "[$DomainController][-] Found $($Trusts.Count) trusts configured" -ForegroundColor Yellow
    Write-Output "[$DomainController][-] Found $($Trusts.Count) trusts configured"
        
    Write-Output $Trusts


    # --------- Password policy
    Write-Output "==================== Password policy ===================="
    Write-Host "`n[$DomainController][-] Checking for domain password policy" -ForegroundColor Cyan

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