<#
.SYNOPSIS
    Read-only Microsoft 365 security configuration scan.

.DESCRIPTION
    Connects to Microsoft Graph and runs a set of read-only checks against a tenant's
    identity, device and audit configuration: MFA enforcement, legacy authentication,
    device compliance and encryption, sign-in logging, guest access and Global Admin
    count. Each finding is mapped to a HIPAA Security Rule citation.

    Writes two files: a JSON file with every result, and an HTML report you can open
    in a browser or hand to someone non-technical.

    Read-only. Every Graph call is a GET. Nothing in the tenant is changed.

.PARAMETER TenantId
    Directory (tenant) ID to scan.

.PARAMETER ClientId
    Application ID to sign in with. Defaults to the Microsoft Graph Command Line Tools
    app. Use your own app registration if your tenant blocks that app.

.PARAMETER AccessToken
    Optional. A Graph access token to use instead of an interactive sign-in. This is how
    the script runs unattended in CI (see the passwordless-cicd-pipeline repo).

.PARAMETER OrgName
    Friendly name recorded in the report.

.PARAMETER OutputPath
    Folder for the JSON and HTML output. Defaults to the current folder.

.EXAMPLE
    ./Invoke-M365SecurityScan.ps1 -TenantId "<tenant-id>" -OrgName "Contoso"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    [string]$AccessToken,
    [string]$OrgName = "Unspecified",
    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

# Read-only Graph scopes. Nothing here grants write access.
$RequiredScopes = @(
    "Policy.Read.All"                          # Conditional Access, Authorization Policy
    "Directory.Read.All"                       # Org/domain metadata, directory roles
    "DeviceManagementConfiguration.Read.All"    # Intune device compliance policies
    "DeviceManagementManagedDevices.Read.All"   # Managed device state
    "AuditLog.Read.All"                         # Sign-in logs, directory audit logs
    "Organization.Read.All"                     # Tenant/org metadata
)

$RequiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.DirectoryManagement"
    "Microsoft.Graph.DeviceManagement"
    "Microsoft.Graph.Reports"
)

# ---------------------------------------------------------------------------
# Module check (does not auto-install; flags what's missing and stops)
# ---------------------------------------------------------------------------
function Assert-RequiredModules {
    $missing = @()
    foreach ($m in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m }
    }
    if ($missing.Count -gt 0) {
        Write-Host "Missing required modules:" -ForegroundColor Yellow
        $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host "Install with:  Install-Module <name> -Scope CurrentUser" -ForegroundColor Yellow
        throw "Required Microsoft Graph PowerShell modules are not installed. See list above."
    }
}

# ---------------------------------------------------------------------------
# Result object returned by every check
# ---------------------------------------------------------------------------
function New-CheckResult {
    param(
        [string]$ControlID,
        [string]$ControlName,
        [string]$Category,
        [string]$HIPAACitation,
        [ValidateSet("Pass","Fail","Partial","Manual","Error")]
        [string]$Status,
        [string]$Evidence,
        [string]$Recommendation,
        [ValidateSet("High","Medium","Low","Info")]
        [string]$Severity
    )
    [PSCustomObject]@{
        ControlID      = $ControlID
        ControlName    = $ControlName
        Category       = $Category
        HIPAACitation  = $HIPAACitation
        Status         = $Status
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Severity       = $Severity
    }
}

# Wraps a check body so one failing/throwing check never aborts the whole scan.
function Invoke-SafeCheck {
    param(
        [string]$ControlID,
        [string]$ControlName,
        [string]$Category,
        [string]$HIPAACitation,
        [scriptblock]$Body,
        [string]$Severity
    )
    try {
        & $Body
    }
    catch {
        New-CheckResult -ControlID $ControlID -ControlName $ControlName -Category $Category `
            -HIPAACitation $HIPAACitation -Status "Error" `
            -Evidence "Check could not complete: $($_.Exception.Message)" `
            -Recommendation "Re-run after confirming the signed-in account or app has the required read scope." `
            -Severity $Severity
    }
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

function Test-MFAEnforcement {
    Invoke-SafeCheck -ControlID "AC-01" -ControlName "Multi-Factor Authentication Enforcement" `
        -Category "Access Control" -HIPAACitation "45 CFR 164.312(d) - Person or Entity Authentication" `
        -Severity "High" -Body {
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        $enforcing = $policies | Where-Object {
            $_.State -eq "enabled" -and (
                $_.GrantControls.BuiltInControls -contains "mfa" -or
                $_.GrantControls.AuthenticationStrength.Id
            )
        }
        if ($enforcing.Count -gt 0) {
            New-CheckResult -ControlID "AC-01" -ControlName "Multi-Factor Authentication Enforcement" `
                -Category "Access Control" -HIPAACitation "45 CFR 164.312(d) - Person or Entity Authentication" `
                -Status "Pass" -Evidence "$($enforcing.Count) enabled Conditional Access polic$(if($enforcing.Count -eq 1){'y'}else{'ies'}) $(if($enforcing.Count -eq 1){'requires'}else{'require'}) MFA: $(($enforcing.DisplayName) -join '; ')" `
                -Recommendation "None - MFA is enforced through Conditional Access (MFA grant or authentication strength)." -Severity "High"
        }
        else {
            New-CheckResult -ControlID "AC-01" -ControlName "Multi-Factor Authentication Enforcement" `
                -Category "Access Control" -HIPAACitation "45 CFR 164.312(d) - Person or Entity Authentication" `
                -Status "Fail" -Evidence "No enabled Conditional Access policy requiring MFA or an authentication strength was found." `
                -Recommendation "Create and enable a Conditional Access policy requiring MFA for all users on all cloud apps." -Severity "High"
        }
    }
}

function Test-LegacyAuthBlocked {
    Invoke-SafeCheck -ControlID "AC-02" -ControlName "Legacy Authentication Blocked" `
        -Category "Access Control" -HIPAACitation "45 CFR 164.312(e)(1) - Transmission Security" `
        -Severity "High" -Body {
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        $blocking = $policies | Where-Object {
            $_.State -eq "enabled" -and
            ($_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or $_.Conditions.ClientAppTypes -contains "other") -and
            $_.GrantControls.BuiltInControls -contains "block"
        }
        if ($blocking.Count -gt 0) {
            New-CheckResult -ControlID "AC-02" -ControlName "Legacy Authentication Blocked" `
                -Category "Access Control" -HIPAACitation "45 CFR 164.312(e)(1) - Transmission Security" `
                -Status "Pass" -Evidence "Legacy/basic authentication clients are blocked by policy: $(($blocking.DisplayName) -join '; ')" `
                -Recommendation "None - legacy auth already blocked." -Severity "High"
        }
        else {
            New-CheckResult -ControlID "AC-02" -ControlName "Legacy Authentication Blocked" `
                -Category "Access Control" -HIPAACitation "45 CFR 164.312(e)(1) - Transmission Security" `
                -Status "Fail" -Evidence "No enabled Conditional Access policy blocking legacy authentication clients was found." `
                -Recommendation "Create a Conditional Access policy blocking legacy authentication protocols tenant-wide." -Severity "High"
        }
    }
}

function Test-DeviceComplianceEncryption {
    Invoke-SafeCheck -ControlID "DM-01" -ControlName "Device Compliance - Encryption Required" `
        -Category "Device Management" -HIPAACitation "45 CFR 164.312(a)(2)(iv) - Encryption and Decryption" `
        -Severity "High" -Body {
        $policies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        if ($policies.Count -eq 0) {
            New-CheckResult -ControlID "DM-01" -ControlName "Device Compliance - Encryption Required" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.312(a)(2)(iv) - Encryption and Decryption" `
                -Status "Fail" -Evidence "No device compliance policies exist in this tenant." `
                -Recommendation "Create a device compliance policy requiring disk encryption (BitLocker/FileVault) before allowing managed access." -Severity "High"
            return
        }
        $encryptionRequiring = $policies | Where-Object {
            $_.AdditionalProperties.storageRequireEncryption -eq $true -or
            $_.AdditionalProperties.bitLockerEnabled -eq $true
        }
        if ($encryptionRequiring.Count -gt 0) {
            New-CheckResult -ControlID "DM-01" -ControlName "Device Compliance - Encryption Required" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.312(a)(2)(iv) - Encryption and Decryption" `
                -Status "Pass" -Evidence "$($encryptionRequiring.Count) of $($policies.Count) compliance policies require disk encryption." `
                -Recommendation "None - encryption requirement confirmed." -Severity "High"
        }
        else {
            New-CheckResult -ControlID "DM-01" -ControlName "Device Compliance - Encryption Required" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.312(a)(2)(iv) - Encryption and Decryption" `
                -Status "Partial" -Evidence "$($policies.Count) compliance policy/policies exist but none explicitly require disk encryption." `
                -Recommendation "Update existing compliance policies (or add a new one) to require disk encryption." -Severity "High"
        }
    }
}

function Test-DeviceComplianceAssignment {
    Invoke-SafeCheck -ControlID "DM-02" -ControlName "Device Compliance Policy Assignment Coverage" `
        -Category "Device Management" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(A) - Risk Analysis" `
        -Severity "Medium" -Body {
        $policies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        if ($policies.Count -eq 0) {
            New-CheckResult -ControlID "DM-02" -ControlName "Device Compliance Policy Assignment Coverage" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(A) - Risk Analysis" `
                -Status "Fail" -Evidence "No device compliance policies exist to assign." `
                -Recommendation "See DM-01 - no compliance policies exist yet." -Severity "Medium"
            return
        }
        $unassigned = @()
        foreach ($p in $policies) {
            $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $p.Id -ErrorAction SilentlyContinue
            if (-not $assignments -or $assignments.Count -eq 0) { $unassigned += $p.DisplayName }
        }
        if ($unassigned.Count -eq 0) {
            New-CheckResult -ControlID "DM-02" -ControlName "Device Compliance Policy Assignment Coverage" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(A) - Risk Analysis" `
                -Status "Pass" -Evidence "All $($policies.Count) compliance policies have at least one assignment." `
                -Recommendation "None." -Severity "Medium"
        }
        else {
            New-CheckResult -ControlID "DM-02" -ControlName "Device Compliance Policy Assignment Coverage" `
                -Category "Device Management" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(A) - Risk Analysis" `
                -Status "Partial" -Evidence "Unassigned (orphaned) policies found: $($unassigned -join '; ')" `
                -Recommendation "Assign these policies to a device/user group or remove them - an unassigned policy enforces nothing." -Severity "Medium"
        }
    }
}

function Test-SignInLogActivity {
    Invoke-SafeCheck -ControlID "AU-01" -ControlName "Sign-In Log Activity" `
        -Category "Audit Controls" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(D) - Information System Activity Review" `
        -Severity "Medium" -Body {
        $recent = Get-MgAuditLogSignIn -Top 5 -ErrorAction Stop
        if ($recent.Count -gt 0) {
            New-CheckResult -ControlID "AU-01" -ControlName "Sign-In Log Activity" `
                -Category "Audit Controls" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(D) - Information System Activity Review" `
                -Status "Pass" -Evidence "Sign-in logs are actively populating (most recent entry: $($recent[0].CreatedDateTime))." `
                -Recommendation "None - confirm log retention period separately in Entra ID > Diagnostic settings." -Severity "Medium"
        }
        else {
            New-CheckResult -ControlID "AU-01" -ControlName "Sign-In Log Activity" `
                -Category "Audit Controls" -HIPAACitation "45 CFR 164.308(a)(1)(ii)(D) - Information System Activity Review" `
                -Status "Fail" -Evidence "No sign-in log entries were returned." `
                -Recommendation "Confirm Entra ID sign-in logging is enabled and licensed (requires Entra ID P1/P2 for extended retention)." -Severity "Medium"
        }
    }
}

function Test-GuestAccessRestriction {
    Invoke-SafeCheck -ControlID "IAM-01" -ControlName "Guest / External Access Restriction" `
        -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(4) - Information Access Management" `
        -Severity "Medium" -Body {
        $authPolicy = Get-MgPolicyAuthorizationPolicy
        $guestInvite = $authPolicy.AllowInvitesFrom
        if ($guestInvite -in @("none", "adminsAndGuestInviters")) {
            New-CheckResult -ControlID "IAM-01" -ControlName "Guest / External Access Restriction" `
                -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(4) - Information Access Management" `
                -Status "Pass" -Evidence "Guest invitations restricted (AllowInvitesFrom: $guestInvite)." `
                -Recommendation "None." -Severity "Medium"
        }
        else {
            New-CheckResult -ControlID "IAM-01" -ControlName "Guest / External Access Restriction" `
                -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(4) - Information Access Management" `
                -Status "Fail" -Evidence "Guest invitations are open beyond admins/designated inviters (AllowInvitesFrom: $guestInvite)." `
                -Recommendation "Restrict guest invitations to admins and designated inviters in Entra ID > External Identities." -Severity "Medium"
        }
    }
}

function Test-PrivilegedRoleSprawl {
    Invoke-SafeCheck -ControlID "IAM-02" -ControlName "Global Administrator Role Sprawl" `
        -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(3) - Workforce Security" `
        -Severity "High" -Body {
        $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
        if (-not $gaRole) {
            New-CheckResult -ControlID "IAM-02" -ControlName "Global Administrator Role Sprawl" `
                -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(3) - Workforce Security" `
                -Status "Manual" -Evidence "Global Administrator role is not activated in this tenant's directory role list (may use PIM-only activation)." `
                -Recommendation "Verify privileged role assignment manually via Entra ID > Roles and administrators, or via PIM if in use." -Severity "High"
            return
        }
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All
        if ($members.Count -le 2) {
            New-CheckResult -ControlID "IAM-02" -ControlName "Global Administrator Role Sprawl" `
                -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(3) - Workforce Security" `
                -Status "Pass" -Evidence "$($members.Count) active Global Administrator assignment(s) - within a reasonable break-glass/primary-admin range." `
                -Recommendation "None." -Severity "High"
        }
        else {
            New-CheckResult -ControlID "IAM-02" -ControlName "Global Administrator Role Sprawl" `
                -Category "Information Access Management" -HIPAACitation "45 CFR 164.308(a)(3) - Workforce Security" `
                -Status "Partial" -Evidence "$($members.Count) active Global Administrator assignments found." `
                -Recommendation "Review whether all $($members.Count) accounts require standing Global Administrator access; consider PIM eligible/just-in-time assignment instead." -Severity "High"
        }
    }
}

function Get-IncidentProcedureManualCheck {
    New-CheckResult -ControlID "IR-01" -ControlName "Documented Security Incident Procedure" `
        -Category "Security Incident Procedures" -HIPAACitation "45 CFR 164.308(a)(6) - Security Incident Procedures" `
        -Status "Manual" -Evidence "Not verifiable via Graph API - this control requires a documented, written incident response procedure." `
        -Recommendation "Confirm a written incident response procedure exists, is current and has been tested. This is a document review item, not an automated check." `
        -Severity "Info"
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

function ConvertTo-HtmlReport {
    param($Report)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $colors = @{ Pass = "#1a7f37"; Fail = "#cf222e"; Partial = "#bf8700"; Manual = "#57606a"; Error = "#8250df" }
    $rows = foreach ($c in $Report.Controls) {
        "<tr><td>$(& $enc $c.ControlID)</td><td>$(& $enc $c.ControlName)</td><td style='color:$($colors[$c.Status]);font-weight:600'>$(& $enc $c.Status)</td><td>$(& $enc $c.Severity)</td><td>$(& $enc $c.Evidence)</td><td>$(& $enc $c.Recommendation)</td><td>$(& $enc $c.HIPAACitation)</td></tr>"
    }
    $summary = $Report.Controls | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }
@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>M365 Security Scan - $(& $enc $Report.OrgName)</title>
<style>body{font-family:-apple-system,Segoe UI,Arial,sans-serif;margin:32px;color:#1f2328}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #d0d7de;padding:8px;text-align:left;vertical-align:top}th{background:#f6f8fa}</style>
</head><body>
<h1>Microsoft 365 Security Scan</h1>
<p><strong>$(& $enc $Report.OrgName)</strong> ($(& $enc $Report.TenantDisplayName), $(& $enc $Report.TenantId))<br>Scanned $(& $enc $Report.ScanTimestampUtc) UTC<br>$($summary -join ' &middot; ')</p>
<table><tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>Evidence</th><th>Recommendation</th><th>HIPAA citation</th></tr>
$($rows -join "`n")
</table></body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Assert-RequiredModules

if ($AccessToken) {
    Write-Host "Connecting to Microsoft Graph with the supplied access token..." -ForegroundColor Cyan
    Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome
}
else {
    Write-Host "Connecting to Microsoft Graph (interactive sign-in)..." -ForegroundColor Cyan
    Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Scopes $RequiredScopes -NoWelcome
}

$context = Get-MgContext
$org = Get-MgOrganization | Select-Object -First 1

Write-Host "Connected to tenant: $($org.DisplayName) ($($org.Id))" -ForegroundColor Green
Write-Host "Running checks..." -ForegroundColor Cyan

$results = @()
$results += Test-MFAEnforcement
$results += Test-LegacyAuthBlocked
$results += Test-DeviceComplianceEncryption
$results += Test-DeviceComplianceAssignment
$results += Test-SignInLogActivity
$results += Test-GuestAccessRestriction
$results += Test-PrivilegedRoleSprawl
$results += Get-IncidentProcedureManualCheck

$report = [PSCustomObject]@{
    ReportSchemaVersion = "1.0"
    GeneratedBy         = "Invoke-M365SecurityScan.ps1"
    ScanTimestampUtc    = (Get-Date).ToUniversalTime().ToString("o")
    OrgName             = $OrgName
    TenantId            = $org.Id
    TenantDisplayName   = $org.DisplayName
    TotalControls       = $results.Count
    Controls            = $results
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$baseName = "M365SecurityScan_{0}_{1}" -f ($OrgName -replace '[^a-zA-Z0-9]', ''), (Get-Date -Format "yyyyMMdd_HHmmss")
$jsonPath = Join-Path $OutputPath "$baseName.json"
$htmlPath = Join-Path $OutputPath "$baseName.html"

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
ConvertTo-HtmlReport -Report $report | Out-File -FilePath $htmlPath -Encoding utf8

Write-Host ""
Write-Host "Scan complete. $($results.Count) controls checked." -ForegroundColor Green
Write-Host "JSON: $jsonPath" -ForegroundColor Green
Write-Host "HTML: $htmlPath" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
