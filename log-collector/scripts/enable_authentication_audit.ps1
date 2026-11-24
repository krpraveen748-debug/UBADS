#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables the "Logon" and "Logoff" audit subcategories, for real
    authentication-event verification (event IDs 4624/4625/4634/4647).

.DESCRIPTION
    log-collector's documentation has long assumed these events are
    "audited by default" on any Windows install, based on typical Windows
    Server / Group Policy baselines. That assumption does NOT reliably
    hold on a Windows Home edition machine with no Active Directory/Group
    Policy pushing an audit baseline - "Logon"/"Logoff" can be left at
    "No Auditing" out of the box, in which case 4624/4625/4634/4647 are
    never written at all, no matter how correct the collector is.

    This script does two things, and ONLY these two things - the same
    global-switch pattern as enable_process_and_device_audit.ps1:

    1. Enables "Logon" auditing (Success AND Failure) via auditpol - this
       covers both 4624 (successful logon) and 4625 (failed logon).
    2. Enables "Logoff" auditing (Success only - Windows does not define a
       "failed logoff" event) via auditpol - this covers 4634 (logoff) and
       4647 (user-initiated logoff).

    This script does NOT touch any other audit subcategory, does NOT
    enable "include command line in process creation events" or any
    unrelated policy, and does NOT disable any existing Windows security
    feature. Like the other two scripts in this folder, it never creates
    scheduled tasks, never installs anything, and never elevates itself -
    #Requires -RunAsAdministrator above simply refuses to run unless you
    already launched an elevated PowerShell yourself.

.PARAMETER WhatIf
    Preview what would change without making any change (standard
    PowerShell common parameter, enabled by SupportsShouldProcess below).

.EXAMPLE
    .\enable_authentication_audit.ps1
.EXAMPLE
    .\enable_authentication_audit.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

$actions = @(
    @{ Subcategory = "Logon"; Flags = "/success:enable /failure:enable"; EventIds = "4624, 4625"; Uses = "authentication" }
    @{ Subcategory = "Logoff"; Flags = "/success:enable"; EventIds = "4634, 4647"; Uses = "authentication" }
)

Write-Host "This will enable the following audit subcategories:"
foreach ($a in $actions) {
    Write-Host "  - $($a.Subcategory) ($($a.Flags))  -> generates event(s) $($a.EventIds), used by --categories $($a.Uses)"
}
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("local audit policy", "Enable $($actions.Subcategory -join ', ')")) {
    Write-Host "Cancelled - no changes made."
    exit 0
}

foreach ($a in $actions) {
    Write-Host "Enabling '$($a.Subcategory)' ($($a.Flags))..."
    $flagArgs = $a.Flags -split " "
    auditpol /set /subcategory:"$($a.Subcategory)" @flagArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "auditpol failed for '$($a.Subcategory)' (exit code $LASTEXITCODE). Are you running this as Administrator?"
        exit 1
    }
}

Write-Host ""
Write-Host "Done. Test it, e.g.:"
Write-Host "  python collector.py --categories authentication --limit 20"
Write-Host ""
Write-Host "To verify the resulting effective policy without changing anything:"
Write-Host "  auditpol /get /subcategory:`"Logon`",`"Logoff`""
Write-Host ""
Write-Host "To reverse later:"
Write-Host "  auditpol /set /subcategory:`"Logon`" /success:disable /failure:disable"
Write-Host "  auditpol /set /subcategory:`"Logoff`" /success:disable"
