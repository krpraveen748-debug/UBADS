#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables the "Process Creation" and/or "Plug and Play Events" audit
    subcategories, for Phase 4 process/device-activity testing.

.DESCRIPTION
    Unlike file-system auditing, these two subcategories are NOT scoped to
    a specific object/folder - they are simple global on/off switches for
    their event category, and are commonly recommended as baseline Windows
    security auditing settings. This script does not touch any other audit
    subcategory, does not disable any existing Windows security feature,
    and does not enable "include command line in process creation events"
    (a separate, optional Group Policy setting this project deliberately
    does not turn on - see README Privacy section).

    NOTE: this file is plain ASCII on purpose (no em-dashes or other
    non-ASCII punctuation). Windows PowerShell 5.1 reads a .ps1 file with
    no byte-order-mark using the system's legacy ANSI code page rather than
    UTF-8; a multi-byte UTF-8 character can then be misread as several
    separate legacy-codepage characters, one of which can coincidentally be
    a "smart quote" character that PowerShell's parser accepts as an
    alternate string delimiter - silently terminating a string literal
    early and producing a cascading "string is missing the terminator"
    error reported at the end of the file, far from the real cause. Keeping
    this script ASCII-only avoids that failure mode regardless of which
    PowerShell version or system locale runs it.

.PARAMETER Category
    Which subcategory to enable: "process", "device", or "both" (default).

.EXAMPLE
    .\enable_process_and_device_audit.ps1
.EXAMPLE
    .\enable_process_and_device_audit.ps1 -Category process
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet("process", "device", "both")]
    [string]$Category = "both"
)

$actions = @()
if ($Category -in @("process", "both")) {
    $actions += @{ Subcategory = "Process Creation"; EventId = "4688"; Uses = "process_activity" }
}
if ($Category -in @("device", "both")) {
    $actions += @{ Subcategory = "Plug and Play Events"; EventId = "6416"; Uses = "device_activity" }
}

Write-Host "This will enable the following audit subcategories (Success events):"
foreach ($a in $actions) {
    Write-Host "  - $($a.Subcategory)  -> generates event $($a.EventId), used by --categories $($a.Uses)"
}
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("local audit policy", "Enable $($actions.Subcategory -join ', ')")) {
    Write-Host "Cancelled - no changes made."
    exit 0
}

foreach ($a in $actions) {
    Write-Host "Enabling '$($a.Subcategory)'..."
    auditpol /set /subcategory:"$($a.Subcategory)" /success:enable
    if ($LASTEXITCODE -ne 0) {
        Write-Error "auditpol failed for '$($a.Subcategory)' (exit code $LASTEXITCODE). Are you running this as Administrator?"
        exit 1
    }
}

Write-Host ""
Write-Host "Done. Test it, e.g.:"
Write-Host "  python collector.py --categories process_activity,device_activity --limit 20"
Write-Host ""
Write-Host "To reverse later:"
foreach ($a in $actions) {
    Write-Host "  auditpol /set /subcategory:`"$($a.Subcategory)`" /success:disable"
}
