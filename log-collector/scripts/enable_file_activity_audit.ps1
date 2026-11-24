#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables Windows Object Access ("File System") auditing for ONE specific,
    explicitly named folder - for Phase 4 file-activity testing only.

.DESCRIPTION
    This script does two things, and ONLY these two things:

    1. Enables the "File System" audit subcategory globally via auditpol.
       This is a prerequisite switch - without it, Windows will not write
       4656/4660/4663 events for ANY object, no matter its SACL. Enabling
       it alone does not audit anything by itself; it only allows auditing
       to happen where a SACL (step 2) has been explicitly configured.

    2. Adds a file-system audit rule (SACL) to the ONE folder path you pass
       in via -Path. This is what actually causes Windows to log activity
       in that folder. No other folder on the system is affected.

    This script does NOT enable auditing broadly across the computer, does
    NOT touch any folder other than the one you specify, and does NOT
    disable any existing Windows security feature.

    NOTE: this file is plain ASCII on purpose (no em-dashes or other
    non-ASCII punctuation). Windows PowerShell 5.1 reads a .ps1 file with
    no byte-order-mark using the system's legacy ANSI code page rather than
    UTF-8; a multi-byte UTF-8 character can then be misread as several
    separate legacy-codepage characters, one of which can coincidentally be
    a "smart quote" character that PowerShell's parser accepts as an
    alternate string delimiter - silently terminating a string literal
    early and corrupting how the rest of the script is tokenized (this is
    what caused this script's earlier "Unexpected token" parse error at a
    later closing brace). Keeping this script ASCII-only avoids that
    failure mode regardless of which PowerShell version or system locale
    runs it.

.PARAMETER Path
    The single, explicitly authorized test folder to audit. Must already
    exist. You are responsible for only pointing this at a folder you are
    authorized to monitor (e.g. a dedicated test folder you created for
    this research project).

.PARAMETER Principal
    The account/group whose access to audit. Defaults to "Everyone" so
    testing under your own account works regardless of how you're logged
    in; narrow this to a specific username if you want to audit only one
    account.

.EXAMPLE
    .\enable_file_activity_audit.ps1 -Path "C:\Users\you\Documents\UBADS_TestFolder"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Principal = "Everyone"
)

if (-not (Test-Path -Path $Path -PathType Container)) {
    Write-Error "Path '$Path' does not exist or is not a folder. Create it first, then re-run this script."
    exit 1
}

$resolvedPath = (Resolve-Path $Path).Path

Write-Host "This will:"
Write-Host "  1. Enable the 'File System' audit subcategory (auditpol) - a global switch, required for any object-access auditing to be recorded at all."
Write-Host "  2. Add a Success+Failure audit rule for '$Principal' on this folder ONLY:"
Write-Host "       $resolvedPath"
Write-Host ""

if (-not $PSCmdlet.ShouldProcess($resolvedPath, "Enable file-system access auditing for '$Principal'")) {
    Write-Host "Cancelled - no changes made."
    exit 0
}

Write-Host "Enabling 'File System' audit subcategory..."
auditpol /set /subcategory:"File System" /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) {
    Write-Error "auditpol failed (exit code $LASTEXITCODE). Are you running this as Administrator?"
    exit 1
}

Write-Host "Adding audit rule (SACL) to '$resolvedPath'..."
$acl = Get-Acl -Path $resolvedPath -Audit
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $Principal,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AuditFlags]"Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl -Path $resolvedPath -AclObject $acl

Write-Host ""
Write-Host "Done. File activity (create/modify/delete/access) under '$resolvedPath' will now generate Security log events 4656/4660/4663."
Write-Host "Test it: create, edit, and delete a file in that folder, then run:"
Write-Host "  python collector.py --categories file_activity --limit 20"
Write-Host ""
Write-Host "To reverse this later: remove the audit rule via the folder's Properties > Security > Advanced > Auditing tab in Explorer, and/or run:"
Write-Host "  auditpol /set /subcategory:`"File System`" /success:disable /failure:disable"
