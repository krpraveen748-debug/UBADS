# Process sampler for the installer tests: records (pid, parent, name, exe path, command line) of
# UBADS-related processes every ~100 ms until a stop file appears. Used to prove the enrollment
# code never appears on any command line and to show the real process ancestry.
param([string]$Out, [string]$Stop)
$seen = @{}
while (-not (Test-Path $Stop)) {
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -like 'UBADS*' -or $_.Name -like 'ubads-agent*' -or $_.Name -like 'is-*' } |
        ForEach-Object {
            $key = "$($_.ProcessId)|$($_.CommandLine)"
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                [pscustomobject]@{
                    pid = $_.ProcessId; ppid = $_.ParentProcessId; name = $_.Name
                    path = $_.ExecutablePath; cmd = $_.CommandLine
                } | ConvertTo-Json -Compress | Add-Content -Path $Out -Encoding UTF8
            }
        }
    Start-Sleep -Milliseconds 80
}
