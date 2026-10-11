param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath -PathType Leaf)) {
    Write-Error "Error: binary not found at $ExePath"
    exit 1
}

$resolvedExe = (Resolve-Path $ExePath).Path
$tmpDir = Join-Path $env:TEMP ("gostpx-smoke-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

$env:GOSTPX_SELFTEST = "1"
$env:GOSTPX_CONFIG_DIR = $tmpDir
$env:GOSTPX_SYSPROXY_DRY = (Join-Path $tmpDir "sysproxy.json")

Write-Host "=== Running Windows smoke test on $resolvedExe ==="
Write-Host "GOSTPX_CONFIG_DIR=$($env:GOSTPX_CONFIG_DIR)"
Write-Host "GOSTPX_SYSPROXY_DRY=$($env:GOSTPX_SYSPROXY_DRY)"

$stdoutFile = Join-Path $tmpDir "selftest_stdout.log"
$stderrFile = Join-Path $tmpDir "selftest_stderr.log"

$exitCode = $null
$process = $null

try {
    # Launch GUI process redirecting stdout and stderr to files (GUI subsystem has no console)
    $process = Start-Process -FilePath $resolvedExe `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile `
        -PassThru -NoNewWindow

    # Wait up to 120 seconds with Wait-Process watchdog
    try {
        Wait-Process -InputObject $process -Timeout 120 -ErrorAction Stop
    } catch {
        Write-Error "Watchdog timeout: $resolvedExe did not exit within 120 seconds"
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $exitCode = 1
    }

    if ($null -eq $exitCode) {
        # Flush process handles and read ExitCode
        $process.WaitForExit()
        $process.Refresh()
        $exitCode = $process.ExitCode
    }
} catch {
    Write-Error "Failed to execute smoke test: $_"
    $exitCode = 1
} finally {
    Write-Host "=== Selftest Output (stdout) ==="
    if (Test-Path $stdoutFile) {
        Get-Content $stdoutFile | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "(no stdout file generated)"
    }

    Write-Host "=== Selftest Output (stderr) ==="
    if (Test-Path $stderrFile) {
        Get-Content $stderrFile | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "(no stderr file generated)"
    }

    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Empty / null exit code must be treated as failure
if ($null -eq $exitCode -or "$exitCode" -eq "") {
    Write-Error "=== Windows smoke test FAILED (exit code is null/empty) ==="
    exit 1
}

if ($exitCode -eq 0) {
    Write-Host "=== Windows smoke test PASSED (exit code 0) ==="
    exit 0
} else {
    Write-Error "=== Windows smoke test FAILED (exit code $exitCode) ==="
    exit $exitCode
}
