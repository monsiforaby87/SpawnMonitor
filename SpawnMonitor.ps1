# Global tracking structures
$AllChildProcesses = @{}         # Dictionary to store all tracked processes
$MonitoredProcessIds = @()       # List of process IDs being monitored
$NewProcessesToMonitor = @()     # Queue for newly detected child processes
$LoopSleepMs = 200               # Sleep interval for the monitoring loop in milliseconds

# --- WMI Event Handler ---
$ProcessStartAction = {
    # Event triggered when a new process starts
    $event = $event.SourceEventArgs.NewEvent
    $ParentProcessId = $event.ParentProcessId
    $GlobalMonitoredIds = Get-Variable -Name 'MonitoredProcessIds' -Scope Global -ValueOnly

    # Ignore processes not spawned by monitored parents
    if ($GlobalMonitoredIds -notcontains $ParentProcessId) {
        return
    }

    # Extract details of the new process
    $NewProcessId = $event.ProcessId
    $ProcessName = $event.ProcessName
    $CreationDate = $event.CreationDate
    $CommandLine = $event.CommandLine

    $ExecutablePath = $null
    $sha256 = "Unavailable"

    # Attempt to retrieve executable path and compute SHA256 hash
    try {
        $procInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $NewProcessId" | Select-Object ExecutablePath
        $ExecutablePath = $procInfo.ExecutablePath
        if ($ExecutablePath -and (Test-Path $ExecutablePath)) {
            $sha256 = (Get-FileHash -Path $ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
    } catch {
        $ExecutablePath = "Unavailable"
    }

    # Access global tracking structures
    $GlobalAllChildren = Get-Variable -Name 'AllChildProcesses' -Scope Global -ValueOnly
    $GlobalNewQueue = Get-Variable -Name 'NewProcessesToMonitor' -Scope Global -ValueOnly

    # If process is not already tracked, add it to the queue
    if (-not $GlobalAllChildren.ContainsKey($NewProcessId)) {
        $NewProcessObject = [PSCustomObject]@{
            ProcessId      = $NewProcessId
            ParentProcessId= $ParentProcessId
            Name           = $ProcessName
            CreationDate   = $CreationDate
            CommandLine    = $CommandLine
            Path           = $ExecutablePath
            SHA256         = $sha256
            HasExited      = $true
            Status         = 'Terminated'
        }

        $GlobalNewQueue += $NewProcessObject
        Set-Variable -Name 'NewProcessesToMonitor' -Value $GlobalNewQueue -Scope Global

        # Log detection of new child process
        Write-Host "--> ⚡ INSTANTLY CAUGHT: $ProcessName (PPID: $ParentProcessId, PID: $NewProcessId) [STATUS: Pending Check]" -ForegroundColor Yellow
    }
}

# --- Initialization ---
# Prompt user for executable/script path to monitor
$FilePathToRun = Read-Host "Enter the FULL PATH to the executable or script file you want to monitor"
if (-not $FilePathToRun -or -not (Test-Path $FilePathToRun)) {
    Write-Warning "Invalid or missing file path. Exiting."
    exit 1
}

# Attempt to start the specified file
Write-Host "Attempting to start file: $FilePathToRun" -ForegroundColor Cyan
try {
    $parentProcess = Start-Process -FilePath $FilePathToRun -PassThru -ErrorAction Stop
} catch {
    Write-Error "Failed to start process: $($_.Exception.Message)"
    exit 1
}

# Capture parent process details
$parentId = $parentProcess.Id
$ParentProcessName = $parentProcess.Name
$parentCimInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" | Select-Object CommandLine, CreationDate -ErrorAction SilentlyContinue
$parentHash = (Get-FileHash -Path $FilePathToRun -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

# Log successful launch and begin tracking
Write-Host "Successfully launched and tracking parent process: Name='$ParentProcessName', ID='$parentId'"
$MonitoredProcessIds += $parentId

# Store parent process in tracking dictionary
$AllChildProcesses[$parentId] = [PSCustomObject]@{
    ProcessId      = $parentId
    ParentProcessId= $null
    Name           = $ParentProcessName
    CreationDate   = $parentCimInfo.CreationDate
    CommandLine    = $parentCimInfo.CommandLine
    Path           = $FilePathToRun
    SHA256         = $parentHash
    HasExited      = $false
    Status         = 'Active (Parent)'
}

# Register WMI event to detect new process creation
Register-WmiEvent -Class 'Win32_ProcessStartTrace' -Action $ProcessStartAction -SourceIdentifier 'ProcessCreationMonitor'

# Brief pause before starting monitoring loop
[System.Threading.Thread]::Sleep(500)

# Display monitoring start message
Write-Host "Starting combined event/polling monitor. Detection is instant. Display updates every $LoopSleepMs ms. Press Ctrl+C to stop."
Write-Host "-------------------------------------------------------------------------------------------------"

# --- Main Loop ---
while ($true) {
    # Add newly detected processes to tracking dictionary
    if ($NewProcessesToMonitor.Count -gt 0) {
        foreach ($newProcess in $NewProcessesToMonitor) {
            $id = $newProcess.ProcessId
            $AllChildProcesses[$id] = $newProcess
            if ($id -ne $parentId -and $MonitoredProcessIds -notcontains $id) {
                $MonitoredProcessIds += $id
            }
        }
        $NewProcessesToMonitor = @()
    }

    # Check status of all tracked processes
    foreach ($checkId in $AllChildProcesses.Keys) {
        $processEntry = $AllChildProcesses[$checkId]
        if ($checkId -eq $parentId -or $processEntry.Status -eq 'Terminated') {
            continue
        }

        # Update status based on whether process is still running
        $activeCheck = Get-Process -Id $checkId -ErrorAction SilentlyContinue
        if ($activeCheck) {
            $processEntry.Status = 'Active'
            $processEntry.HasExited = $false
        } else {
            $processEntry.Status = 'Terminated'
            $processEntry.HasExited = $true
            $MonitoredProcessIds = $MonitoredProcessIds | Where-Object { $_ -ne $checkId }
        }
    }

    # Check if parent process has exited
    $parentCheck = Get-Process -Id $parentId -ErrorAction SilentlyContinue
    if (-not $parentCheck) {
        # Mark all remaining active processes as terminated
        $AllChildProcesses.Values | Where-Object {$_.Status -eq 'Active'} | ForEach-Object {
            $_.Status = 'Terminated'
            $_.HasExited = $true
        }
        Write-Warning "Parent process (ID: $parentId) is no longer running. Final list captured."
        break
    }

    # Display current tracking status
    Clear-Host
    Write-Host "--- Monitoring: $ParentProcessName (ID: $parentId) ---" -ForegroundColor Cyan
    Write-Host "--- Processes (Last Updated: $(Get-Date -Format 'HH:mm:ss')) ---" -ForegroundColor Green
    Write-Host "-------------------------------------------------------------------------------------------------"

    $AllChildProcesses.Values | Sort-Object CreationDate |
    Format-Table ParentProcessId, ProcessId, Name, Path, SHA256, HasExited, CommandLine -AutoSize

    Write-Host "-------------------------------------------------------------------------------------------------"
    Write-Host "Currently tracking $($AllChildProcesses.Count) processes."
    Write-Host "Monitored for new children: $($MonitoredProcessIds.Count) IDs."
    Write-Host "Updating display every $LoopSleepMs ms. Press Ctrl+C to stop."

    # Sleep before next update
    [System.Threading.Thread]::Sleep($LoopSleepMs)
}

# --- Cleanup ---
# Unregister WMI event subscription
Write-Host "`nCLEANUP: Unregistering WMI event subscription..."
Get-EventSubscriber -SourceIdentifier 'ProcessCreationMonitor' | Unregister-Event

# Display final tracking results
Write-Host "`nFINAL TRACKING RESULTS for processes spawned by $ParentProcessName (ID: $parentId):" -ForegroundColor Yellow

$AllChildProcesses.Values | Sort-Object CreationDate |
Format-Table ParentProcessId, ProcessId, Name, Path, SHA256, HasExited, CommandLine -AutoSize
