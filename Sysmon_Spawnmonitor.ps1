cls
# Prompt for executable path
$exePath = Read-Host "Enter the FULL PATH of the executable to monitor"
if (-not (Test-Path $exePath)) {
    Write-Error "Invalid path. Exiting."
    exit
}

# Start the process
try {
    $parentProcess = Start-Process -FilePath $exePath -PassThru
    $parentId = $parentProcess.Id
    Write-Host "Started process '$($parentProcess.Name)' with PID $parentId" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to start process: $($_.Exception.Message)"
    exit
}

# Initialize tracking lists
$TrackedProcesses = @{}
$TrackedNetwork = @{}
$TrackedDnsQueries = @{}
$TrackedProcesses[$parentId] = [PSCustomObject]@{
    PID                  = $parentId
    ParentProcessId      = $null
    ProcessName          = $parentProcess.Name
    Path                 = $exePath
    CommandLine          = $null
    SHA256               = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    HasNetworkConnectivity = $false
}

# Monitoring loop
while ($true) {
    # Stop if parent process exits
    if (-not (Get-Process -Id $parentId -ErrorAction SilentlyContinue)) {
        Write-Warning "Parent process has exited. Finalizing report..."
        break
    }

    # Query Sysmon logs for ProcessCreate (EventID=1), NetworkConnect (EventID=3), and DnsQuery (EventID=22)
    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1 or EventID=3 or EventID=22)]]
    </Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $filterXml -MaxEvents 500 -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventId = [int]$xml.Event.System.EventID

        # Process creation events
        if ($eventId -eq 1) {
            $procId = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessId" }).'#text'
            $ppid = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessId" }).'#text'
            if ($TrackedProcesses.ContainsKey($ppid) -and -not $TrackedProcesses.ContainsKey($procId)) {
                $path = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
                $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
                $name = Split-Path $path -Leaf
                $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $TrackedProcesses[$procId] = [PSCustomObject]@{
                    PID                  = $procId
                    ParentProcessId      = $ppid
                    ProcessName          = $name
                    Path                 = $path
                    CommandLine          = $cmd
                    SHA256               = $hash
                    HasNetworkConnectivity = $false
                }
            }
        }
        # Network connection events
        elseif ($eventId -eq 3) {
            $procId = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessId" }).'#text'
            if ($TrackedProcesses.ContainsKey($procId)) {
                $sourceIp = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SourceIp" }).'#text'
                $sourcePort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SourcePort" }).'#text'
                $destIp = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" }).'#text'
                $destPort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationPort" }).'#text'

                $networkKey = "$procId-$sourceIp-$sourcePort-$destIp-$destPort"
                if (-not $TrackedNetwork.ContainsKey($networkKey)) {
                    $TrackedNetwork[$networkKey] = [PSCustomObject]@{
                        PID             = $procId
                        ProcessName     = $TrackedProcesses[$procId].ProcessName
                        SourceIP        = $sourceIp
                        SourcePort      = $sourcePort
                        DestinationIP   = $destIp
                        DestinationPort = $destPort
                        Status          = "Success"
                        RequestCount    = 1
                    }
                    $TrackedProcesses[$procId].HasNetworkConnectivity = $true
                } else {
                    $TrackedNetwork[$networkKey].RequestCount += 1
                }
            }
        }
        # DNS query events
        elseif ($eventId -eq 22) {
            $procId = [int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessId" }).'#text'
            if ($TrackedProcesses.ContainsKey($procId)) {
                $queryName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "QueryName" }).'#text'
                $queryKey = "$procId-$queryName"
                if (-not $TrackedDnsQueries.ContainsKey($queryKey)) {
                    $TrackedDnsQueries[$queryKey] = [PSCustomObject]@{
                        PID         = $procId
                        ProcessName = $TrackedProcesses[$procId].ProcessName
                        QueryName   = $queryName
                    }
                }
            }
        }
    }

    # Check for DNS queries without corresponding connections
    foreach ($queryKey in $TrackedDnsQueries.Keys) {
        $dnsQuery = $TrackedDnsQueries[$queryKey]
        $procId = $dnsQuery.PID
        $queryName = $dnsQuery.QueryName
        $networkKey = "$procId-N/A-N/A-$queryName-N/A"
        if (-not $TrackedNetwork.ContainsKey($networkKey)) {
            # Check if any connection used the resolved IP (simplified check)
            $hasConnection = $false
            foreach ($connection in $TrackedNetwork.Values) {
                if ($connection.PID -eq $procId -and $connection.Status -eq "Success") {
                    $hasConnection = $true
                    break
                }
            }
            if (-not $hasConnection) {
                $TrackedNetwork[$networkKey] = [PSCustomObject]@{
                    PID             = $procId
                    ProcessName     = $dnsQuery.ProcessName
                    SourceIP        = "N/A"
                    SourcePort      = "N/A"
                    DestinationIP   = $queryName
                    DestinationPort = "N/A"
                    Status          = "Failed"
                    RequestCount    = 1
                }
                $TrackedProcesses[$procId].HasNetworkConnectivity = $true
            }
        } else {
            $TrackedNetwork[$networkKey].RequestCount += 1
        }
    }

    # Clear DNS queries for next iteration
    $TrackedDnsQueries = @{}

    # Display split screen (same as final report)
    Clear-Host
    Write-Host "--- Processes ---" -ForegroundColor Cyan
    $TrackedProcesses.Values | Sort-Object PID | Format-Table PID, ParentProcessId, ProcessName, HasNetworkConnectivity -AutoSize
    Write-Host "`n" + ("-" * 50) + "`n" # Separator
    Write-Host "--- Network Activity ---" -ForegroundColor Cyan
    foreach ($entry in ($TrackedNetwork.Values | Sort-Object PID)) {
        $color = if ($entry.Status -eq "Failed") { "Red" } else { "Green" }
        Write-Host "PID: $($entry.PID) ($($entry.ProcessName)) | $($entry.SourceIP):$($entry.SourcePort) -> $($entry.DestinationIP):$($entry.DestinationPort) [Requests: $($entry.RequestCount)]" -ForegroundColor $color
    }

    Start-Sleep -Seconds 5
}

# Final process report
Write-Host "`n📋 Final Process Report:" -ForegroundColor Green
$TrackedProcesses.Values | Sort-Object PID | Format-Table PID, ParentProcessId, ProcessName, Path, CommandLine, SHA256, HasNetworkConnectivity -AutoSize

# Final network report
Write-Host "`n📋 Final Network Activity Overview:" -ForegroundColor Green
foreach ($entry in ($TrackedNetwork.Values | Sort-Object PID)) {
    $color = if ($entry.Status -eq "Failed") { "Red" } else { "Green" }
    Write-Host "PID: $($entry.PID) ($($entry.ProcessName)) | $($entry.SourceIP):$($entry.SourcePort) -> $($entry.DestinationIP):$($entry.DestinationPort) [Requests: $($entry.RequestCount)]" -ForegroundColor $color
}

# Export final logs
$csvProcessFinalPath = "C:\Temp\process_log_final.csv"
$csvNetworkFinalPath = "C:\Temp\network_log_final.csv"
$csvDir = "C:\Temp"
if (-not (Test-Path $csvDir)) {
    New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
}

# Prompt for final CSV paths
$csvProcessDefault = $csvProcessFinalPath
$csvNetworkDefault = $csvNetworkFinalPath
$csvProcessPath = Read-Host "Enter path to save final process CSV file (default: $csvProcessDefault)"
$csvNetworkPath = Read-Host "Enter path to save final network CSV file (default: $csvNetworkDefault)"
if (-not $csvProcessPath) { $csvProcessPath = $csvProcessDefault }
if (-not $csvNetworkPath) { $csvNetworkPath = $csvNetworkDefault }

# Ensure directories exist
$csvProcessDir = Split-Path $csvProcessPath
$csvNetworkDir = Split-Path $csvNetworkPath
if (-not (Test-Path $csvProcessDir)) {
    New-Item -Path $csvProcessDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $csvNetworkDir)) {
    New-Item -Path $csvNetworkDir -ItemType Directory -Force | Out-Null
}

# Export to CSV
try {
    $TrackedProcesses.Values | Sort-Object PID | Export-Csv -Path $csvProcessPath -NoTypeInformation -Encoding UTF8
    $TrackedNetwork.Values | Select-Object PID, ProcessName, SourceIP, SourcePort, DestinationIP, DestinationPort, RequestCount | Sort-Object PID | Export-Csv -Path $csvNetworkPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n✅ Final process results exported to: $csvProcessPath" -ForegroundColor Green
    Write-Host "✅ Final network results exported to: $csvNetworkPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export CSV: $($_.Exception.Message)"
}