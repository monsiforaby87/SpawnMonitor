# SpawnMonitor
Monitors a specified executable and tracks all child processes it spawns in real time. Captures process metadata including name, ID, command line, path, and SHA256 hash. Uses WMI events and polling for instant detection. Displays live status updates and final results when the parent process exits.

ProcessSentinel.ps1
 Overview
ProcessSentinel.ps1 is a real-time process monitoring script built in PowerShell. It launches a specified executable or script and continuously tracks all child processes it spawns. Using WMI event subscriptions and polling, it instantly detects new processes, logs detailed metadata, and displays live status updates until the parent process exits.

**Features**
Launches and monitors any executable or script file

Tracks all child processes spawned by the parent

Captures process metadata: name, ID, command line, creation time, executable path, and SHA256 hash

Uses WMI events for instant detection and polling for status updates

Displays a live table of active and terminated processes

Automatically cleans up and summarizes results when the parent process exits

**Requirements**
Windows OS with PowerShell 5.1 or later

Administrator privileges (recommended for full WMI access)

**Usage**
Open PowerShell as Administrator.

Run the script:

powershell
.\ProcessSentinel.ps1
Enter the full path to the executable or script you want to monitor when prompted.

Watch the live display update in real time.

Press Ctrl+C to stop manually or let it exit automatically when the parent process ends.

**Output**
Live console display showing all tracked processes

Final summary table of all child processes with their status and metadata

**Notes**
The script uses WMI event subscriptions, which may require elevated permissions.

SHA256 hashes are computed only if the executable path is accessible.

Designed for forensic analysis, debugging, and process behavior auditing.
