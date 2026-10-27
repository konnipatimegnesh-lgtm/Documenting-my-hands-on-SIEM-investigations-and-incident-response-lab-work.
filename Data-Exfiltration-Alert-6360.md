# Incident Report: Data Exfiltration via PowerShell & 7-Zip

## Objective
Investigated a High-severity SIEM alert (Alert 6360) regarding a suspicious outbound network connection following archive creation. The goal was to determine if data was actively being exfiltrated and to identify the attack chain.

## Investigation Steps (Splunk)
1. **Initial Triage:** The alert indicated `powershell.exe` initiated an outbound connection immediately after an archive file was created.
2. **Process Analysis:** Searched Splunk for the PowerShell Process ID (14264). Identified the parent script as `C:\Windows\Temp\svchost_update.ps1`, a known malicious payload running from a Temp directory.
3. **Data Staging Discovery:** Traced the malicious script's activity and discovered it executed `7z.exe` (7-Zip) via the command line: 
   `"C:\Program Files\7-Zip\7z.exe" a -mx=1 C:\Windows\Temp\nx_build_beta.7z C:\Dev\NeuralNexus\Build\*`
   This confirmed the attacker was compressing the highly sensitive `NeuralNexus\Build` directory into a hidden staging file.
4. **Exfiltration Confirmation:** Immediately after the `.7z` file was created, the PowerShell process initiated a continuous TCP connection to `45.147.230.131` on port `8067` to exfiltrate the staged data.

## Indicators of Compromise (IOCs)
* **Malicious IP (C2/Exfiltration):** 45.147.230.131
* **Malicious Script:** svchost_update.ps1
* **Staged Archive:** nx_build_beta.7z

## Remediation Actions Taken
* Isolated the compromised hosts (THM-SREYES, THM-MSMITH) from the network.
* Blocked the C2 IP `45.147.230.131` at the perimeter firewall.
* Terminated malicious PowerShell processes and deleted the staging archive (`nx_build_beta.7z`).
