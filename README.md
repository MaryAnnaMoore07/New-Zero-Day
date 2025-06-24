## **🛡️ Incident Response Report: Detection of New Zero Day Incident**

![Zero Day](https://github.com/user-attachments/assets/933cf0ce-9f26-44c2-ad32-d0aec8c70bf6)

## **📑 Table of Contents**
Executive Summary

Threat Overview

Timeline of Investigation

Technical Findings

Incident Response Actions

MITRE ATT&CK Techniques Mapped

Lessons Learned

Conclusion
____

## **📌 Executive Summary**
A new ransomware strain called PwnCrypt has surfaced, reportedly spreading via a PowerShell-based payload using AES-256 encryption. The ransomware targets directories like C:\Users\Public\Desktop, renaming files by appending .pwncrypt to the original filename (e.g., hello.txt → hello.pwncrypt.txt).

Upon internal concern from the CISO, a threat hunt was initiated to determine whether the ransomware had infiltrated the corporate environment. The threat hunt uncovered a confirmed hit on the device maryanna-vm-mde, triggering an immediate incident response.
____

## **🧠 Threat Overview**
Name: PwnCrypt Ransomware

Payload Type: PowerShell Script

Encryption Method: AES-256

File Target Behavior: Appends .pwncrypt to filenames

Primary Directory Targeted: C:\Users\Public\Desktop

IOC Indicator: Any files or scripts containing "pwncrypt"

Risk: Potential lateral movement within an immature security environment with no formal user awareness program.
____

## **⏱️ Timeline of Investigation**
Time (UTC)	Action Taken

18:00	Initiated hunt across MDE for files containing "pwncrypt"

18:02:59	Detected pwncrypt.ps1 execution via PowerShell on maryanna-vm-mde

18:03	Cross-referenced DeviceProcessEvents around timestamp

18:04	Checked DeviceNetworkEvents for signs of exfiltration

18:10	Isolated the affected device

18:15	Removed script, performed malware scan

18:30	Submitted reimage ticket for the affected endpoint
____

## **🔎 Technical Findings**
🔍 Step 1: IOC Search — File Event Activity
A query was executed within MDE DeviceFileEvents to identify any file activity associated with the known suspicious indicator "pwncrypt".

```
let VMName = "maryanna-vm-mde";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| order by Timestamp desc
```
✅ Multiple file events referencing pwncrypt were discovered.

![image](https://github.com/user-attachments/assets/b1c7338b-f61b-4837-8d84-98e33975387e)

____

## **⌚ Step 2: Process Timeline Correlation**
A specific instance of a PowerShell script execution was noted. The script pwncrypt.ps1 was executed at:

📌 Timestamp: 2025-04-29T18:02:59.9698061Z

Correlated process activity from 3 minutes before to 3 minutes after the timestamp:

```
let specificTime = datetime(2025-04-29T18:02:59.9698061Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```
⚠️ A PowerShell script named pwncrypt.ps1 was confirmed to have launched on the system.

![image](https://github.com/user-attachments/assets/9b5e802e-aaa9-49c4-969f-7ad84f720c06)
____

## **🌐 Step 3: Exfiltration Check**
A scan of DeviceNetworkEvents was conducted during the same 6-minute window to look for evidence of data exfiltration:

```
let VMName = "maryanna-vm-mde";
let specificTime = datetime(2025-04-29T18:02:59.9698061Z);
DeviceNetworkEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```
🟢 Result: No evidence of network exfiltration or suspicious outbound traffic observed.
_____

## **🚨 Incident Response Actions**
Action	Description

🛑 Isolation	Affected host is immediately isolated from the network.

🔍 Script Removal	pwncrypt.ps1 removed manually from the host.

🧪 Malware Scan	Full scan run on system — returned no results.

🛠️ Reimaging	Device flagged for rebuild as a precautionary step.

📝 Documentation: Full activity timeline and artifacts logged for post-mortem review.
____

## **🎯 MITRE ATT&CK Techniques Mapped**
ID	Technique	Details

T1059.001	PowerShell	PowerShell-based execution of pwncrypt.ps1.

T1560	Archive Collected Data (Assumed): If the script prepares or compresses files for encryption.

T1027	Obfuscated Files or Information (Potential): Possible use of obfuscated script content.

T1036	Masquerading (Potential)	File may appear legitimate to evade detection.

T1070.004	Indicator Removal on Host (Potential)	Script may clean logs or remove traces.

T1105	Ingress Tool Transfer (Future stage)	Suggests a prior remote delivery mechanism.
____

## **📚 Lessons Learned**
Early detection via IOC correlation (e.g., .pwncrypt) helped prevent a larger outbreak.

Organizations with immature security postures are especially vulnerable to script-based ransomware.

Lack of user training continues to be a high-risk vector; awareness programs must be prioritized.

Need to enhance behavioral detections for PowerShell usage, especially involving Public directories.
____

## **✅ Conclusion**
The presence of pwncrypt.ps1 on the corporate endpoint was a confirmed intrusion of a zero-day ransomware strain. While no data was exfiltrated and lateral movement was not detected, immediate containment, removal, and reimaging actions were taken. This incident underscores the need for foundational improvements in endpoint security, employee awareness, and ransomware detection strategies.

