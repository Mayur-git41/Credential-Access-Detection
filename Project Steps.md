# Day 18 – Credential Access Detection

## Objective

Detect process access events using Sysmon Event ID 10.

## Tools

- Windows 11
- Sysmon
- Splunk Enterprise

## MITRE ATT&CK

- TA0006 – Credential Access
- T1003 – OS Credential Dumping
- T1003.001 – LSASS Memory

## Splunk Queries

### Process Access

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=10
| table _time SourceImage TargetImage GrantedAccess User
```

### LSASS Access

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=10 TargetImage="*lsass.exe"
| table _time SourceImage TargetImage GrantedAccess User
```

## Result

Observed Sysmon Process Access events and searched for access to `lsass.exe`. This exercise demonstrates how defenders can investigate activity related to credential access.

## Skills Learned

- Sysmon Event ID 10
- Splunk searches
- Credential Access detection
- MITRE ATT&CK mapping

# Day 19 – LSASS Access Detection Using Splunk

## Objective

The objective of this lab was to detect process access to the **Local Security Authority Subsystem Service (LSASS)** using **Sysmon Event ID 10** and **Splunk**. Monitoring LSASS access helps identify potential credential dumping attempts used by attackers.

---

## Lab Environment

- Oracle VirtualBox
- Windows 11
- Ubuntu
- Splunk Enterprise 9.4.3
- Sysmon

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Credential Access | OS Credential Dumping | T1003 |
| Credential Access | LSASS Memory | T1003.001 |

---

## Sysmon Event

**Event ID:** 10

**Description:** Process Access

This event logs when one process attempts to access another process. Monitoring access to **lsass.exe** is important because attackers often target it to dump credentials.

---

## Splunk Detection Query

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=10 lsass
```

---

## Detection Logic

- Search for Sysmon Process Access events.
- Filter events containing **lsass.exe**.
- Review the source process, target process, and access details.
- Investigate unexpected access to LSASS.

---

## Results

- Successfully searched Sysmon Event ID 10 logs in Splunk.
- Detected an event containing **lsass.exe**.
- Verified that the detection query correctly identifies LSASS-related process access.
- Confirmed the detection can be used to monitor potential credential access activity.

---

## Evidence

Include the screenshot:

**Screenshots/Day19-LSASS-Detection.png**

---

## Skills Learned

- Sysmon Event ID 10 Analysis
- Splunk SPL Queries
- Process Access Monitoring
- LSASS Detection
- Credential Access Detection
- MITRE ATT&CK Mapping

---

## Conclusion

This lab demonstrated how to detect LSASS process access using Sysmon and Splunk. The detection query successfully identified an Event ID 10 containing **lsass.exe**, validating the detection logic for monitoring potential credential dumping activity.

# Day 20 – Windows Discovery Detection Using Splunk

## Objective

The objective of Day 20 was to understand and detect common Windows Discovery activities using Sysmon and Splunk.

Attackers often perform discovery after gaining access to a system to learn about the computer, users, processes, and network configuration.

---

## Lab Environment

- Windows 11
- Sysmon
- Splunk Enterprise
- Splunk Universal Forwarder
- Oracle VirtualBox

---

## MITRE ATT&CK Mapping

| Discovery Activity | MITRE ATT&CK Technique | ID |
|---|---|---|
| User Discovery | System Owner/User Discovery | T1033 |
| Hostname Discovery | System Information Discovery | T1082 |
| System Information | System Information Discovery | T1082 |
| Network Configuration | System Network Configuration Discovery | T1016 |
| Process Discovery | Process Discovery | T1057 |

---

## Discovery Commands Tested

The following Windows commands were executed for learning and detection purposes:

```powershell
whoami
```

```powershell
hostname
```

```powershell
ipconfig
```

```powershell
systeminfo
```

```powershell
tasklist
```

```powershell
net user
```

These are legitimate Windows commands, but similar commands can also be used by attackers during system reconnaissance.

---

## Sysmon Event

### Event ID 1 – Process Creation

Sysmon Event ID 1 records the creation of a new process.

This event is useful for monitoring command execution and identifying suspicious discovery activity.

---

## Splunk Detection

### View Process Creation Events

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
```

### Search for Discovery Commands

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search whoami OR hostname OR ipconfig OR systeminfo OR tasklist
```

### Count Process Creation by Image

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
| stats count by Image
```

---

## Detection Logic

The detection process was:

1. Execute common Windows discovery commands.
2. Sysmon records the resulting process creation activity.
3. Sysmon logs are forwarded to Splunk.
4. Splunk extracts the XML fields using `xmlkv`.
5. Event ID 1 is searched for process creation activity.
6. Discovery-related commands are identified for investigation.

---

## Analysis

The commands used during this exercise are normal administrative commands and are not inherently malicious.

However, a combination of several discovery commands in a short period can provide useful context during a security investigation.

For example:

```text
whoami
hostname
ipconfig
systeminfo
tasklist
net user
```

When these commands appear together with other suspicious activity, a SOC analyst should investigate the associated user, process, parent process, command line, and timeline.

---

## Skills Learned

- Windows Discovery Techniques
- Sysmon Event ID 1
- Splunk SPL
- XML Event Parsing using `xmlkv`
- Process Creation Analysis
- Threat Hunting
- MITRE ATT&CK Mapping
- SOC Investigation

---

## Evidence

Add screenshots demonstrating:

- Windows discovery commands
- Sysmon Event ID 1
- Splunk search results
- Discovery command detection

Recommended screenshot name:

```text
Screenshots/Day20-Windows-Discovery.png
```

---

## Result

Successfully investigated Windows Discovery activity using Sysmon and Splunk.

The exercise demonstrated how a SOC analyst can use process creation telemetry to identify commands that may indicate system reconnaissance.

---

## Conclusion

# Day 21 – Registry Run Key Persistence Detection

## Objective

The objective of Day 21 was to understand and detect Windows Registry Run Key persistence using Sysmon and Splunk.

Registry Run Keys can be used to automatically execute programs when a user logs in. Attackers may abuse this mechanism to maintain persistence on a compromised Windows system.

---

## Lab Environment

* Windows 11
* Sysmon
* Splunk Enterprise
* Splunk Universal Forwarder
* Oracle VirtualBox

---

## MITRE ATT&CK Mapping

| Tactic      | Technique                                                             | ID        |
| ----------- | --------------------------------------------------------------------- | --------- |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |

---

## Registry Run Key Locations

### Current User

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Local Machine

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Programs configured in these locations can automatically start when a user logs in.

---

## Registry Commands Used

### Check Current User Run Keys

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Check Local Machine Run Keys

```powershell
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

These commands were used to inspect existing Run Key entries.

---

## Sysmon Event

### Event ID 13 – Registry Value Set

Sysmon Event ID 13 records registry value modifications.

This event can be useful for detecting changes to Registry Run Keys.

---

## Splunk Detection Queries

### View Registry Value Changes

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=13
```

### Search for Run Key Activity

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=13 Run
```

### Count Registry Value Changes

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=13
| stats count
```

---

## Detection Logic

The detection process was:

1. Identify important Windows Registry Run Key locations.
2. Review existing Run Key entries.
3. Monitor Sysmon Event ID 13.
4. Search Splunk for registry value modifications.
5. Look for activity related to `Run` registry keys.
6. Investigate the process, user, registry location, and value involved.

---

## Investigation Fields

When a suspicious Registry Run Key modification is detected, the following information should be investigated:

* Registry target
* Registry value
* Process responsible for the modification
* User account
* Executable path
* Timestamp
* Parent process

---

## Security Consideration

A Registry Run Key modification is not automatically malicious. Legitimate applications may also use Run Keys for startup functionality.

A SOC analyst should investigate the context of the modification and determine whether the executable and user activity are expected.

---

## Skills Learned

* Windows Registry Analysis
* Registry Run Key Persistence
* Sysmon Event ID 13
* Splunk SPL
* Persistence Detection
* Threat Hunting
* MITRE ATT&CK Mapping

---

## Evidence

Add screenshots demonstrating:

* Windows Run Key inspection
* Sysmon Event ID 13
* Splunk Registry Event Search
* Run Key detection results

Recommended screenshot:

```text
Screenshots/Day21-Registry-Run-Key.png
```

---

## Result

Successfully investigated Windows Registry Run Key persistence and learned how Sysmon Event ID 13 can be used with Splunk to monitor registry value modifications.

---

## Conclusion

Day 21 focused on detecting Registry Run Key persistence. Sysmon Event ID 13 and Splunk provide useful telemetry for monitoring registry modifications that could be associated with persistence.

The detection can be improved by correlating Registry Run Key modifications with the responsible process, user, executable path, and other suspicious activity.


Day 20 focused on Windows Discovery detection. By combining Sysmon Event ID 1 with Splunk searches, it is possible to monitor command execution and identify discovery activity that may be relevant during a security investigation.

The detection can be further improved by correlating discovery commands with the user, parent process, command line, and other suspicious events.

# Day 22 — Windows Service Persistence Detection

## Objective

The objective of Day 22 was to understand how attackers can abuse **Windows Services for persistence** and how a SOC Analyst can detect and investigate service creation using **Sysmon, Splunk, and Sigma**.

---

## Tools Used

* Windows 10/11 Virtual Machine
* Sysmon
* Splunk Enterprise
* Splunk Universal Forwarder
* Sigma
* PowerShell
* Windows Service Control (`sc.exe`)

---

## Attack Technique

**MITRE ATT&CK: T1543.003 — Windows Service**

Attackers can create or modify Windows Services to establish persistence on a compromised system. A service can be configured to execute a program when Windows starts or when the service is started.

In this lab, a harmless test service was created to generate telemetry for detection.

---

# Step 1 — Verify Sysmon

First, Sysmon was checked to make sure it was running.

```powershell
Get-Service Sysmon64
```

Expected result:

```text
Status   Name      DisplayName
------   ----      -----------
Running  Sysmon64  Sysmon64
```

**Screenshot:**
`01-sysmon-running.png`

---

# Step 2 — Create SOC Lab Directory

A directory was created for the laboratory activities.

```powershell
mkdir C:\SOC-Lab
```

The directory was verified using:

```powershell
Test-Path C:\SOC-Lab
```

Expected output:

```text
True
```

**Screenshot:**
`02-soc-lab-directory.png`

---

# Step 3 — Create a Test Windows Service

A harmless test service was created using the Windows Service Control utility.

```powershell
sc.exe create SOC-Test-Service binPath= "C:\Windows\System32\svchost.exe" start= demand
```

Expected output:

```text
[SC] CreateService SUCCESS
```

The service was **not started**.

The service was verified using:

```powershell
Get-Service SOC-Test-Service
```

Expected result:

```text
Status   Name                DisplayName
------   ----                -----------
Stopped  SOC-Test-Service    SOC-Test-Service
```

**Screenshot:**
`03-service-created.png`

---

# Step 4 — Verify Sysmon Event

Sysmon Event ID 1 was searched because Event ID 1 records **Process Creation**.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 20 | Format-List TimeCreated, Id, ProviderName, Message
```

The event containing:

```text
sc.exe create SOC-Test-Service
```

was identified.

**Screenshot:**
`04-sysmon-event.png`

---

# Step 5 — Find the Event in Splunk

The Sysmon event was searched in Splunk using:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
| search "SOC-Test-Service"
```

The event was successfully received by Splunk.

**Screenshot:**
`05-splunk-event.png`

---

# Step 6 — Extract Important Fields

The following Splunk query was used to display important investigation fields:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1 "SOC-Test-Service"
| table _time host Computer User Image CommandLine ParentImage ParentCommandLine
```

Important fields included:

* Time
* Host
* Computer
* User
* Image
* CommandLine
* ParentImage
* ParentCommandLine

These fields help a SOC Analyst understand **who executed the command, what was executed, and which process started it**.

**Screenshot:**
`06-splunk-fields.png`

---

# Step 7 — Create Splunk Detection

A detection query was created to identify service creation using `sc.exe`.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
| search Image="*\\sc.exe"
| search CommandLine="* create *"
| table _time host Computer User Image CommandLine ParentImage ParentCommandLine
```

An enhanced version was also created:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
| search Image="*\\sc.exe" CommandLine="* create *"
| eval Detection="Potential Service Persistence"
| table _time host User Image CommandLine ParentImage Detection
```

The event was successfully identified as:

```text
Potential Service Persistence
```

**Screenshot:**
`07-splunk-detection.png`

---

# Step 8 — Create Sigma Rule

A Sigma rule was created to detect suspicious service creation using `sc.exe`.

File:

```text
service_creation.yml
```

Sigma rule:

```yaml
title: Suspicious Windows Service Creation
id: 8c2d5b8a-7f2e-4b3a-9d61-123456789001
status: experimental
description: Detects service creation using sc.exe, which may indicate persistence.
author: Mayur
date: 2026-08-18
logsource:
    product: windows
    category: process_creation

detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains: ' create '
    condition: selection

falsepositives:
    - Legitimate software installation
    - System administration
    - IT maintenance

level: medium

tags:
    - attack.persistence
    - attack.t1543.003
```

**Screenshot:**
`08-sigma-rule.png`

---

# Step 9 — Validate Sigma Rule

The Sigma rule was validated using:

```bash
sigma check service_creation.yml
```

The rule was checked for syntax and configuration errors.

**Screenshot:**
`09-sigma-validation.png`

---

# Step 10 — SOC Investigation

The generated alert was investigated using the Splunk event data.

The following information was examined:

| Investigation Field | Purpose                               |
| ------------------- | ------------------------------------- |
| Time                | Determine when the activity occurred  |
| User                | Identify who executed the action      |
| Host                | Identify the affected endpoint        |
| Image               | Identify the executable               |
| CommandLine         | Understand the exact command          |
| ParentImage         | Identify the process that launched it |
| ParentCommandLine   | Understand the execution context      |

The process chain was analyzed:

```text
PowerShell
    ↓
sc.exe
    ↓
Service Creation
    ↓
SOC-Test-Service
```

---

# Alert Assessment

The detection was classified as:

```text
Severity: Medium
Verdict: Benign / Authorized
```

### Reason

The service was intentionally created as part of the SOC laboratory exercise.

Although the activity was benign in this lab, the same behavior could be suspicious in a real environment.

A SOC Analyst would investigate:

* Unexpected service creation
* Unknown service names
* Suspicious executable paths
* Services created by unexpected users
* Suspicious parent processes
* Automatic service startup
* Other correlated security events

**Screenshot:**
`10-soc-investigation.png`

---

# Step 11 — Cleanup

After completing the investigation, the test service was removed.

```powershell
sc.exe delete SOC-Test-Service
```

Expected output:

```text
[SC] DeleteService SUCCESS
```

The service was then verified to ensure it had been removed.

**Screenshot:**
`11-cleanup.png`

---

# Detection Flow

```text
Windows Endpoint
       |
       v
Service Creation
       |
       v
sc.exe
       |
       v
Sysmon Event ID 1
       |
       v
Splunk Universal Forwarder
       |
       v
Splunk Enterprise
       |
       v
Detection Query
       |
       v
Potential Service Persistence
       |
       v
SOC Investigation
       |
       v
Benign / Suspicious / Malicious
```

---

# MITRE ATT&CK Mapping

| Technique                                        | ID        | Description                                          |
| ------------------------------------------------ | --------- | ---------------------------------------------------- |
| Create or Modify System Process: Windows Service | T1543.003 | Attackers can abuse Windows Services for persistence |

---

# Key Learning Outcomes

After completing Day 22, I learned:

1. How Windows Services can be abused for persistence.
2. How `sc.exe` can create Windows Services.
3. How Sysmon Event ID 1 records process creation.
4. How to search Sysmon telemetry in Splunk.
5. How to create a Splunk detection query.
6. How to create a Sigma detection rule.
7. How to investigate a service-creation alert.
8. How to distinguish legitimate administrative activity from potentially malicious activity.
9. How to map a detection to MITRE ATT&CK.
10. How to clean up a SOC laboratory environment after testing.

---

# Conclusion

Day 22 demonstrated a complete SOC detection workflow for Windows Service persistence.

The activity was generated in a controlled laboratory environment, monitored using Sysmon, forwarded to Splunk, detected using a Splunk query, converted into a Sigma rule, and investigated using standard SOC analysis techniques.

The exercise demonstrated how a SOC Analyst can move from **endpoint telemetry → detection → investigation → classification → remediation/cleanup**.
