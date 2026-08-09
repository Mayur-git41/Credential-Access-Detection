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

Day 20 focused on Windows Discovery detection. By combining Sysmon Event ID 1 with Splunk searches, it is possible to monitor command execution and identify discovery activity that may be relevant during a security investigation.

The detection can be further improved by correlating discovery commands with the user, parent process, command line, and other suspicious events.
