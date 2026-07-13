# Credential Access Detection Using Sigma Rules

## Project Summary

This project demonstrates the design and implementation of a detection engineering lab focused on identifying credential theft activities on Windows systems. The solution leverages Sysmon telemetry, Windows Event Logs, Sigma rules, and Splunk to detect behaviors commonly associated with credential dumping attacks.

The objective was to simulate real-world Security Operations Center (SOC) workflows by collecting endpoint telemetry, developing detections, validating alerts, and mapping findings to the MITRE ATT&CK framework.

---

## Business Problem

Credential theft remains one of the most frequently used techniques by attackers to gain unauthorized access, escalate privileges, and move laterally within enterprise environments.

Security teams must be able to detect:

* Credential dumping tools such as Mimikatz
* Unauthorized access to the LSASS process
* Suspicious PowerShell activity
* Abnormal process creation patterns
* Indicators of credential harvesting attempts

This project addresses these challenges by implementing endpoint visibility and detection mechanisms that can identify potential credential access activity at an early stage.

---

## Solution Overview

A Windows endpoint was configured with Sysmon to generate detailed security telemetry. Sigma rules were then used to define detection logic for credential access techniques. The generated events were collected and analyzed in Splunk to validate detections and investigate suspicious behavior.

### Detection Workflow

```text
Windows Endpoint
        │
        ▼
     Sysmon
        │
        ▼
Windows Event Logs
        │
        ▼
Sigma Detection Rules
        │
        ▼
Splunk Analysis & Alerting
        │
        ▼
Security Investigation
```

---

## Technologies Used

| Technology                 | Purpose                       |
| -------------------------- | ----------------------------- |
| Sysmon                     | Endpoint telemetry collection |
| Sigma Rules                | Detection rule creation       |
| Splunk Enterprise          | Log ingestion and analysis    |
| Splunk Universal Forwarder | Event forwarding              |
| Windows Event Logs         | Security event source         |
| PowerShell                 | Attack simulation and testing |
| VirtualBox                 | Lab virtualization            |
| MITRE ATT&CK               | Threat mapping framework      |

---

## Project Implementation

### 1. Endpoint Monitoring Setup

Configured Sysmon on a Windows virtual machine to capture detailed security events including:

* Process creation
* Process access
* Parent-child process relationships
* Command-line arguments
* Security-relevant system activity

This provided enhanced visibility beyond standard Windows logging.

---

### 2. Log Collection Pipeline

Implemented centralized log collection using Splunk.

Process:

1. Installed Splunk Enterprise on Ubuntu.
2. Installed Splunk Universal Forwarder on Windows.
3. Configured event forwarding.
4. Collected Sysmon and Windows Event Logs.
5. Verified successful ingestion into Splunk.

---

### 3. Detection Engineering

Developed Sigma-based detections targeting credential access techniques.

Detection coverage included:

#### Mimikatz Execution Detection

Identifies execution of known Mimikatz binaries and command patterns associated with credential extraction.

#### LSASS Memory Access Detection

Detects suspicious access attempts targeting the Local Security Authority Subsystem Service (LSASS), a common source of credential dumping.

#### Credential Dumping Activity

Monitors behaviors associated with credential harvesting tools and memory dumping techniques.

#### Suspicious Process Creation

Detects abnormal process execution patterns that may indicate attacker activity.

---

### 4. Validation and Testing

Performed controlled attack simulations to verify detection effectiveness.

Testing activities included:

* PowerShell execution
* Encoded PowerShell commands
* Suspicious process launches
* Credential access behavior simulation

Generated events were successfully captured and analyzed through Sysmon and Splunk.

---

## MITRE ATT&CK Coverage

| Technique ID | Technique                         |
| ------------ | --------------------------------- |
| T1003        | OS Credential Dumping             |
| T1003.001    | LSASS Memory                      |
| T1059.001    | PowerShell                        |
| T1055        | Process Injection                 |
| T1548        | Abuse Elevation Control Mechanism |

---

## Sample Detection Logic

Example detection concepts implemented in the project:

* Detection of PowerShell encoded commands
* Detection of LSASS access attempts
* Detection of suspicious process creation
* Detection of known credential dumping tool execution

These detections can be adapted to enterprise SIEM environments for real-world monitoring.

---

## Security Outcomes

The implemented solution enables security teams to:

* Detect credential dumping attempts
* Monitor sensitive process access
* Improve endpoint visibility
* Accelerate incident investigation
* Map detections to ATT&CK techniques
* Strengthen SOC monitoring capabilities

---

## Skills Demonstrated

### Detection Engineering

* Sigma rule development
* Detection validation
* Alert tuning

### SOC Operations

* Security monitoring
* Event analysis
* Threat investigation

### SIEM Engineering

* Splunk deployment
* Log onboarding
* Search and detection creation

### Endpoint Security

* Sysmon configuration
* Windows logging
* Endpoint telemetry analysis

---

## Project Highlights

* Designed and implemented a complete detection engineering lab.
* Configured Sysmon for enhanced endpoint visibility.
* Integrated Windows telemetry with Splunk.
* Developed Sigma-based detections for credential access techniques.
* Simulated attack activity and validated detections.
* Mapped findings to the MITRE ATT&CK framework.
* Demonstrated practical SOC analyst and detection engineering skills.

---

## Future Enhancements

* Automated Sigma-to-Splunk rule conversion.
* Real-time alerting and dashboard creation.
* Detection coverage expansion for lateral movement techniques.
* Integration with Security Onion and Wazuh.
* Threat hunting use cases and reporting.

---

## Author

**Mayur Suvarna**
Cyber Security Student | SOC Analyst Enthusiast | Detection Engineering Learner

Focused on Security Operations, Threat Detection, SIEM Engineering, Digital Forensics, and Blue Team Security.
