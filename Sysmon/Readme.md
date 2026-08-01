# Sysmon Configuration

## Overview

Microsoft Sysmon (System Monitor) is a Windows system service that logs detailed system activity such as process creation, network connections, registry modifications, file creation, and process access.

This project uses Sysmon to collect endpoint telemetry for security monitoring and forwards the events to Splunk using the Splunk Universal Forwarder.

---

## Objectives

- Install Sysmon
- Configure Sysmon with a custom configuration
- Collect Windows security telemetry
- Monitor suspicious activities
- Forward logs to Splunk

---

## Tools

- Windows 11
- Microsoft Sysmon
- Splunk Universal Forwarder

---

## Important Sysmon Event IDs

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 10 | Process Access |
| 11 | File Creation |
| 12 | Registry Object Create/Delete |
| 13 | Registry Value Set |
| 15 | FileCreateStreamHash |
| 17 | Pipe Created |

---

## Verification

Successfully verified Sysmon events in Splunk.

---

## MITRE ATT&CK

- TA0006 – Credential Access
- TA0005 – Defense Evasion
- TA0007 – Discovery

---

## Status

✅ Sysmon Installed

✅ Configuration Applied

✅ Logs Successfully Forwarded to Splunk
