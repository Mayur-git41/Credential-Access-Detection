# Splunk Enterprise

## Overview

Splunk Enterprise is used as the Security Information and Event Management (SIEM) platform for collecting, searching, and analyzing Windows security logs.

---

## Objectives

- Install Splunk Enterprise
- Configure Splunk
- Install Universal Forwarder
- Collect Sysmon Logs
- Search and Analyze Security Events

---

## Components

- Splunk Enterprise
- Splunk Universal Forwarder
- Windows 11 Endpoint
- Ubuntu Splunk Server

---

## Sample Search Queries

### View Sysmon Events

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

### Extract XML Fields

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
```

### Count Event IDs

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| stats count by EventID
```

### Process Creation

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=1
```

---

## Verification

Successfully received Sysmon events from Windows.

Verified:

- Process Creation
- Registry Changes
- Process Access
- File Creation

---

## Skills Learned

- SPL Searching
- XML Parsing
- Event Analysis
- Security Monitoring

---

## Status

✅ Splunk Installed

✅ Universal Forwarder Configured

✅ Sysmon Logs Successfully Indexed
