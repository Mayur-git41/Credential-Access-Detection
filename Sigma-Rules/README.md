# Sigma Detection Rules

## Overview

Sigma is an open standard used to write vendor-neutral detection rules. These rules can later be converted into Splunk SPL queries.

---

## Objectives

- Learn Sigma Syntax
- Create Detection Rules
- Detect Suspicious Activities
- Map Rules to MITRE ATT&CK

---

## Rule Created

### Suspicious PowerShell Encoded Command

Detection Logic

- Detect PowerShell execution
- Detect use of Base64 encoded commands
- Identify possible malicious execution

---

## MITRE ATT&CK

Technique:

T1059.001 - PowerShell

T1027 - Obfuscated Files or Information

---

## Detection Fields

- Image
- CommandLine
- ParentImage

---

## Detection Outcome

Successfully validated Sigma rule syntax.

Rule can be converted into Splunk SPL.

---

## Future Rules

- Mimikatz Detection
- LSASS Access
- Registry Persistence
- Scheduled Tasks
- WMI Persistence
- PsExec Detection

---

## Status

Sigma Installed

First Detection Rule Created

Rule Validated Successfully
