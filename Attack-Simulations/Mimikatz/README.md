# Day 17 – Mimikatz Detection

## Objective

Detect execution of Mimikatz using Sysmon, Splunk, and Sigma.

## Tools Used

* Splunk Enterprise
* Sysmon
* Sigma
* Windows 10
* Ubuntu

## Attack Simulation

A test executable named mimikatz.exe was created to simulate credential dumping activity.

## Detection

Sysmon Event ID 1 was collected and analyzed in Splunk.

## MITRE ATT&CK

* TA0006 Credential Access
* T1003.001 LSASS Memory

## Outcome

Successfully detected simulated Mimikatz execution and created Sigma-based detection logic.
