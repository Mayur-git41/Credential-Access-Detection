# Incident Report

Incident ID:
SOC-D17-001

Date:
14-07-2026

Severity:
High

MITRE ATT&CK:
T1003.001

Summary:
Potential execution of Mimikatz was detected through Sysmon process creation logs.

Evidence:

* Process Name: mimikatz.exe
* Event ID: 1
* Source: Sysmon

Impact:
Possible credential dumping activity.

Recommendation:
Investigate host immediately and isolate if activity is unauthorized.

Status:
Closed (Lab Simulation)

