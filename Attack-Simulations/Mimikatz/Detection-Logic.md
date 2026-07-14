# Detection Logic

This detection identifies potential credential dumping tools such as Mimikatz.

The rule monitors Sysmon Event ID 1 (Process Creation).

Detection triggers when:

* Process name contains mimikatz.exe
* Command line references Mimikatz
* Suspicious credential dumping utilities execute

Potential impact:

* Credential theft
* Privilege escalation
* Lateral movement

Data Source:

* Sysmon Event ID 1

MITRE ATT&CK:

* TA0006 Credential Access
* T1003.001 LSASS Memory

