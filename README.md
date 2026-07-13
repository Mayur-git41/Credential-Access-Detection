# Credential Access Detection using Sigma Rules
OBJECTIVE:

Detect credential dumping activities such as:

1)Mimikatz execution

2)LSASS memory access

3)Credential dumping attempts

4)suspicious process creation

ARCHITECTURE:
     
Windows VM
     |
   
     |
Sysmon Logs
     |
     |    
Windows Event Logs
     |
     |     
Sigma Rules
     |
     
Detection Results

Sysmon Event Logs

Sysmon was successfully installed and configured on the Windows endpoint.

Steps involved to execute 

# Sigma CLI Installation

## Objective

Install Sigma CLI on Ubuntu.

## Commands Used

```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install sigma-cli --break-system-packages
sigma --help
```

## Verification

Sigma CLI installed successfully.

## Available Commands

- analyze
- check
- convert
- list
- plugin
- pysigma
- version

## Learning Outcome

- Installed Sigma CLI
- Verified installation
- Ready to convert Sigma rules into Splunk SPL

  # Sigma Rules Repository

## Objective
Downloaded and explored the official Sigma detection rules repository.

## Environment

- Ubuntu 24.04 LTS
- Python 3
- Git
- Sigma CLI

## Commands Executed

```bash
cd ~

git clone https://github.com/SigmaHQ/sigma.git

cd sigma

ls

cd rules

ls

find . -name "*.yml" | wc -l

find . -name "*.yml" | head -1

cat <rule-file>

git --version
```
# PowerShell Encoded Command Detection

## Objective
Detect suspicious PowerShell encoded command execution using Sigma Rules.

## MITRE ATT&CK Mapping
Technique: T1059.001 – PowerShell

## Sigma Rule

```yaml
title: Suspicious PowerShell Encoded Command
...
```

## Validation

Rule successfully validated using Sigma CLI.

## Splunk Query

(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")

## Detection Result

Successfully identified encoded PowerShell execution.

## Screenshots

1. Sigma Rule Creation
2. Sigma Validation
3. Sigma to Splunk Conversion
4. PowerShell Attack Simulation
5. Splunk Detection

# PowerShell Attack Simulation Detection

## Objective

Simulate suspicious PowerShell execution and detect it using Sysmon Event ID 1 in Splunk.

## Attack Simulation

Command:

powershell -enc QQBBAA==

## Detection Source

Sysmon Event ID:

1

Event Name:

Process Creation

## MITRE ATT&CK Mapping

Technique:

T1059.001

Name:

PowerShell

## Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer

## Detection Query

index=main EventCode=1 Image="*powershell.exe*"

## Evidence

Screenshots included:

1. Forwarder connection
2. Sysmon Event ID 1
3. PowerShell execution
4. Splunk detection


