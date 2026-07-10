# Day 13 – Sigma CLI Installation

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

  # Day 14 – Sigma Rules Repository

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
# Day 15 – PowerShell Encoded Command Detection

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
