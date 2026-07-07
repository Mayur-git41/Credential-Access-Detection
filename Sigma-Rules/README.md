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
