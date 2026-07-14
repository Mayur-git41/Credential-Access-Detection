# Splunk Queries

## Basic Detection

index=main EventCode=1 Image="*mimikatz*"

## Process Investigation

index=main EventCode=1
| table _time Image CommandLine ParentImage User

## Timeline

index=main EventCode=1
| sort _time

