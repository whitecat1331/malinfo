# malinfo Description
Python static and dynamic analysis tool.

# Requirements
* python3.11+
* Virus Total API Key

set environment variable VIRUS_TOTAL_API_KEY

<u>Linux</u>
```
export VIRUS_TOTAL_API_KEY=YOUR_KEY
```

<u>Windows</u>
```
setx VIRUS_TOTAL_API_KEY YOUR_KEY
```

<b> OR </b>

create a .env file and set VIRUS_TOTAL_API_KEY to YOUR_KEY


# Manuel Installation

pip install -r requirements.txt

python malinfo.py --help

# Quick Installation

pip install .

<b>or if developing</b>

pip install --editable .

malinfo --help

# Usage

```
Usage: malinfo.py [OPTIONS] OUTPUT_FILE MALWARE_FILE

Options:
  -m, --monitor_duration FLOAT
  -d, --directories TEXT
  --help                        Show this message and exit.
```


# Current Features

## <u>Static Analysis Report</u>
* Hash Information
* Binary Information
* Virus Total Information
* Strings Information

## <u>Dynamic Analysis Report</u>
* Start Proxy Servers
* Monitor Network Connections
* Monitor New Processes 
* Monitor File IO on the File System
