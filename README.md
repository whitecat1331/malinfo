# malinfo Description

<b> Do Not Run This Program On An Unprotected Machine!!! </b>

This program is a Python static and dynamic analysis tool. This tool will perform different static and dynamic analysis techniques such as 
magic byte analysis, network indicator analysis, and much more. The goal of this project is to provide a free and public way for any malware analyst to help determine if 
a file is malicious or not. The first part of the program will perform various static analysis techniques such as hashing, Virus Total results, and string analysis.
The program will then perform dynamic andlysis on the file to determine and log new processes, network connections, and file changes in specified directories. 
All of the results will be compiled into a markdown report. 

This repo is licence is under GPL-3. This means that anyone can copy, distribute, and basically do whatever you want with the code in the repo. 
I spent a lot of time and effort in this project and the only thing I ask if you use this project is to mention whitecat1331 as the author. 

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
