# malinfo Description
Python research report tool for suspected malware

# Requirements
* python3.11+
* Virus Total API Key

set environment variable VIRUS_TOTAL_API_KEY

<u>Linux</u>

export VIRUS_TOTAL_API_KEY=YOUR_KEY


# Manuel Installation

pip install -r requirements.txt

python malinfo.py --help

# Quick Installation

pip install .

<b>or if developing</b>

pip install --editable .

malinfo --help

# Current Features

## <u>Static Analysis Reporting</u>
* Hash Information
* Binary Information
* Virus Total Information
* Strings Information

# Upcoming Features

## <u>Dynamic Analysis Report</u>
* Start Proxy Servers
* Monitor Network Connections
* Monitor New Processes 
* Monitor File IO on the File System

