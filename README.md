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
  -i, --interface [lo|eno1|wlo1|vmnet1|vmnet8]
  --help                          Show this message and exit.
```

# Troubleshooting

## Port 53 Already In Use

Ubuntu based systems are already listening on port 53 by default. 
If you want the DNS server for Responder to function correctly, you will need 
to stop the systemd-resolver from using port 53.

To see if port 53 is in use, run the command
```
sudo lsof -i :53
```
If there is any output, then the system is actively using port 53.

To disable the systemd-resolver, you will need to override the default DNS server
by editing the /etc/systemd/resolved.conf file.

```
sudo vim /etc/systemd/resolved.conf
```

You will need to uncomment the line with DNSStubListener and set it to no.
This is what the file should look like after the appropriate changes are made.

```
[Resolve]
#DNS=
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#DNSOverTLS=no
#Cache=no
DNSStubListener=no
#ReadEtcHosts=yes
```

Next you will need restart the service

```
sudo systemctl restart systemd-resolved
```

The changes will be applied after reboot and port 53 should no longer be in use.

To undo these changes, comment the DNSStubListener setting. 

## Exception: Nameserver not found: set host file to interface

This error means that the nameserver is not set to Responder's DNS server.

### Linux 

Edit the /etc/resolv.conf file, you will need root permission.

```
sudo vim /etc/resolv.conf
```

Change the nameserver to the interface you intend to use Responder on.

Example:
```
nameserver 127.0.0.1
```

### Windows 

https://www.lifewire.com/how-to-change-dns-servers-in-windows-2626242

### OS X
https://softwarekeep.com/help-center/how-to-change-dns-settings-on-a-mac

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
j* Monitor File IO on the File System
