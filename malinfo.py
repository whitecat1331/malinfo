import sys
import hashlib
import lief
import click
import vt
import os
import string
import traceback
import time
import json
import multiprocessing
import magic 
import traceback
import subprocess
import netifaces
import dns.resolver
import Monitor.monitor
from platform import system
from markdown_formatter import MarkdownFormatter
from concurrent.futures import ProcessPoolExecutor
from dotenv import load_dotenv
from icecream import ic
from datetime import datetime
from enum import Enum
from scapy.all import *


# used in both Static and Dynamic analysis
class FileManager:

    BLOCKSIZE = 65536

    def __init__(self, malware_file):
        self.malware_file = malware_file

    def __enter__(self):
        try:
            self.malware_handle = open(self.malware_file, "rb", buffering=0)

        except Exception:
            print(traceback.format_exc())
            sys.stderr.write("Failed to open file for Info\n")
            sys.exit(1)

        return self

    def read(self):
        buf = self.malware_handle.read(FileManager.BLOCKSIZE)
        while len(buf) > 0:
            yield buf
            buf = self.malware_handle.read(FileManager.BLOCKSIZE)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.malware_handle.close()

    def __del__(self):
        self.malware_handle.close()

class VirusTotalAPI:
    VT_KEY = "VIRUS_TOTAL_API_KEY"

    def __init__(self):
        self.api_key = VirusTotalAPI.get_vt_key()
        self.client = vt.Client(self.api_key)

    def file_info(self, hashsum):
        try:
            return self.client.get_object(f"/files/{hashsum}").last_analysis_stats
        except Exception:
            traceback.print_exc

        return {}

    def __del__(self):
        self.client.close()


    @staticmethod
    def get_vt_key():
        try:
            load_dotenv()
            vt_key = os.environ[VirusTotalAPI.VT_KEY]
        except KeyError:
            vt_key = input("Enter Virus Total API Key: ")
            os.environ[VirusTotalAPI.VT_KEY] = vt_key
        return vt_key

class StaticAnalysis:

    def __init__(self, malware_file, hash_type = "sha256"):
        self.malware_file = malware_file
        self.magic_bytes_info = magic.from_file(self.malware_file)
        self.hash_info = StaticAnalysis.HashInfo(self.malware_file).info()
        self.string_info = StaticAnalysis.Strings(self.malware_file).info()
        self.vt_info = VirusTotalAPI().file_info(self.hash_info[hash_type])
        lief_parsed = lief.parse(malware_file)
        self.header_info = str(lief_parsed)
        self.os_type = type(lief_parsed)

    class Strings:
        def __init__(self, malware_file):
            self.malware_file = malware_file

        def strings(self, min=4):
            with open(self.malware_file, errors="ignore") as f:
                result = ""
                for c in f.read():
                    if c in string.printable:
                        result += c
                        continue
                    if len(result) >= min:
                        yield result
                    result = ""
                if len(result) >= min:  # catch result at EOF
                    yield result

        def info(self):
            return list(self.strings())


    class HashInfo:
        HASH_ORDER = ["md5", "sha1", "sha256"]

        def __init__(self, malware_file):
            # set hashers
            self.all_hashes = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
            with FileManager(malware_file) as file_manager:
                for buf in file_manager.read():
                    for hasher in self.all_hashes:
                        hasher.update(buf)

            for i in range(len(self.all_hashes)):
                self.all_hashes[i] = self.all_hashes[i].hexdigest()

            self.parse_info()

        def parse_info(self):
            self.dict_info = {}
            for i in range(len(StaticAnalysis.HashInfo.HASH_ORDER)):
                self.dict_info[StaticAnalysis.HashInfo.HASH_ORDER[i]] = self.all_hashes[i]

        def get_info(self):
            info = ""
            for i in range(len(self.all_hashes)):
                info += f"{StaticAnalysis.HashInfo.HASH_ORDER[i]}: {self.all_hashes[i]}\n"
            return info

        def info(self):
            return self.dict_info

        def __iter__(self):
            return self.dict_info

class DynamicAnalysis:

    def __init__(self, duration, directories, static_analysis, interface):
        process_pool_executor = ProcessPoolExecutor()
        # start responder
        responder = multiprocessing.Process(target=DynamicAnalysis.execute_responder, args=(duration, interface))
        responder.start()
        while socket.gethostbyname("whatsmydns.net") != netifaces.ifaddresses(interface)[2][0]["addr"]:
            time.sleep(0.1)
        # start listening
        listener = process_pool_executor.submit(DynamicAnalysis.listen, interface, duration, directories)
        # detonate malware
        detonater = multiprocessing.Process(target=DynamicAnalysis.execute_binary, args=(static_analysis, ))
        detonater.start()
        # parse results
        detonater.join()
        responder.join()
        self.monitor_parser = listener.result()
        self.processes_info = self.monitor_parser.parse_processes()
        self.network_packet_info = self.monitor_parser.parse_network_packets()
        self.file_changes_info = self.monitor_parser.parse_file_changes()

    @staticmethod
    def listen(interface, duration, directories):
        return DynamicAnalysis.MonitorParser(interface, duration, directories)

    @staticmethod
    def execute_binary(static_analysis):
        executable_name = static_analysis.malware_file
        os_type = static_analysis.os_type
        os_name = system().lower()

        magic_bytes_info = static_analysis.magic_bytes_info.lower()
        if "python" in magic_bytes_info and "executable" in magic_bytes_info:
            args = ("python", executable_name)
            
        elif os_name == "linux" and os_type == lief.ELF.Binary:
            args = (f"./{executable_name}",)

        elif os_name == "windows" and os_type == lief.PE.Binary:
            args = (f".\{executable_name}",)

        elif os_name == "darwin" and os_type == lief.MachO.Binary:
            args = (f"./{executable_name}",)
        
        else:
            print("Unable to execute file")
            return

        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        print(output.decode('utf-8'))

    @staticmethod
    def execute_responder(duration, interface):
        os.chdir("Responder")
        responder_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Responder", "Responder.py")
        args = ("python", "Responder.py", f"--interface={interface}", f"--monitor_time={duration}", "--DHCP-DNS", "--wpad")
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        print(output.decode('utf-8'))
        os.chdir("..")

    
        

    class MonitorParser:
        LOGNAME = "Logs"

        def __init__(self, interface, duration, directories, detonation_time=time.time()):
            self.detonation_time = detonation_time

            if not os.path.exists(DynamicAnalysis.MonitorParser.LOGNAME):
                os.makedirs(DynamicAnalysis.MonitorParser.LOGNAME)

            self.monitor_info = Monitor.monitor.main(interface, duration, directories)

        def parse_processes(self, monitor_name="process_monitor"):
            raw_processes = self.monitor_info[monitor_name]
            delayed_processes = []
            for process in raw_processes:
                if process["create_time"] > self.detonation_time:
                    delayed_processes.append(process)
            logfile = os.path.join(DynamicAnalysis.MonitorParser.LOGNAME, f"{monitor_name}.json")
            with open(logfile, 'w') as f:
                json.dump(delayed_processes, f)
            parsed_processes = []
            for parsed_process in delayed_processes:
                parsed_processes.append(parsed_process["name"])
            parsed_processes = set(parsed_processes)
            return parsed_processes

        def parse_network_packets(self, monitor_name="network_monitor"):
            raw_packets = self.monitor_info[monitor_name]
            logfile = os.path.join(DynamicAnalysis.MonitorParser.LOGNAME, f"{monitor_name}.pcap")
            wrpcap(logfile, raw_packets)
            delayed_packets = []
            for packet in raw_packets[DNSQR]:
                if packet.time > self.detonation_time:
                    delayed_packets.append(packet)
            # filter packets by suspicious dns query
            query_names = set()
            for packet in delayed_packets:
                query_names.add(packet[DNSQR].qname.decode('utf-8')[:-1])
            return query_names

        def parse_file_changes(self, monitor_name="changed_files"):
            raw_file_changes = self.monitor_info["filesystem_monitor"]
            logfile = os.path.join(DynamicAnalysis.MonitorParser.LOGNAME, f"{monitor_name}.json")
            with open(logfile, 'w') as f:
                json.dump(raw_file_changes, f)
            parsed_file_changes = set()
            for file_change in raw_file_changes:
                if file_change["time"] > self.detonation_time:
                    parsed_file_changes.add(file_change['source'])
            return parsed_file_changes

class MalInfo:

    def __init__(self, duration, directories, malware_file, interface):
        self.static_analysis = StaticAnalysis(malware_file)
        self.dynamic_analysis = DynamicAnalysis(duration, directories, self.static_analysis, interface)


class ReportGenerator:

    class ReportInfo:
        def __init__(self, malware_name, author_name, malware_source, malware_link):
            self.malware_name = malware_name
            self.author_name = author_name
            self.malware_source = malware_source
            self.malware_link = malware_link
            self.date = datetime.now()

    REPORT_TEMPLATE = \
"""
<center><b>{malware_name}</b></center> <br>
<center>{author_name}</center>           <br>
<center>{malware_source}</center>                   <br>
<center>{date}</center>           <br>

---

### <u>Malware Samples</u>

[malware_source_link]({malware_source_link})
<br>

---

### <u>Static Analysis</u>

##### Malware Info:

###### Magic Bytes

```
{magic_bytes_info}
```

###### Hashes:

{hashes}

###### Header Info

```
{header_info}
```

##### Virus Total

{virus_total_info}

###### Strings:

Note: Links Defanged Using [Cyber Chef](https://gchq.github.io/CyberChef/)

```
{strings}
```

---

### <u>Dynamic Analysis</u>

##### Process Indicators:

```
{process_indicators}
```

##### Network Indicators:

```
{network_indicators}
```

##### File Indicators

```
{file_indicators}
```

---

"""


    def __init__(self, monitor_duration, directories, output_file, malware_file, interface):
        self.input = click.prompt
        self.print = click.echo
        self.malware_file = malware_file
        self.malinfo = MalInfo(monitor_duration, directories, malware_file, interface)
        self.report_name = output_file
        self.generate_report()


    def get_report_info(self):
        malware_name = self.input(
            "What is the main name of the malware?\n", type=str)
        author_name = self.input(
            "What is the report author's name?\n", type=str)
        malware_source = self.input(
            "Where was the malware found?\n", type=str)
        malware_link = self.input(
            "What is the link to access the malware?\n", type=str)
        report_info = ReportGenerator.ReportInfo(
            malware_name, author_name, malware_source, malware_link)
        return report_info


    def generate_report(self):

        # Generic Report Info
        report_info = self.get_report_info()
        malware_name = report_info.malware_name
        author_name = report_info.author_name
        malware_source = report_info.malware_source
        date = report_info.date
        malware_source_link = report_info.malware_link

        # Static Analysis Report Info
        magic_bytes_info = self.malinfo.static_analysis.magic_bytes_info

        hashes = MarkdownFormatter.format_info_table(
            self.malinfo.static_analysis.hash_info, "Hash", "Value"
            )

        header_info = self.malinfo.static_analysis.header_info

        virus_total_info = MarkdownFormatter.format_info_table(
            self.malinfo.static_analysis.vt_info, "Info", "Value"
            )

        strings = MarkdownFormatter.extract_strings(
            self.malinfo.static_analysis.string_info
            )

        # Dynamic Analysis Report Info
        processes_info = MarkdownFormatter.extract_strings(
            self.malinfo.dynamic_analysis.processes_info
            )

        network_info = MarkdownFormatter.extract_strings(
                self.malinfo.dynamic_analysis.network_packet_info
                )

        file_changes_info = MarkdownFormatter.extract_strings(
                self.malinfo.dynamic_analysis.file_changes_info
                )

        report = ReportGenerator.REPORT_TEMPLATE.format(malware_name=malware_name, author_name=author_name,
                                        malware_source=malware_source,
                                        malware_source_link=malware_source_link,
                                        date=date, magic_bytes_info=magic_bytes_info,
                                        hashes=hashes, header_info=header_info,
                                        virus_total_info=virus_total_info,
                                        strings=strings, process_indicators=processes_info,
                                        network_indicators=network_info, 
                                        file_indicators=file_changes_info)

        ReportGenerator.write_report(self.report_name, report)

    @staticmethod
    def write_report(report_name, report):
        with open(report_name, "w") as f:
            f.write(report)


@click.command()
@click.option("-m", "--monitor_duration", "monitor_duration", type=float)
@click.option("-d", "--directories", "directories", type=str, multiple=True)
@click.option("-i", "--interface", "interface", 
              type=click.Choice(netifaces.interfaces()),
              default=netifaces.interfaces()[0]
            )
@click.argument("output_file", type=str)
@click.argument("malware_file", type=str)
def generate(monitor_duration, directories, interface, output_file, malware_file):
    ic(interface)
    ReportGenerator(monitor_duration, directories, output_file, malware_file)

if __name__ == "__main__":
    generate()
