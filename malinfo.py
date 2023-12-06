import Monitor.monitor
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
from icecream import ic
from datetime import datetime
from scapy.all import *
from enum import Enum
import traceback


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

# used in both Static and Dynamic analysis
class VirusTotalAPI:
    VT_KEY = "VIRUS_TOTAL_API_KEY"

    def __init__():
        pass

    @staticmethod
    def file_info(hashsum, hash_type="sha256"):
        try:
            api_key = VirusTotalAPI.get_vt_key()
            client = vt.Client(api_key)
            file = client.get_object(f"/files/{hashsum[hash_type]}")
        except vt.error.APIError:
            file = type('NoFileAnalytics', (), {})()
            file.last_analysis_stats = {}
        except Exception:
            print(traceback.format_exc())
        finally:
            client.close()
        return file.last_analysis_stats

    staticmethod
    def get_vt_key():
        try:
            vt_key = os.environ[VirusTotalAPI.VT_KEY]
        except KeyError:
            vt_key = input("Enter Virus Total API Key: ")
            os.environ[VirusTotalAPI.VT_KEY] = vt_key
        return vt_key

class StaticAnalysis:

    def __init__(self, malware_file):
        self.malware_file = malware_file
        self.hash_info = StaticAnalysis.HashInfo(self.malware_file)
        self.string_info = StaticAnalysis.Strings(self.malware_file)
        self.binary_info = StaticAnalysis.BinaryInfo(self.malware_file)
        self.vt_info = VirusTotalAPI.file_info(self.hash_info.info())

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


    class BinaryInfo:

        class OSType(Enum):
            LINUX = 1  # the best choice
            MAC = 2 # meh
            WINDOWS = 3 # eww why?

        def __init__(self, malware_file):
            self.lief_parsed = lief.parse(malware_file)
            if self.lief_parsed:
                self.header_info = self.lief_parsed.header
                self.header_attr = [info for info in dir(self.header_info) if not info.startswith(
                    "__") and not callable(getattr(self.header_info, info))]

                # set os type
                self.set_os_type()

                self.parse_info()
            else:
                self.header_info = []
                self.header_attr = []
                self.dict_info = {}
                self.os_type = None

        # convert lief object to dictionary using output

        def parse_info(self):
            self.dict_info = {}
            # convert to dict
            for i in range(len(self.header_attr)):
                self.dict_info[self.header_attr[i]] = getattr(
                    self.header_info, self.header_attr[i])
            # remove empty information
            self.dict_info = {key: val for key, val in self.dict_info.items() if not (
                isinstance(val, set) and len(val) == 0)}

        def set_os_type(self):
            lief_types = [lief.ELF.Binary, lief.PE.Binary, lief.MachO.Binary]
            os_types = list(StaticAnalysis.BinaryInfo.OSType)
            for i in range(len(lief_types)):
                if isinstance(self.lief_parsed, lief_types[i]):
                    self.os_type = os_types[i]

        def info(self):
            return self.dict_info

        def __iter__(self):
            return self.dict_info

class DynamicAnalysis:

    def __init__(self):
        self.conn1, self.conn2 = multiprocessing.Pipe()
        listener = multiprocessing.Process(target=self.listen)
        detonater = multiprocessing.Process(target=DynamicAnalysis.execute_binary)
        # start listening
        listener.start()
        # detonate malware
        detonater.start()
        # parse results
        detonater.join(timeout=1)
        listener.join(timeout=1)
        self.monitor_parser = self.conn1.recv()
        self.conn1.close()
        self.processes_info = self.monitor_parser.parse_processes()
        self.network_packet_info = self.monitor_parser.parse_network_packets()
        self.file_changes_info = self.monitor_parser.parse_file_changes()

    def listen(self):
        self.conn2.send(DynamicAnalysis.MonitorParser())
        self.conn2.close()

    def execute_binary():
        from Tests.malinfo_test import malware_test
        malware_test()

    def processes_info(self):
        pass

    def network_packet_info(self):
        pass

    def changed_files_info(self):
        pass

    class MonitorParser:
        DURATION = 5 # seconds
        LOGNAME = "Logs"

        def __init__(self, duration=DURATION, detonation_time=time.time()):
            self.detonation_time = detonation_time

            if not os.path.exists(DynamicAnalysis.MonitorParser.LOGNAME):
                os.makedirs(DynamicAnalysis.MonitorParser.LOGNAME)

            self.monitor_info = Monitor.monitor.main(duration)

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


class ReportInfo:
    def __init__(self, malware_name, author_name, malware_source, malware_link):
        self.malware_name = malware_name
        self.author_name = author_name
        self.malware_source = malware_source
        self.malware_link = malware_link
        self.date = datetime.now()


class MalInfo:

    def __init__(self):
        self.static_analysis = StaticAnalysis()


class MarkdownFormatter:
    def __init__(self):
        pass

    @staticmethod
    def extract_strings(list_of_strings):
        strings = ""
        for binary_string in list_of_strings:
            strings += f"{binary_string}\n"

        return strings

    @staticmethod
    def format_info_table(info, *headers):

        if not info:
            return ""

        if not isinstance(info, dict):
            raise TypeError("info must be a dictionary")

        info = list(info.items())
        # top table
        table = "|"
        for header in headers:
            table += f" {header} |"
        table += "\n"
        # dashes
        table += "|"
        for header in headers:
            table += " "
            table += ("-" * len(header))
            table += " |"
        table += "\n"
        # dictionary info
        for row in range(len(info)):

            if len(info[row]) != len(headers):
                raise ValueError("Dictionary Info and Header Mismatch")

            table += "|"
            for col in range(len(info[row])):
                table += f" {info[row][col]} |"
            table += "\n"
        return table

class ReportGenerator:

    REPORT_TEMPLATE = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "report_template.md")

    def __init__(self, malware_file):
        self.input = click.prompt
        self.print = click.echo
        self.malware_file = malware_file
        self.mal_info = MalInfo()


    def get_report_info(self):
        malware_name = self.input(
            "What is the main name of the malware?\n", type=str)
        author_name = self.input(
            "What is the report author's name?\n", type=str)
        malware_source = self.input(
            "Where was the malware found?\n", type=str)
        malware_link = self.input(
            "What is the link to access the malware?\n", type=str)
        report_info = ReportInfo(
            malware_name, author_name, malware_source, malware_link)
        return report_info



    def generate_report(self, report_name):

        try:
            with open(report_name) as f:
                report_info = self.get_report_info()
                malware_name = report_info.malware_name
                author_name = report_info.author_name
                malware_source = report_info.malware_source
                date = report_info.date
                malware_source_link = report_info.malware_link

                hashes = ReportGenerator.format_info_table(
                    self.mal_info.static_analysis.hash_info.info(), "Hash", "Value")
                binary_info = ReportGenerator.format_info_table(
                    self.mal_info.static_analysis.binary_info.info(), "Info", "Value")
                virus_total_info = ReportGenerator.format_info_table(
                    self.mal_info.static_analysis.vt_info.file_info(), "Info", "Value")

                strings = ReportGenerator.extract_strings(
                    self.mal_info.static_analysis.string_info.info())

                report_template = f.read()
                report = report_template.format(malware_name=malware_name, author_name=author_name,
                                                malware_source=malware_source,
                                                malware_source_link=malware_source_link,
                                                date=date, hashes=hashes, binary_info=binary_info,
                                                virus_total_info=virus_total_info,
                                                strings=strings)
                ReportGenerator.write_report(report_name, report)
        except FileNotFoundError as e:
            sys.stderr.write(
                f"{ReportGenerator.REPORT_TEMPLATE} not found.\n{e}")
            sys.exit(1)

    @staticmethod
    def write_report(report_name, report):
        with open(report_name, "w") as f:
            f.write(report)


@click.command()
@click.option("-m", "--monitor_duration", "monitor_duration", type=float)
@click.option("-d", "--directories", "directories", type=str, multiple=True)
@click.argument("output_file", type=str)
@click.argument("malware_file", type=str)
def generate(monitor_duration, directories, output_file, malware_file):
    ic(monitor_duration)
    ic(directories)
    ic(output_file)
    ic(malware_file)

if __name__ == "__main__":
    generate()
