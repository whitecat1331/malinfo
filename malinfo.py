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
import Monitor.monitor
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

    def __init__():
        pass

    @staticmethod
    def file_info(hashsum):
        try:
            api_key = VirusTotalAPI.get_vt_key()
            client = vt.Client(api_key)
            file = client.get_object(f"/files/{hashsum}")
        except vt.error.APIError:
            file = type('NoFileAnalytics', (), {})()
            file.last_analysis_stats = {}
            print("No File Analytics")
        except Exception:
            traceback.print_exc
        finally:
            client.close()
        return file.last_analysis_stats

    staticmethod
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
        self.magic_byte_info = magic.from_file(self.malware_file)
        self.hash_info = StaticAnalysis.HashInfo(self.malware_file).info()
        self.string_info = StaticAnalysis.Strings(self.malware_file).info()
        self.binary_info = StaticAnalysis.BinaryInfo(self.malware_file).info()
        self.vt_info = VirusTotalAPI.file_info(self.hash_info[hash_type])

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

        def __init__(self, malware_file):
            self.lief_parsed = lief.parse(malware_file)
            if self.lief_parsed:
                self.header_info = self.lief_parsed.header
                self.header_attr = [info for info in dir(self.header_info) if not info.startswith(
                    "__") and not callable(getattr(self.header_info, info))]

                # set os type
                # self.set_os_type()
                self.os_type = type(self.lief_parsed)

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

        def info(self):
            return self.dict_info

        def __iter__(self):
            return self.dict_info

class DynamicAnalysis:

    def __init__(self, duration, directories):
        process_pool_executor = ProcessPoolExecutor()
        # start listening
        listener = process_pool_executor.submit(self.listen, duration, directories)
        # detonate malware
        detonater = multiprocessing.Process(target=DynamicAnalysis.execute_binary)
        detonater.start()
        # parse results
        detonater.join()
        self.monitor_parser = listener.result()
        self.processes_info = self.monitor_parser.parse_processes()
        self.network_packet_info = self.monitor_parser.parse_network_packets()
        self.file_changes_info = self.monitor_parser.parse_file_changes()

    def listen(self, duration, directories):
        return DynamicAnalysis.MonitorParser(duration, directories)

    def execute_binary():
        from Tests.malinfo_test import malware_test
        malware_test()

    class MonitorParser:
        LOGNAME = "Logs"

        def __init__(self, duration, directories, detonation_time=time.time()):
            self.detonation_time = detonation_time

            if not os.path.exists(DynamicAnalysis.MonitorParser.LOGNAME):
                os.makedirs(DynamicAnalysis.MonitorParser.LOGNAME)

            self.monitor_info = Monitor.monitor.main(duration, directories)

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

    def __init__(self, duration, directories):
        self.static_analysis = StaticAnalysis()
        self.dynamic_analysis = DynamicAnalysis(duration, directories)



class ReportGenerator:

    class ReportInfo:
        def __init__(self, malware_name, author_name, malware_source, malware_link):
            self.malware_name = malware_name
            self.author_name = author_name
            self.malware_source = malware_source
            self.malware_link = malware_link
            self.date = datetime.now()

    REPORT_TEMPLATE = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "report_template.md")


    def __init__(self, monitor_duration, directories, output_file, malware_file):
        self.input = click.prompt
        self.print = click.echo
        self.malware_file = malware_file
        self.malinfo = MalInfo(monitor_duration, directories)
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

        try:
            with open(self.report_name) as f:
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
                binary_info = MarkdownFormatter.format_info_table(
                    self.malinfo.static_analysis.binary_info, "Info", "Value"
                    )
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

                report_template = f.read()
                report = report_template.format(malware_name=malware_name, author_name=author_name,
                                                malware_source=malware_source,
                                                malware_source_link=malware_source_link,
                                                date=date, magic_bytes_info=magic_bytes_info,
                                                hashes=hashes, binary_info=binary_info,
                                                virus_total_info=virus_total_info,
                                                strings=strings, process_indicators=processes_info,
                                                network_indicators=network_info, 
                                                file_indicators=file_changes_info)

                ReportGenerator.write_report(self.report_name, report)
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
