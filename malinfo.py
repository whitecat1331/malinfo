from datetime import datetime
from enum import Enum
import sys
import hashlib
import lief
import click
import vt
import os
import string
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
        for i in range(len(HashInfo.HASH_ORDER)):
            self.dict_info[HashInfo.HASH_ORDER[i]] = self.all_hashes[i]

    def get_info(self):
        info = ""
        for i in range(len(self.all_hashes)):
            info += f"{HashInfo.HASH_ORDER[i]}: {self.all_hashes[i]}\n"
        return info

    def info(self):
        return self.dict_info

    def __iter__(self):
        return self.dict_info


class BinaryInfo:

    class OSType(Enum):
        LINUX = 1  # the best choice
        MAC = 2
        WINDOWS = 3

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
        os_types = list(BinaryInfo.OSType)
        for i in range(len(lief_types)):
            if isinstance(self.lief_parsed, lief_types[i]):
                self.os_type = os_types[i]

    def info(self):
        return self.dict_info

    def __iter__(self):
        return self.dict_info


class ReportInfo:
    def __init__(self, malware_name, author_name, malware_source, malware_link):
        self.malware_name = malware_name
        self.author_name = author_name
        self.malware_source = malware_source
        self.malware_link = malware_link
        self.date = datetime.now()


class VirusTotalAPI:
    VT_KEY = "VIRUS_TOTAL_API_KEY"

    def __init__(self, sha256, api_key):
        try:
            self.client = vt.Client(api_key)
            self.file = self.client.get_object(f"/files/{sha256}")
        except vt.error.APIError:
            self.file = type('NoFileAnalytics', (), {})()
            self.file.last_analysis_stats = {}

        except Exception:
            print(traceback.format_exc())

    def info(self):
        return self.file.last_analysis_stats

    def __iter__(self):
        return self.file.last_analysis_stats

    def __del__(self):
        self.client.close()


class DynamicAnalysis:

    def __init__(self):
        pass

    def execute_binary(self):
        pass

    def monitor_processes(self):
        pass

    def monitor_network_connections(self):
        pass


class MalInfo:

    def __init__(self, hash_info, binary_info, vt_info, string_info):
        self.hash_info = hash_info
        self.binary_info = binary_info
        self.vt_info = vt_info
        self.string_info = string_info


class ReportGenerator:

    REPORT_TEMPLATE = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "report_template.md")

    def __init__(self, malware_file):
        self.input = click.prompt
        self.print = click.echo
        self.malware_file = malware_file
        hash_info = HashInfo(self.malware_file)
        binary_info = BinaryInfo(self.malware_file)
        vt_info = VirusTotalAPI(
            hash_info.info()['sha256'], self.get_vt_key())
        string_info = Strings(self.malware_file)
        self.mal_info = MalInfo(hash_info, binary_info, vt_info, string_info)

    @staticmethod
    def extract_strings(list_of_strings):
        strings = ""
        for binary_string in list_of_strings:
            strings += f"{binary_string}\n"

        return strings

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

    def get_vt_key(self):
        try:
            vt_key = os.environ[VirusTotalAPI.VT_KEY]
        except KeyError:
            vt_key = self.input("Enter Virus Total API Key", type=str)
            os.environ[VirusTotalAPI.VT_KEY] = vt_key
        return vt_key

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

    def generate_report(self, report_name):

        try:
            with open(ReportGenerator.REPORT_TEMPLATE) as f:
                report_info = self.get_report_info()
                malware_name = report_info.malware_name
                author_name = report_info.author_name
                malware_source = report_info.malware_source
                date = report_info.date
                malware_source_link = report_info.malware_link

                hashes = ReportGenerator.format_info_table(
                    self.mal_info.hash_info.info(), "Hash", "Value")
                binary_info = ReportGenerator.format_info_table(
                    self.mal_info.binary_info.info(), "Info", "Value")
                virus_total_info = ReportGenerator.format_info_table(
                    self.mal_info.vt_info.info(), "Info", "Value")

                strings = ReportGenerator.extract_strings(
                    self.mal_info.string_info.info())

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


def hash_info_test():
    test_file = "test.txt"
    md5 = "e19c1283c925b3206685ff522acfe3e6"
    sha1 = "6476df3aac780622368173fe6e768a2edc3932c8"
    sha256 = "91751cee0a1ab8414400238a761411daa29643ab4b8243e9a91649e25be53ada"
    all_hashes = [md5, sha1, sha256]

    hash_info = HashInfo(test_file)

    print(hash_info.get_info())
    for i in range(len(all_hashes)):
        assert (all_hashes[i] == hash_info.all_hashes[i])

    return hash_info


def binary_info_test():
    test_bin = "test_c_bin"
    binary_info = BinaryInfo(test_bin)
    print(binary_info.os_type)
    print(binary_info.info())
    return binary_info


def virus_total_api_test():
    _hash = "0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83"
    try:
        vt_key = os.environ[VirusTotalAPI.VT_KEY]
    except KeyError:
        vt_key = click.prompt("Enter Virus Total API Key", type=str)
        os.environ[VirusTotalAPI.VT_KEY] = vt_key

    vt_api = VirusTotalAPI(_hash, vt_key)
    print(vt_api)
    return vt_api


def format_info_table_test():
    hash_info = hash_info_test()
    hash_dict = hash_info.info()
    table = ReportGenerator.format_info_table(
        hash_dict, "Hashing Algorithm", "Value")
    print(table)
    return table


def strings_test():
    test_bin = "test_c_bin"
    string_info = Strings(test_bin).info()

    for info in string_info:
        print(info)
    return string_info


def test_report_generator():
    malware_file = "test_c_bin"
    report_name = "test_report.md"
    report_generator = ReportGenerator(malware_file)
    report_generator.generate_report(report_name)


def test_all():
    hash_info_test()
    binary_info_test()
    virus_total_api_test()
    format_info_table_test()
    strings_test()
    test_report_generator()


def _test():
    binary_info_test()


@click.command()
@click.argument("output_file", type=str)
@click.argument("malware_file", type=str)
@click.option("-T", "--test", "test", is_flag=True, show_default=False, default=False, help="Run all tests")
def generate(output_file, malware_file, test):
    if test:
        test_all()
        sys.exit(0)
    report_generator = ReportGenerator(malware_file)
    report_generator.generate_report(output_file)


if __name__ == "__main__":
    generate()
