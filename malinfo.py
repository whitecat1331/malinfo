from datetime import datetime
import sys
import hashlib
import lief
import click
import vt
import os
import string


class FileManager:

    BLOCKSIZE = 65536

    def __init__(self, malware_file):
        self.malware_file = malware_file

    def __enter__(self):
        try:
            self.malware_handle = open(self.malware_file, "rb", buffering=0)

        except FileNotFoundError:
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
    def __init__(self, malware_file):
        self.lief_parsed = lief.parse(malware_file)
        self.header_info = self.lief_parsed.header
        self.header_attr = [info for info in dir(self.header_info) if not info.startswith(
            "__") and not callable(getattr(self.header_info, info))]
        self.parse_info()

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
        self.client = vt.Client(api_key)
        self.file = self.client.get_object(f"/files/{sha256}")

    def info(self):
        return self.file.last_analysis_stats

    def __iter__(self):
        return self.file.last_analysis_stats


class MalInfo:
    def __init__(self, hash_info, binary_info, report_info, vt_info, string_info):
        self.hash_info = hash_info
        self.binary_info = binary_info
        self.report_info = report_info
        self.vt_info = vt_info
        self.string_info = string_info


class ReportGenerator:
    def __init__(self, malware_file):
        self.print = click.echo
        self.input = click.prompt
        self.malware_file = malware_file
        hash_info = HashInfo(self.malware_file)
        binary_info = BinaryInfo(self.malware_file)
        report_info = self.get_report_info()
        vt_info = VirusTotalAPI(
            hash_info.info()['sha256'], self.get_vt_key())
        strings = ReportGenerator.extract_strings(
            self.mal_info.string_info.info())
        self.mal_info = MalInfo(hash_info, binary_info,
                                report_info, vt_info, strings)

    @staticmethod
    def extract_strings(list_of_strings):
        strings = ""
        for binary_string in list_of_strings:
            strings += binary_string

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

    def generate_report(self):
        malware_name = self.mal_info.report_info.malware_name
        author_name = self.mal_info.report_info.author_name
        malware_source = self.mal_info.report_info.malware_source
        date = self.mal_info.report_info.date
        hashes = ReportGenerator.format_info_table(
            self.mal_info.hash_info.info(), "Hash", "Value")
        binary_info = ReportGenerator.format_info_table(
            self.mal_info.binary_info.info(), "Info", "Value")
        virus_total_info = ReportGenerator.format_info_table(
            self.mal_info.vt_info.info(), "Info", "Value")
        strings = self.mal_info.string_info
        pass


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


def test_all():
    hash_info_test()
    binary_info_test()
    virus_total_api_test()


if __name__ == "__main__":
    strings_test()
