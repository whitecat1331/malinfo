from datetime import datetime
import sys
import hashlib
import lief
import click
import vt
import os


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
        return self.malware_handle.read(FileManager.BLOCKSIZE)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.malware_handle.close()

    def __del__(self):
        self.malware_handle.close()


class HashInfo:
    HASH_ORDER = ["md5", "sha1", "sha256"]

    def __init__(self, malware_file):
        # set hashers
        self.all_hashes = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        with FileManager(malware_file) as file_manager:

            buf = file_manager.read()
            while len(buf) > 0:
                for hasher in self.all_hashes:
                    hasher.update(buf)
                buf = file_manager.read()

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

    def __iter__(self):
        return self.dict_info.items()


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

    def __iter__(self):
        return self.dict_info.items()


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

    def __iter__(self):
        return self.file.last_analysis_stats


class MalInfo:
    def __init__(self, hash_info, binary_info, report_info):
        self.hash_info = hash_info
        self.binary_info = binary_info
        self.report_info = report_info


class ReportGenerator:
    def __init__(self, malware_file):
        self.print = click.echo
        self.input = click.prompt
        self.malware_file = malware_file
        hash_info = HashInfo(self.malware_file)
        binary_info = BinaryInfo(self.malware_file)
        report_info = self.get_report_info()
        self.mal_info = MalInfo(hash_info, binary_info, report_info)

    def get_report_info(self):
        malware_name = self.input(
            "What is the main name of the malware?\n", type=str)
        author_name = self.input(
            "What is the report author's name?\n", type=str)
        malware_source = self.input(
            "Where did you get the malware?\n", type=str)
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

    def generate_report(self):
        self.print("Generating Report...")
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


def binary_info_test():
    test_bin = "test_c_bin"
    binary_info = BinaryInfo(test_bin)
    print(binary_info)
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


def test_all():
    hash_info_test()
    binary_info_test()
    virus_total_api_test()


if __name__ == "__main__":
    pass
