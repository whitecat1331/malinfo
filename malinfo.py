import sys
import hashlib
import lief



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
        with FileManager(malware_file) as file_manager:
            self.all_hashes = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]

            buf = file_manager.read()
            while len(buf) > 0:
                for hasher in self.all_hashes:
                    hasher.update(buf)
                buf = file_manager.read()

            for i in range(len(self.all_hashes)):
                self.all_hashes[i] = self.all_hashes[i].hexdigest()

    def get_info(self):
            info = ""
            for i in range(len(self.all_hashes)):
                info += f"{HashInfo.HASH_ORDER[i]}: {self.all_hashes[i]}\n"
            return info






class BinaryInfo:
    def __init__(self, malware_file):
        self.lief_parsed = lief.parse(malware_file)
        print(self.lief_parsed)


class ReportInfo:
    def __init__(self, malware_file):
        Info.__init__(self, malware_file)
        self.set_author_name()
        self.set_date()

    def set_author_name(self):
        pass

    def set_date(self):
        pass

class MalInfo:
    def __init__(self, malware_file):
        self.malware_file = malware_file
        self.hash_info = HashInfo(self.malware_file)
        self.binary_info = BinaryInfo(self.malware_file)
        self.report_info = ReportInfo(self.malware_file)

def hash_info_test():
    test_file = "test.txt"
    md5 = "e19c1283c925b3206685ff522acfe3e6"
    sha1 = "6476df3aac780622368173fe6e768a2edc3932c8"
    sha256 = "91751cee0a1ab8414400238a761411daa29643ab4b8243e9a91649e25be53ada"
    all_hashes = [md5, sha1, sha256]

    hash_info = HashInfo(test_file)

    print(hash_info.get_info())
    for i in range(len(all_hashes)):
        assert(all_hashes[i] == hash_info.all_hashes[i])

def binary_info_test():
    test_bin = "test_c_bin"
    binary_info = BinaryInfo(test_bin)

def test_all():
    hash_info_test()
    binary_info_test()

if __name__ == "__main__":
    hash_info_test()

