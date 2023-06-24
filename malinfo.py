import sys
import hashlib

class Info:
    def __init__(self, malware_file):
        self.malware_file = malware_file

        try:
            self.malware_handle = open(self.malware_file, "rb", buffering=0)

        except FileNotFoundError:
            sys.stderr.write("File failed to open for Info\n")
            sys.exit(1)

    def __del__(self):
        self.malware_handle.close()


class HashInfo(Info):
    def __init__(self, malware_file):
        Info.__init__(self, malware_file)
        set_md5()
        set_sha1()
        set_sha256()

    def set_md5(self):
        pass

    def set_sha1(self):
        pass

    def set_sha256(self):
        pass

class BinaryInfo(Info):
    def __init__(self, malware_file):
        Info.__init(self, malware_file)
        self.set_os()
        self.set_file_format()
        self.set_arcitechture()

    def set_os(self):
        pass

    def set_file_format(self):
        pass

    def set_arcitechture(self):
        pass

class ReportInfo(Info):
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

