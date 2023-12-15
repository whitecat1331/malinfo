import time
import multiprocessing
import os, sys
import socket
from icecream import ic
from malinfo import StaticAnalysis, DynamicAnalysis, MalInfo, ReportGenerator

DURATION = 3
DIRECTORIES = []
CALCULATOR_BINARY = "Malware.Calc.exe.malz"
MALICOUS_IDENTIFIERS = "identifiers.py"
ELF_BINARY = "hello_world"

TEST_FILE = os.path.join("Tests", MALICOUS_IDENTIFIERS)


def static_analysis_test():
    static_analysis = StaticAnalysis(TEST_FILE)
    ic(static_analysis.magic_bytes_info)
    ic(static_analysis.hash_info) 
    ic(static_analysis.string_info)
    ic(static_analysis.header_info)
    ic(static_analysis.vt_info)
    ic(static_analysis.os_type)


def dynamic_analysis_test():
    static_analysis = StaticAnalysis(TEST_FILE)
    dynamic_analysis = DynamicAnalysis(DURATION, DIRECTORIES, static_analysis)
    ic(dynamic_analysis.processes_info)
    ic(dynamic_analysis.network_packet_info)
    ic(dynamic_analysis.file_changes_info)
    
def malinfo_test():
    malinfo = MalInfo(duration, dirctories, TEST_FILE)
    static_analysis = malinfo.static_analysis
    ic(static_analysis.magic_bytes_info)
    ic(static_analysis.hash_info) 
    ic(static_analysis.string_info)
    ic(static_analysis.header_info)
    ic(static_analysis.vt_info)
    ic(static_analysis.os_type)
    dynamic_analysis = malinfo.dynamic_analysis
    ic(dynamic_analysis.processes_info)
    ic(dynamic_analysis.network_packet_info)
    ic(dynamic_analysis.file_changes_info)

def test_report_generator():
    report_generator = ReportGenerator(DURATION, DIRECTORIES, "malinfo_test_report.md", TEST_FILE)
    

if __name__ == "__main__":
    dynamic_analysis_test()
