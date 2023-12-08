import time
import multiprocessing
import os, sys
import socket
from icecream import ic

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from malinfo import *

DURATION = 5
DIRECTORIES = []
CALCULATOR_BINARY = "Malware.Calc.exe.malz"
MALICOUS_IDENTIFIERS = "identifiers.py"
ELF_BINARY = "hello_world"

TEST_FILE = ELF_BINARY


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
    duration = 5
    dirctories = []
    dynamic_analysis = DynamicAnalysis(duration, dirctories, static_analysis)
    ic(dynamic_analysis.processes_info)
    ic(dynamic_analysis.network_packet_info)
    ic(dynamic_analysis.file_changes_info)
    
def malinfo_test():
    duration = 5
    dirctories = []
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
    pass

if __name__ == "__main__":
    dynamic_analysis_test()
