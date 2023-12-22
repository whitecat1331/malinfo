import time
import multiprocessing
import os, sys
import socket
import tempfile
from icecream import ic


def dummy_processes(duration):
    ic("Starting dummy process")
    time.sleep(duration)
    ic("Ending dummy process")

def dummy_process():
    ic("Starting dummy process")
    ic("Ending dummy process")

def dns_requests(duration):
    start_time = time.time()
    run_time = 0
    while run_time < duration:
        ic(socket.gethostbyname('whatsmydns.net'))
        run_time = time.time() - start_time
        time.sleep(1)

def dns_request():
    ic(socket.gethostbyname('whatsmydns.net'))

def write_to_tmps(duration):
    start_time = time.time()
    run_time = 0
    tmp_dir = tempfile.gettempdir()
    tmp_file = "test_malware.txt"
    tmp_path = os.path.join(tmp_dir, tmp_file)
    while run_time < duration:
        with open(tmp_path, "a") as f:
            ic("Writing to file...")
            f.write("This was written from test malware\n")

        run_time = time.time() - start_time
        time.sleep(1)
    os.remove(tmp_path)
    ic("removed file")

def write_to_tmp():
    start_time = time.time()
    run_time = 0
    tmp_dir = tempfile.gettempdir()
    tmp_file = "test_malware.txt"
    tmp_path = os.path.join(tmp_dir, tmp_file)
    with open(tmp_path, "a") as f:
        ic("Writing to file...")
        f.write("This was written from test malware\n")

    os.remove(tmp_path)
    ic("removed file")

def malware_tests():
    duration = 5
    malinfo_test_functions = [dummy_processes, dns_requests, write_to_tmps]

    processes = []
    for test_function in malinfo_test_functions: 
        p = multiprocessing.Process(target=test_function, args=(duration,))
        processes.append(p)
        p.start()

    for process in processes:
        process.join(timeout=1)

def malware_test():
    malinfo_test_functions = [dummy_process, dns_request, write_to_tmp]

    processes = []
    for test_function in malinfo_test_functions: 
        p = multiprocessing.Process(target=test_function)
        processes.append(p)
        p.start()

    for process in processes:
        process.join(timeout=1)

if __name__ == "__main__":
    malware_test()
