import time
import psutil
import netifaces
from concurrent.futures import ProcessPoolExecutor
from scapy.all import sniff
from icecream import ic

import Monitor.filewatch as filewatch

def process_monitor(duration):
    start_time = time.time() 

    run_time = 0
    processes = []
    while run_time < duration:
        procs = [p.info for p in psutil.process_iter(
            ['pid', 'name', 'ppid', 'cwd', 'cmdline', 'connections', 'create_time', 'username', 'status'])]

        for info in procs:
            processes.append(info)

        run_time = time.time() - start_time

    return {"process_monitor": processes}

def network_monitor(interface, duration):
    network_packets = sniff(iface=interface, timeout=duration)
    return {"network_monitor": network_packets}

def filesystem_monitor(duration, directories):
    return {"filesystem_monitor": filewatch.main(duration, directories)}


def main(interface, duration, directories):
    process_pool_executor = ProcessPoolExecutor()
    processes = []
    running_process = process_pool_executor.submit(process_monitor, duration)
    processes.append(running_process)
    running_process = process_pool_executor.submit(network_monitor, interface, duration)
    processes.append(running_process)
    running_process = process_pool_executor.submit(filesystem_monitor, duration, directories)
    processes.append(running_process)


    all_monitor_results = {}
    for running_process in processes:
        all_monitor_results.update(running_process.result())


    return all_monitor_results

INTERFACE = netifaces.interfaces()[0]
DURATION = 5
DIRECTORIES = []

if __name__ == "__main__":
    main(INTERFACE, DURATION, DIRECTORIES)
