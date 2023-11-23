import time
import psutil
from concurrent.futures import ProcessPoolExecutor
from scapy.all import sniff
from icecream import ic

if __name__ == "__main__":
    import filewatch
else:
    import Monitor.filewatch as filewatch

DURATION = 5
DEPTH_LIMIT = 0

def process_monitor(duration):
    start_time = time.time() 

    run_time = 0
    processes = []
    while run_time < duration:
        procs = [p.info for p in psutil.process_iter(
            ['pid', 'name', 'ppid', 'cwd', 'cmdline', 'connections', 'create_time', 'terminal', 'username', 'status'])]

        for info in procs:
            if info not in processes:
                processes.append(info)

        run_time = time.time() - start_time

    return {"process_monitor": processes}

def network_monitor(duration):
    network_packets = sniff(timeout=duration)
    return {"network_monitor": network_packets}

def filesystem_monitor(duration):
    return {"filesystem_monitor": filewatch.main()}

MONITORS = [process_monitor, network_monitor, filesystem_monitor]
DURATION = 5


def main(duration=DURATION):
    process_pool_executor = ProcessPoolExecutor()
    processes = []
    for monitor in MONITORS:
        running_process = process_pool_executor.submit(monitor, duration)
        processes.append(running_process)

    all_monitor_results = {}
    for running_process in processes:
        all_monitor_results.update(running_process.result())


    return all_monitor_results



if __name__ == "__main__":
    main()
