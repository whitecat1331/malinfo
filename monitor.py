import time
import psutil
import packet_sniffer.sniffer
import filewatch
from concurrent.futures import ProcessPoolExecutor
from icecream import ic


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
    network_packets = packet_sniffer.sniffer.main(duration)
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


    ic(all_monitor_results)
    return all_monitor_results



if __name__ == "__main__":
    main()
