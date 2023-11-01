import time
import psutil
import packet_sniffer.sniffer
import filewatch
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

    return processes

def network_monitor(duration):
    network_packets = packet_sniffer.sniffer.main(duration)
    return network_packets

def filesystem_monitor(duration):
    return filewatch.main()



def main(duration):
    process_results = process_monitor(duration)
    network_results = network_monitor(duration)
    file_results = filesystem_monitor(duration)
    ic(process_results)
    ic(network_results)
    ic(file_results)

DURATION = 5

if __name__ == "__main__":
    main(DURATION)
