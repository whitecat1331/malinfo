import time
import psutil
from icecream import ic

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


def main(duration):
    process_results = process_monitor(duration)
    ic(process_results)

DURATION = 5

if __name__ == "__main__":
    main(DURATION)
