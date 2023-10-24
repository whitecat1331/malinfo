# Module to keep tract of new processes and connection
import time
import sys
import psutil
import traceback
import Proxy.threader
from multiprocessing import Queue
import packet_sniffer.sniffer
from packet_sniffer.core import PacketSniffer
from packet_sniffer.output import OutputToScreen


class Monitor():
    DURATION = 5
    RESULTS = Queue()

    def __init__(self, func, duration=DURATION):
        self.duration = duration
        self.tracking_info = []
        self.start_time = time.time()
        self.func = func

    def __call__(self):
        current_time = time.time()
        run_time = 0
        try:
            while run_time < self.duration:
                updated_info = next(self.func())
                for info in updated_info:
                    if info not in self.tracking_info:
                        self.tracking_info.append(info)
                current_time = time.time()
                run_time = current_time - self.start_time
        except Exception:
            traceback.print_exc()
        finally:
            Monitor.RESULTS.put(self.tracking_info)
            return self.tracking_info

    @staticmethod
    def get_results():
        while not Monitor.RESULTS.empty():
            yield Monitor.RESULTS.get()

    @staticmethod
    def to_dict(monitor_order):
        results = Monitor.get_all_results()
        all_results = {}
        for item in results:
            print("\nResult:\n", item)
        sys.exit()
        try:
            for i in range(len(monitor_order)):
                all_results[f"{monitor_order[i].__name__}"] = results[i]
        except:
            traceback.print_exc()

        return all_results

    @staticmethod
    def get_all_results():
        results = []
        for result in Monitor.get_results():
            results.append(result)

        return results

    @staticmethod
    def timer(func):
        return Proxy.threader.Threader.timer(func,
                                             duration=Monitor.DURATION, queue=Monitor.RESULTS)


class ProcessMonitor:
    def __init__(self):
        pass

    @Monitor
    @staticmethod
    def monitor():
        procs = [p.info for p in psutil.process_iter(
            ['pid', 'name', 'ppid', 'cwd', 'cmdline', 'connections', 'create_time', 'terminal', 'username', 'status'])]
        yield procs

    @ staticmethod
    def parse_info(raw_data):
        # convert all items in list to a dictionary for further processing
        raw_data = raw_data[ProcessMonitor.__name__]
        return raw_data


class NetworkMonitor:

    def __init__(self):
        pass

    @staticmethod
    @Monitor.timer
    def monitor(*args):
        results = packet_sniffer.sniffer.main(
            Monitor.DURATION - 1)
        args[0].put(results)
        return results





    @ staticmethod
    def parse_info(raw_data):
        raw_data = raw_data[NetworkMonitor.__name__]
        return raw_data


MONITORS = Proxy.threader.Threader.get_threads(globals(), "Monitor")


def main():
    threads = Proxy.threader.Threader("monitor", MONITORS)
    threads.start()
    thread_results = Monitor.to_dict(MONITORS)
    process_info = ProcessMonitor.parse_info(thread_results)
    network_info = NetworkMonitor.parse_info(thread_results)
    print("\nProcess Info\n")
    print(process_info)
    print("\nNetwork Info\n")
    print(network_info)


if __name__ == "__main__":
    main()
