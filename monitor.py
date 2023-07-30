# Module to keep tract of new processes and connection
import time
import json
import psutil
import traceback
import Proxy.threader
from multiprocessing import Process, Queue
from packet_sniffer.core import PacketSniffer
from abc import ABC, abstractmethod


class Monitor():
    DURATION = 1
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
        for i in range(len(monitor_order)):
            all_results[f"{monitor_order[i].__name__}"] = results[i]

        return all_results

    @staticmethod
    def get_all_results():
        results = []
        for result in Monitor.get_results():
            results.append(result)

        return results


class ProcessMonitor:
    def __init__(self):
        pass

    @Monitor
    @staticmethod
    def monitor():
        for process in psutil.process_iter(list(psutil.Process().as_dict().keys())):
            # must leave as list to get all items
            yield process.info.items()

    @staticmethod
    def parse_info(raw_data):
        # convert all items in list to a dictionary for further processing
        raw_data = raw_data[ProcessMonitor.__name__]
        info = {}
        for process_info, value in raw_data:
            info[process_info] = value
        return info


class NetworkMonitor:
    def __init__(self):
        pass

    @ Monitor
    @ staticmethod
    def monitor(interface=None):
        sniffer = PacketSniffer()
        for frame in sniffer.listen(interface):
            yield [frame]


MONITORS = Proxy.threader.Threader.get_threads(globals(), "Monitor")


def main():
    while True:
        thread = Proxy.threader.Threader("monitor", MONITORS)
        thread.start()
        thread_results = Monitor.to_dict(MONITORS)
        process_info = ProcessMonitor.parse_info(thread_results)

        time.sleep(1)


if __name__ == "__main__":
    main()
