# Module to keep tract of new processes and connection
import time
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
        for i in range(len(monitor_order)):
            yield {f"{monitor_order[i].__name__}": results[i]}

    @staticmethod
    def print_results():
        for result in Monitor.get_results():
            print(result)

    @staticmethod
    def print_dict_results(monitor_order):
        for result in Monitor.to_dict(monitor_order):
            print(result)

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
        yield psutil.pids()


class NetworkMonitor:
    def __init__(self):
        pass

    @Monitor
    @staticmethod
    def monitor(interface=None):
        sniffer = PacketSniffer()
        for frame in sniffer.listen(interface):
            yield [frame]


MONITORS = Proxy.threader.Threader.get_threads(globals(), "Monitor")


def main():
    while True:
        thread = Proxy.threader.Threader("monitor", MONITORS)
        thread.start()
        Monitor.print_dict_results(MONITORS)
        time.sleep(1)


if __name__ == "__main__":
    main()
