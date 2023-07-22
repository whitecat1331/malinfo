# Module to keep tract of new processes and connection
import time
import psutil
import traceback
from multiprocessing import Process, Queue
from packet_sniffer.core import PacketSniffer


class Monitor:
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
        except Exception as e:
            traceback.print_exc()
        finally:
            Monitor.RESULTS.put(self.tracking_info)
            return self.tracking_info

    @staticmethod
    def get_results():
        yield Monitor.RESULTS.get()


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


MONITORS = [ProcessMonitor, NetworkMonitor]


def start_monitors(index=None, Monitors=MONITORS):
    if index:
        Monitors = [Monitors[index]]

    processes = []

    try:
        for i in range(len(Monitors)):
            print(f"Starting {Monitors[i].__name__}")
            processes.append(Process(target=Monitors[i]().monitor))
            processes[i].start()

        for i in range(len(Monitors)):
            print(f"Ending {Monitors[i].__name__}")
            processes[i].join()

        print(Monitor.RESULTS.get())
        print()
        print(Monitor.RESULTS.get())

    except Exception as e:
        traceback.print_exc(e)
    finally:
        for i in range(len(processes)):
            print(f"Terminating {Monitors[i].__name__}")
            processes[i].terminate()


if __name__ == "__main__":
    start_monitors()
