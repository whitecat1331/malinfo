# Module to keep tract of new processes and connection
import time
import psutil


class Monitor:
    DURATION = 5

    def __init__(self, func, duration=DURATION):
        self.duration = duration
        self.tracking_info = []
        self.start_time = time.time()
        self.func = func

    def __call__(self):
        current_time = time.time()
        run_time = 0
        while run_time < self.duration:
            print(f"{run_time}s < {self.duration}s")
            current_info = self.func()
            for info in current_info:
                if info not in self.tracking_info:
                    self.tracking_info.append(info)
            time.sleep(1)
            current_time = time.time()
            run_time = current_time - self.start_time

        return self.tracking_info


class ProcessMonitor:
    def __init__(self):
        pass

    @Monitor
    @staticmethod
    def monitor_processes():
        return psutil.pids()


class ConnectionMonitor:
    def __init__(self):
        pass


def start_process_monitor():
    print("Starting...")
    info = ProcessMonitor().monitor_processes()
    print(f"End\n{info}")


def main():
    pass


if __name__ == "__main__":
    start_process_monitor()
