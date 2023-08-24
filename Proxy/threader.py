import traceback
import time
from multiprocessing import Process


class Threader:
    def __init__(self, main, threads):
        self.threads = threads
        self.processes = []
        self.main = main

    def start(self, class_name=None, *args, **kwargs):
        if class_name:
            self.threads = [class_name]

        try:
            for i in range(len(self.threads)):
                self.processes.append(
                    Process(target=getattr(self.threads[i](*args), self.main)))
                self.processes[i].start()

            for process in self.processes:
                process.join()

        except Exception as e:
            traceback.print_exc(e)
        finally:
            for process in self.processes:
                process.terminate()

    @staticmethod
    def get_threads(_globals, cname):
        classes = []
        for class_name, obj in _globals.items():
            if cname in class_name and isinstance(obj, type) and cname != class_name:
                classes.append(obj)

        return classes

    @staticmethod
    def filter_class_attributes(cname):
        _dir = dir(cname)
        _dir = [info for info in _dir if not info.startswith(
            "__") and not callable(getattr(cname, info))]
        print(_dir)
        return _dir

    @staticmethod
    def timer(func, duration, queue):
        start_time = time.time()

        def wrapper():
            run_time = 0
            try:
                process = Process(target=func, kwargs={"queue": queue})
                process.start()
                while run_time < duration:
                    current_time = time.time()
                    run_time = current_time - start_time
                process.terminate()
            except Exception:
                traceback.print_exc()

        return wrapper
