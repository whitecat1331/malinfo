import traceback
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
