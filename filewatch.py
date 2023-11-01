import time
import os
import string
import sys
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from icecream import ic

network_packets = Queue()
DURATION = 5
DEPTH_LIMIT = 0

def on_created(event):
    network_packets.put(f"{event.src_path} has been created.")

def on_deleted(event):
    network_packets.put(f"{event.src_path} was deleted")

def on_modified(event):
    network_packets.put(f"{event.src_path} has been modified")

def on_moved(event):
    network_packets.put(f"{event.src_path} moved to {event.dest_path}")

def main(duration=DURATION, depth_limit=DEPTH_LIMIT):
    patterns = ["*"]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved

    go_recursively = False

    path = os.path.abspath(os.sep)
    path = os.path.normpath(path)
    directories = []
    for root,dirs,files in os.walk(path, topdown=True):
        depth = root[len(path) + len(os.path.sep):].count(os.path.sep)
        if depth == depth_limit:
            # We're currently two directories in, so all subdirs have depth 3
            directories += [os.path.join(root, d) for d in dirs]
            dirs[:] = [] # Don't recurse any deeper

    observers = []
    
    for directory in directories:
        my_observer = Observer()
        my_observer.start()
        my_observer.schedule(my_event_handler, directory, recursive=go_recursively)
        observers.append(my_observer)


    time.sleep(duration)

    for my_observer in observers:
        my_observer.stop()
        my_observer.join()

    return list(network_packets.queue)

if __name__ == "__main__":
    main()


