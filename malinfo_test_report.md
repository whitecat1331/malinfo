
<center><b>test</b></center> <br>
<center>test</center>           <br>
<center>test.com</center>                   <br>
<center>2023-12-19 21:15:08.602258</center>           <br>

---

### <u>Malware Samples</u>

[malware_source_link](test.com)
<br>

---

### <u>Static Analysis</u>

##### Malware Info:

###### Magic Bytes

```
Python script, ASCII text executable
```

###### Hashes:

| Hash | Value |
| ---- | ----- |
| md5 | 2dee01b72118324af23d625ae289e0bb |
| sha1 | 96132eb00a4353c292b7ba6005b69e573b957771 |
| sha256 | 978b512170ab2009266dd264eabbfef686b900abaa1eec2619c74d8a6dd0f1b3 |


###### Header Info

```
None
```

##### Virus Total



###### Strings:

Note: Links Defanged Using [Cyber Chef](https://gchq.github.io/CyberChef/)

```
import time
import multiprocessing
import os, sys
import socket
import tempfile
from icecream import ic


def dummy_process(duration):
    ic("Starting dummy process")
    time.sleep(duration)
    ic("Ending dummy process")

def dns_requests(duration):
    start_time = time.time()
    run_time = 0
    while run_time < duration:
        ic(socket.gethostbyname('whatsmydns.net'))
        run_time = time.time() - start_time
        time.sleep(1)

def write_to_tmp(duration):
    start_time = time.time()
    run_time = 0
    tmp_dir = tempfile.gettempdir()
    tmp_file = "test_malware.txt"
    tmp_path = os.path.join(tmp_dir, tmp_file)
    while run_time < duration:
        with open(tmp_path, "a") as f:
            ic("Writing to file...")
            f.write("This was written from test malware\n")

        run_time = time.time() - start_time
        time.sleep(1)
    os.remove(tmp_path)
    ic("removed file")

def malware_test():
    duration = 5
    malinfo_test_functions = [dummy_process, dns_requests, write_to_tmp]

    processes = []
    for test_function in malinfo_test_functions: 
        p = multiprocessing.Process(target=test_function, args=(duration,))
        processes.append(p)
        p.start()

    for process in processes:
        process.join(timeout=1)

if __name__ == "__main__":
    malware_test()


```

---

### <u>Dynamic Analysis</u>

##### Process Indicators:

```
python

```

##### Network Indicators:

```
whatsmydns.net

```

##### File Indicators

```
/tmp/k9ekagh_
/tmp/test_malware.txt
/tmp

```

---

