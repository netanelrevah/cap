# Cap: lightweight package for use network captures

[![PyPI version](https://img.shields.io/pypi/v/cap.svg)](https://pypi.python.org/pypi/cap/)
[![PyPI downloads](https://img.shields.io/pypi/dm/cap.svg)](https://pypi.python.org/pypi/cap/)
[![GitHub](https://img.shields.io/github/license/netanelrevah/cap)](https://pypi.python.org/pypi/cap/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cap)](https://pypi.python.org/pypi/cap/)

The idea is to read and write capture files like it is really a serialized data. The API is ment to be close as possible to json and pickle APIs.

## Installation:
install the package by:
``` bash
pip install cap
```
or from the source:
``` bash
python setup.py install
```
## Usage:
### read cap:
```python
import cap
captured_packets = cap.load(open("C:\\test.cap", "rb"))
```
### filter about somthing
```python
ip_v4_captured_packet = []
for captured_packet in captured_packets:
    if captured_packet.data[12:14] == '\x08\x00':
        ip_v4_captured_packet.append(p)
```
### dump filtered packets
```python
cap.dump(ip_v4_captured_packet, open('C:\\new_test.cap', "wb"))
```

Have a nice use and please report about problems and issues.
Thank you.
