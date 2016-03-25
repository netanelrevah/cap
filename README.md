# Cap: lightweight package for use network captures

[![Build Status](https://travis-ci.org/cap/cap.svg?branch=develop)](https://travis-ci.org/netanelrevah/cap) [![PyPI version](https://img.shields.io/pypi/v/cap.svg)](https://pypi.python.org/pypi/cap/) [![PyPI downloads](https://img.shields.io/pypi/dm/cap.svg)](https://pypi.python.org/pypi/cap/)

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
``` python
import cap
c = cap.load("C:\\test.cap")
print c
```
output:
```
<CaptureFile - 8 packets from 2015-01-01 04:00:11.123456 to 2015-01-01 04:25:55.746353>
```
### use built-in operators:
``` python
len(c)
```
output:
```
16
```
### print nice hex dump
``` python
print c[0].hex_dump()
```
output:
``` 
 0: 12 34 56 78 9A BC CB A9   8: 87 65 43 21 86 dd 12 34
16: 12 34 56 78 9A BC CB A9  24: 12 34 56 78 9A BC CB A9
32: 12 34 56 78 9A BC CB A9  40: 12 34 56 78 9A BC CB A9
48: 12 34 56 78 9A BC CB A9  56: 12 34 56 78 9A BC CB A9
64: 12 34 56 78 9A BC CB A9  72: 12 34 56 78 9A BC CB A9
80: 12 34 56 78 9A BC
```
### parse some fields
``` python
ethernet_next_protocol = c[0][12:14]
print struct.unpack('>H', ethernet_next_protocol)[0]
```
### filter about somthing
``` python
ip_v4_cap = cap.NetworkCapture(True, (2, 4), cap.LinkLayerTypes.ethernet, 0, 15000)
for p in c:
    if p[12:14] == '\x08\x00':
        ip_v4_cap.append(p)
print len(ip_v4_cap)
```
### dump filtered packets
``` python
cap.dump('C:\\new_test.cap', ip_v4_cap)
```

Have a nice use and please report about problems and issues.
Thank you.
