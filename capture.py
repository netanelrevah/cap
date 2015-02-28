import StringIO

__author__ = 'netanelrevah'

import struct
from datetime import datetime, timedelta
from enum import Enum


class LinkLayerHeaderTypes(Enum):
    none, ethernet = range(0, 2)

MAGIC_VALUE = 0xa1b2c3d4

NATIVE_ORDERING_MAGIC = '\xa1\xb2\xc3\xd4'
NATIVE_ORDERING_MAGIC_WITH_NS = '\xa1\xb2\x3c\xd4'
SWAPPED_ORDERING_MAGIC = '\xd4\xc3\xb2\xa1'
SWAPPED_ORDERING_MAGIC_WITH_NS = '\xd4\x3c\xb2\xa1'

HEADER_NATIVE_UNPACKING_STRING = 'IHHiIII'
HEADER_SWAPPED_UNPACKING_STRING = 'IHHiIII'


class CaptureFileGenerator(object):
    def __init__(self, io):
        self.io = io
        self._extract_header_data(self.io.read(24))
        pass

    def _extract_header_data(self, header):
        unpacked_header = None
        if header.startswith('\xD4\xC3\xB2\xA1'):
            unpacked_header = struct.unpack('IHHiIII', header)
        swapped_order = (header[0:4] == SWAPPED_ORDERING_MAGIC)
        version = (unpacked_header[1], unpacked_header[2])
        self.cap = CaptureFile(swapped_order, version, unpacked_header[6], unpacked_header[3], unpacked_header[5] / 2)
        self.cap.header = header

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        packet_header = self.io.read(16)
        if packet_header != '':
            seconds, micro_seconds, data_length, original_length = struct.unpack('IIII', packet_header)
            p = CapturedPacket(self.io.read(data_length), seconds, micro_seconds, original_length)
            p.header = packet_header
            self.cap.packets.append(p)
            return p
        else:
            raise StopIteration()


class CaptureFile(object):
    def __init__(self, swapped_order, version, link_layer_type, time_zone, max_capture_length):
        self.header = None
        self.swapped_order = True
        self.version = (2, 4)

        if not isinstance(time_zone, timedelta):
            time_zone = timedelta(hours=time_zone)
        self.time_zone = time_zone

        if not isinstance(link_layer_type, LinkLayerHeaderTypes):
            link_layer_type = LinkLayerHeaderTypes(link_layer_type)
        self.link_layer_type = LinkLayerHeaderTypes(link_layer_type)

        self.max_capture_length = max_capture_length
        self.packets = []

    def __len__(self):
        return len(self.packets)

    def __getitem__(self, index):
        return self.packets[index]

    def __iter__(self):
        return self.packets.__iter__()

    def __repr__(self):
        return '<CaptureFile - %d packets from %s to %s>' % (len(self), self[0].capture_time, self[-1].capture_time)


class CapturedPacket(object):
    def __init__(self, data, seconds, micro_seconds, original_length):
        self.header = None
        self.data = data
        self.seconds = seconds
        self.micro_seconds = micro_seconds
        self.original_length = original_length

    @property
    def capture_time(self):
        dt = datetime.fromtimestamp(self.seconds) + timedelta(microseconds=self.micro_seconds)
        return dt

    @property
    def is_full(self):
        return self.original_length == len(self)

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return '<CapturedPacket - %d bytes captured at %s >' % (len(self.data), self.capture_time)

    def __iter__(self):
        return self.data.__iter__()


def load(path):
    io = open(path, 'rb')
    return loads(io)


def loads(io):
    if isinstance(io, str):
        io = StringIO.StringIO(io)
    cap_generator = CaptureFileGenerator(io)
    while True:
        try:
            cap_generator.next()
        except StopIteration as e:
            break
    return cap_generator.cap


def dumps(cap):
    assert isinstance(cap, CaptureFile)
    major, minor = cap.version
    time_zone = cap.time_zone.seconds / 60 / 60
    snapshot_len = cap.max_capture_length * 2
    structure_format = 'IHHiIII' if not cap.swapped_order else '<IHHiIII'
    return struct.pack(structure_format, MAGIC_VALUE, major, minor, time_zone, 0, snapshot_len, cap.link_layer_type.value)