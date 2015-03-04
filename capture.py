__author__ = 'netanelrevah'

from enum import Enum
from datetime import datetime, timedelta
import struct
import StringIO


class LinkLayerHeaderTypes(Enum):
    none, ethernet = range(0, 2)


class CaptureFileGenerator(object):
    SWAPPED_ORDERING_MAGIC = '\xd4\xc3\xb2\xa1'

    def __init__(self, io):
        self.io = io
        self._extract_header_data(self.io.read(24))
        pass

    def _extract_header_data(self, header):
        if header.startswith(CaptureFileGenerator.SWAPPED_ORDERING_MAGIC):
            unpacked_header = struct.unpack(CaptureFile.SWAPPED_ORDER_HEADER_FORMAT, header)
        else:
            unpacked_header = struct.unpack(CaptureFile.NATIVE_ORDER_HEADER_FORMAT, header)
        swapped_order = (header[0:4] == CaptureFileGenerator.SWAPPED_ORDERING_MAGIC)
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
    MAGIC_VALUE = 0xa1b2c3d4
    SWAPPED_ORDER_HEADER_FORMAT = '<IHHiIII'
    NATIVE_ORDER_HEADER_FORMAT = '>IHHiIII'

    def __init__(self, swapped_order, version, link_layer_type, time_zone, max_capture_length):
        self.header = None
        self.swapped_order = swapped_order
        self.version = version

        if not isinstance(time_zone, timedelta):
            time_zone = timedelta(hours=time_zone)
        self.time_zone = time_zone

        if not isinstance(link_layer_type, LinkLayerHeaderTypes):
            link_layer_type = LinkLayerHeaderTypes(link_layer_type)
        self.link_layer_type = LinkLayerHeaderTypes(link_layer_type)

        self.max_capture_length = max_capture_length
        self.packets = []

    @property
    def max_capture_length_octets(self):
        return self.max_capture_length * 2

    @property
    def major_version(self):
        major, _ = self.version
        return major

    @property
    def minor_version(self):
        _, minor = self.version
        return minor

    @property
    def time_zone_hours(self):
        return self.time_zone.seconds / 3600

    def header_format(self):
        return CaptureFile.SWAPPED_ORDER_HEADER_FORMAT if self.swapped_order else CaptureFile.NATIVE_ORDER_HEADER_FORMAT

    def __len__(self):
        return len(self.packets)

    def __getitem__(self, index):
        return self.packets[index]

    def __iter__(self):
        return self.packets.__iter__()

    def __repr__(self):
        if len(self) == 0:
            return '<CaptureFile - Empty cap>'
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

    def hex_dump(self):
        max_index_len = len(str(len(self)))
        indexes_format = "{:" + str(max_index_len) + "}: "

        hs = []
        for i in xrange(len(self) / 16 + 1):
            first_dword = self.data[i*16: i*16+8]
            last_dword = self.data[i*16+8: i*16+16]

            h = indexes_format.format(i*16)
            h += ' '.join("{:02x}".format(ord(byte)) for byte in first_dword)
            if last_dword != '':
                h += '  '
                h += indexes_format.format(i*16+8)
                h += ' '.join("{:02x}".format(ord(byte)) for byte in last_dword)
            hs.append(h)
        return '\n'.join(hs)

    def __str__(self):
        return ''.join("{:02x}".format(ord(byte)) for byte in self.data)

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
        except StopIteration:
            break
    return cap_generator.cap


def dumps(cap):
    return struct.pack(cap.header_format(), CaptureFile.MAGIC_VALUE, cap.major_version, cap.minor_version,
                       cap.time_zone_hours, 0, cap.max_capture_length_octets, cap.link_layer_type.value)