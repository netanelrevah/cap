__author__ = 'netanelrevah'

from enum import Enum
from datetime import datetime, timedelta
import time
import struct
from io import BytesIO


class InvalidCapException(Exception):
    def __init__(self, data):
        self.data = data
        if data == "":
            super(InvalidCapException, self).__init__("Got empty stream. Cap must have at least 24 bytes")
        elif len(data) < 24:
            super(InvalidCapException, self).__init__("Data too short: len('%s') == %d" % (data, len(data)))
        else:
            super(InvalidCapException, self).__init__("Magic is not valid: %r" % (data[0:4]))


class LinkLayerTypes(Enum):
    none, ethernet = list(range(0, 2))


class NetworkCaptureLoader(object):
    VALID_MAGICS = [b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\xd4']
    SWAPPED_ORDERING_MAGIC = b'\xd4\xc3\xb2\xa1'

    def __init__(self, io):
        self.io = io
        self.cap = None
        self.initialized = False
        self.packet_pack_pattern = '>IIII'
        pass

    def _initialize(self):
        header = self.io.read(24)
        if len(header) < 24 or ((header[:4] not in NetworkCaptureLoader.VALID_MAGICS) and
                                    (header[3::-1] not in NetworkCaptureLoader.VALID_MAGICS)):
            raise InvalidCapException(header + self.io.read())
        if header.startswith(NetworkCaptureLoader.SWAPPED_ORDERING_MAGIC):
            swapped_order = True
            unpacked_header = struct.unpack(NetworkCapture.SWAPPED_ORDER_HEADER_FORMAT, header)
            self.packet_pack_pattern = '<IIII'
        else:
            swapped_order = False
            unpacked_header = struct.unpack(NetworkCapture.NATIVE_ORDER_HEADER_FORMAT, header)
        version = (unpacked_header[1], unpacked_header[2])
        self.cap = NetworkCapture(swapped_order, version, unpacked_header[6], unpacked_header[3],
                                  unpacked_header[5] / 2)
        self.cap.header = header
        self.initialized = True

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        if not self.initialized:
            self._initialize()
        packet_header = self.io.read(16)
        if packet_header != b'':
            seconds, micro_seconds, data_length, original_length = struct.unpack(self.packet_pack_pattern, packet_header)
            p = CapturedPacket(self.io.read(data_length), seconds, micro_seconds, original_length)
            p.header = packet_header
            self.cap.packets.append(p)
            return p
        else:
            raise StopIteration()


class NetworkCapture(object):
    MAGIC_VALUE = 0xa1b2c3d4
    SWAPPED_ORDER_HEADER_FORMAT = '<IHHiIII'
    NATIVE_ORDER_HEADER_FORMAT = '>IHHiIII'

    def __init__(self, swapped_order=False, version=(2, 4), link_layer_type=0, time_zone=0, max_capture_length=131072):
        self.header = None
        self.swapped_order = swapped_order
        self.version = version

        if not isinstance(time_zone, timedelta):
            time_zone = timedelta(hours=time_zone)
        self.time_zone = time_zone

        if not isinstance(link_layer_type, LinkLayerTypes):
            link_layer_type = LinkLayerTypes(link_layer_type)
        self.link_layer_type = LinkLayerTypes(link_layer_type)

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
        return int(self.time_zone.seconds / 3600)

    def header_format(self):
        return NetworkCapture.SWAPPED_ORDER_HEADER_FORMAT if self.swapped_order else NetworkCapture.NATIVE_ORDER_HEADER_FORMAT

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

    def append(self, packet):
        self.packets.append(packet)

    def dump(self):
        file_header = struct.pack(self.header_format(),
                                  NetworkCapture.MAGIC_VALUE,
                                  self.major_version, self.minor_version,
                                  self.time_zone_hours, 0,
                                  self.max_capture_length_octets,
                                  self.link_layer_type.value)
        packet_dump = []
        for packet in self:
            packet_dump.append(packet.dump(self.swapped_order))
        ret = file_header
        for pd in packet_dump:
            ret += pd
        return ret


class CapturedPacket(object):
    def __init__(self, data, seconds=None, micro_seconds=None, original_length=None):
        self.header = None
        self.data = data
        if seconds is None:
            now = datetime.now()
            self.seconds = time.mktime(now.timetuple())
            self.micro_seconds = now.microsecond
        if micro_seconds is None:
            micro_seconds = 0
        self.seconds = seconds
        self.micro_seconds = micro_seconds
        self.original_length = original_length
        if self.original_length is None:
            self.original_length = len(data)

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
        for i in range(len(self) / 16 + 1):
            first_dword = self.data[i * 16: i * 16 + 8]
            last_dword = self.data[i * 16 + 8: i * 16 + 16]

            h = indexes_format.format(i * 16)
            h += ' '.join("{:02x}".format(ord(byte)) for byte in first_dword)
            if last_dword != '':
                h += '  '
                h += indexes_format.format(i * 16 + 8)
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

    def __getitem__(self, item):
        return self.data.__getitem__(item)

    def dump(self, swapped_order=False):
        pack_pattern = '>IIII'
        if swapped_order:
            pack_pattern = '<IIII'
        header = struct.pack(pack_pattern, self.seconds, self.micro_seconds, len(self), self.original_length)
        return header + self.data


def load(path):
    io = open(path, 'rb')
    return loads(io)


def loads(io):
    if isinstance(io, bytes):
        io = BytesIO(io)
    cap_generator = NetworkCaptureLoader(io)
    while True:
        try:
            next(cap_generator)
        except StopIteration:
            break
    return cap_generator.cap


def dump(cap, path):
    open(path, 'wb').write(dumps(cap))


def dumps(cap):
    return cap.dump()