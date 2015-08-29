__author__ = 'code-museum'

from datetime import timedelta
from struct import Struct
from io import BytesIO

from enum import Enum

from cap.nicer.bits import format_dword, format_byte
from cap.nicer.times import seconds_from_datetime, microseconds_from_datetime, current_datetime, \
    datetime_from_seconds_and_microseconds, datetime_from_timestamp


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
    none, ethernet = tuple(range(0, 2))


class NetworkCaptureLoader(object):
    VALID_MAGICS = [b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\xd4']
    SWAPPED_ORDERING_MAGIC = b'\xd4\xc3\xb2\xa1'

    def __init__(self, io):
        self.io = io
        self.cap = None
        self.initialized = False
        self.swapped_order = False
        pass

    def _initialize(self):
        header = self.io.read(24)
        if len(header) < 24 or ((header[:4] not in NetworkCaptureLoader.VALID_MAGICS) and
                                    (header[3::-1] not in NetworkCaptureLoader.VALID_MAGICS)):
            raise InvalidCapException(header + self.io.read())
        if header.startswith(NetworkCaptureLoader.SWAPPED_ORDERING_MAGIC):
            self.swapped_order = True
            unpacked_header = NetworkCapture.SWAPPED_ORDER_HEADER_STRUCT.unpack(header)
        else:
            unpacked_header = NetworkCapture.NATIVE_ORDER_HEADER_STRUCT.unpack(header)
        version = (unpacked_header[1], unpacked_header[2])
        self.cap = NetworkCapture(self.swapped_order, version, unpacked_header[6], unpacked_header[3],
                                  unpacked_header[5] / 2)
        self.cap.header = header
        self.initialized = True

    def initialize(self):
        if not self.initialized:
            self._initialize()

    def _read_next_header(self):
        return self.io.read(16)

    def _read_next_data(self, data_length):
        return self.io.read(data_length)

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        self.initialize()

        packet_header = self._read_next_header()
        if not packet_header:
            raise StopIteration()

        loader = CapturedPacketLoader(self.swapped_order)
        loader.parse_header(packet_header)
        loader.data = self._read_next_data(loader.packet_header.data_length)
        p = loader.build()

        self.cap.packets.append(p)
        return p


class CapturedPacketHeaderStruct(object):
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IIII')
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IIII')

    def __init__(self, seconds, microseconds, data_length, original_length):
        self.seconds = seconds
        self.microseconds = microseconds
        self.data_length = data_length
        self.original_length = original_length

    @property
    def capture_time(self):
        return datetime_from_seconds_and_microseconds(self.seconds, self.microseconds)

    @staticmethod
    def get_header_struct(is_native_order=True):
        return CapturedPacketHeaderStruct.NATIVE_ORDER_HEADER_STRUCT if is_native_order else \
            CapturedPacketHeaderStruct.SWAPPED_ORDER_HEADER_STRUCT

    def pack(self, is_native_order=True):
        return self.get_header_struct(is_native_order).pack(self.seconds, self.microseconds, self.data_length,
                                                            self.original_length)

    @classmethod
    def unpack(cls, data, is_native_order=True):
        header_struct = CapturedPacketHeaderStruct.get_header_struct(is_native_order)
        seconds, microseconds, data_length, original_length = header_struct.unpack(data)
        return cls(seconds, microseconds, data_length, original_length)


class CapturedPacketLoader(object):
    def __init__(self, swapped_order=False):
        self.swapped_order = swapped_order
        self.packed_packet_header = None
        self.packet_header = None
        self.data = b''

    def parse_header(self, packed_packet_header):
        self.packed_packet_header = packed_packet_header
        self.packet_header = CapturedPacketHeaderStruct.unpack(packed_packet_header, not self.swapped_order)

    @property
    def has_header(self):
        return self.packet_header is not None

    @property
    def has_data(self):
        return self.data is not None

    def build(self):
        if not self.has_header or not self.has_data:
            return None
        if len(self.data) != self.packet_header.data_length:
            raise Exception('Packet header invalid, got data length {} instead of {}'.format(
                len(self.data), self.packet_header.data_length))
        p = CapturedPacket(self.data, self.packet_header.capture_time, self.packet_header.original_length)
        p.header = self.packed_packet_header
        return p


class NetworkCapture(object):
    MAGIC_VALUE = 0xa1b2c3d4
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IHHiIII')
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IHHiIII')

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

    def copy(self):
        c = NetworkCapture(self.swapped_order, self.version, self.link_layer_type.value, self.time_zone,
                           self.max_capture_length)
        c.packets = self.packets
        return c

    def __add__(self, other):
        c = self.copy()
        c.packets = c.packets + other.packets
        return c

    def header_struct(self):
        return NetworkCapture.SWAPPED_ORDER_HEADER_STRUCT if self.swapped_order else NetworkCapture.NATIVE_ORDER_HEADER_STRUCT

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
        pass

    def sort(self):
        self.packets.sort(key=lambda p: p.capture_time)
        pass

    def dumps(self):
        file_header = self.header_struct().pack(NetworkCapture.MAGIC_VALUE,
                                                self.major_version, self.minor_version,
                                                self.time_zone_hours, 0,
                                                self.max_capture_length_octets,
                                                self.link_layer_type.value)

        packet_dump = []
        for packet in self:
            packet_dump.append(packet.dumps(self.swapped_order))
        ret = file_header
        for pd in packet_dump:
            ret += pd
        return ret


class CapturedPacket(object):
    def __init__(self, data, capture_time=None, original_length=None):
        self.header = None
        self.data = data

        self.capture_time = capture_time
        if self.capture_time is None:
            self.capture_time = current_datetime()
        elif isinstance(self.capture_time, int) or isinstance(self.capture_time, float):
            self.capture_time = datetime_from_timestamp(self.capture_time)

        self.original_length = original_length
        if self.original_length is None:
            self.original_length = len(data)

    @property
    def seconds(self):
        return seconds_from_datetime(self.capture_time)

    @property
    def microseconds(self):
        return microseconds_from_datetime(self.capture_time)

    @property
    def is_fully_captured(self):
        return self.original_length == len(self)

    def hex_dump(self):
        return format_dword(self.data)

    def __str__(self):
        return ''.join(format_byte(byte) for byte in self.data)

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return '<CapturedPacket - %d bytes captured at %s >' % (len(self.data), self.capture_time)

    def __iter__(self):
        return self.data.__iter__()

    def __getitem__(self, item):
        return self.data.__getitem__(item)

    def __lt__(self, other):
        return self.capture_time < other.capture_time

    def dumps(self, swapped_order=False):
        header_struct = CapturedPacketHeaderStruct(self.seconds, self.microseconds, len(self), self.original_length)
        return header_struct.pack(not swapped_order) + self.data


def load(path):
    stream = open(path, 'rb')
    return loads(stream)


def loads(data):
    if isinstance(data, bytes):
        data = BytesIO(data)
    cap_generator = NetworkCaptureLoader(data)
    while True:
        try:
            next(cap_generator)
        except StopIteration:
            break
    return cap_generator.cap


def dump(cap, path):
    open(path, 'wb').write(dumps(cap))


def dumps(cap):
    return cap.dumps()


def merge(target_path, *source_paths):
    if not source_paths:
        dump(NetworkCapture(), target_path)
    else:
        caps = [load(p) for p in source_paths]
        new_cap = caps[0]
        for c in caps[1:]:
            new_cap.packets += c.packets
        dump(new_cap, target_path)
