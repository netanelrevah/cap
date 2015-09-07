from struct import Struct

from cap.logics import NetworkCapture, CapturedPacket

from cap.nicer.structs import DefinedStruct
from cap.nicer.times import datetime_from_seconds_and_microseconds, seconds_from_datetime, \
    microseconds_from_datetime

__author__ = 'netanelrevah'


class PacketCaptureHeaderFormat(DefinedStruct):
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IHHiIII')
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IHHiIII')
    MAGIC_VALUE = 0xa1b2c3d4

    @classmethod
    def from_network_capture(cls, captured_packet):
        # major_version, minor_version = captured_packet.version
        # time_zone_hours = int(hours_from_timedelta(captured_packet.time_zone))
        # max_capture_length_octets = captured_packet.max_capture_length * 2
        # link_layer_type = captured_packet.link_layer_type.value
        # return PacketCaptureHeaderFormat(
        #     major_version, minor_version, time_zone_hours, max_capture_length_octets, link_layer_type)
        return cls(2, 4, 0, 0x40000, 1)

    @classmethod
    def loads(cls, stream, is_native_order=True):
        header_data = stream.read(24)  # TODO: use length function
        return cls.unpack(header_data, is_native_order)

    def __init__(self, major_version, minor_version, time_zone_hours, max_capture_length_octets, link_layer_type):
        self.major_version = major_version
        self.minor_version = minor_version
        self.time_zone_hours = time_zone_hours
        self.max_capture_length_octets = max_capture_length_octets
        self.link_layer_type = link_layer_type

    @staticmethod
    def _filter_constants(values):
        return values[1], values[2], values[4], values[5], values[6]

    def _get_values_tuple(self):
        return self.MAGIC_VALUE, self.major_version, self.minor_version, self.time_zone_hours, 0, \
               self.max_capture_length_octets, self.link_layer_type


class CapturedPacketHeaderFormat(DefinedStruct):
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IIII')
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IIII')

    @classmethod
    def from_captured_packet(cls, captured_packet):
        seconds = seconds_from_datetime(captured_packet.capture_time)
        microseconds = microseconds_from_datetime(captured_packet.capture_time)
        return cls(seconds, microseconds, len(captured_packet), captured_packet.original_length)

    @classmethod
    def loads(cls, stream, is_native_order=True):
        header_data = stream.read(16)  # TODO: use length function
        if not header_data or len(header_data) == 0:
            return
        return cls.unpack(header_data, is_native_order)

    def __init__(self, seconds, microseconds, data_length, original_length):
        self.seconds = seconds
        self.microseconds = microseconds
        self.data_length = data_length
        self.original_length = original_length

    @property
    def capture_time(self):
        return datetime_from_seconds_and_microseconds(self.seconds, self.microseconds)

    def _get_values_tuple(self):
        return (self.seconds,
                self.microseconds,
                self.data_length,
                self.original_length)


class CapturedPacketFormat(object):
    @classmethod
    def from_captured_packet(cls, captured_packet):
        captured_packet_header = CapturedPacketHeaderFormat.from_captured_packet(captured_packet)
        return cls(captured_packet_header, captured_packet.data)

    @classmethod
    def loads(cls, stream, is_native_order):
        captured_packet_header = CapturedPacketHeaderFormat.loads(stream, is_native_order)
        if captured_packet_header is None:
            return None
        data = stream.read(captured_packet_header.data_length)
        return cls(captured_packet_header, data)

    def __init__(self, header, data):
        self.header = header
        self.data = data

    def to_captured_packet(self):
        return CapturedPacket(self.data, self.header.capture_time, self.header.original_length)

    def dumps(self, is_native_order=True):
        return self.header.pack(is_native_order) + self.data


class PacketCaptureFormatLoader(object):
    MAGIC_VALUES_TO_ORDER = {b'\xa1\xb2\xc3\xd4': True, b'\xa1\xb2\x3c\xd4': True,
                             b'\xd4\xc3\xb2\xa1': False, b'\xd4\x3c\xb2\xa1': False}

    def __init__(self, stream):
        self.stream = stream
        self._is_native_order = False
        self._file_header = None

    def _load_file_header(self):
        magic = self.stream.read(4)
        if magic not in self.MAGIC_VALUES_TO_ORDER:
            raise Exception('Stream magic is invalid')
        self._is_native_order = self.MAGIC_VALUES_TO_ORDER[magic]
        self.stream.seek(-4, 1)

        self._file_header = PacketCaptureHeaderFormat.loads(self.stream, self._is_native_order)

    def _force_file_header_loading(self):
        if self._file_header is None:
            self._load_file_header()

    @property
    def file_header(self):
        self._force_file_header_loading()
        return self._file_header

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        self._force_file_header_loading()
        formatted_captured_packet = CapturedPacketFormat.loads(self.stream, self._is_native_order)
        if formatted_captured_packet is None:
            raise StopIteration()
        return formatted_captured_packet


class PacketCaptureFormatDumper(object):
    MAGIC_VALUES_TO_ORDER = {b'\xa1\xb2\xc3\xd4': True, b'\xa1\xb2\x3c\xd4': True,
                             b'\xd4\xc3\xb2\xa1': False, b'\xd4\x3c\xb2\xa1': False}

    def __init__(self, packet_capture, is_native_order=True):
        self._packet_capture = packet_capture
        self._is_native_order = is_native_order
        self._file_header = None
        self._captured_packets_iterator = None

    def _dump_file_header(self):
        self._file_header = self._packet_capture.file_header.pack(self._is_native_order)

    def _force_file_header_dumping(self):
        if self._file_header is None:
            self._dump_file_header()

    @property
    def file_header(self):
        self._force_file_header_dumping()
        return self._file_header

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        self._force_file_header_dumping()
        if self._captured_packets_iterator is None:
            self._captured_packets_iterator = iter(self._packet_capture.captured_packets)
        return next(self._captured_packets_iterator).dumps(self._is_native_order)


class PacketCaptureFormat(object):
    @classmethod
    def from_network_capture(cls, network_capture):
        file_header = PacketCaptureHeaderFormat.from_network_capture(network_capture)
        formatted_captured_packets = [CapturedPacketFormat.from_captured_packet(p) for p in network_capture]
        return PacketCaptureFormat(file_header, formatted_captured_packets)

    @classmethod
    def loads(cls, stream):
        loader = PacketCaptureFormatLoader(stream)
        return cls(loader.file_header, list(loader))

    def __init__(self, file_header, formatted_captured_packets=None):
        self.file_header = file_header
        self.captured_packets = formatted_captured_packets if formatted_captured_packets is not None else []

    def to_network_capture(self):
        return NetworkCapture([p.to_captured_packet() for p in self.captured_packets], self.file_header.link_layer_type)

    def dumps(self, is_native_order=True):
        dumper = PacketCaptureFormatDumper(self, is_native_order)
        return dumper.file_header + b''.join(list(dumper))
