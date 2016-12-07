from collections import namedtuple
from enum import Enum
from struct import Struct

from nicer.eqs import ComparableMixin
from nicer.times import Timestamp
from pkt.captures import CaptureEnvironment, NetworkCapture, CapturedPacket

__author__ = 'netanelrevah'


class LinkLayerTypes(Enum):
    none, ethernet = tuple(range(0, 2))


class PcapMagic(object):
    VALUES_TO_BYTES = {('big_endian', 'microseconds'): b'\xd4\xc3\xb2\xa1',
                       ('big_endian', 'nanoseconds'): b'\xd4\x3c\xb2\xa1',
                       ('little_endian', 'microseconds'): b'\xa1\xb2\xc3\xd4',
                       ('little_endian', 'nanoseconds'): b'\xa1\xb2\x3c\xd4'}
    BYTES_TO_VALUES = {b'\xd4\xc3\xb2\xa1': ('big_endian', 'microseconds'),
                       b'\xd4\x3c\xb2\xa1': ('big_endian', 'nanoseconds'),
                       b'\xa1\xb2\xc3\xd4': ('little_endian', 'microseconds'),
                       b'\xa1\xb2\x3c\xd4': ('little_endian', 'nanoseconds')}

    def __init__(self, endianness, seconds_parts):
        self.endianness = endianness
        self.seconds_parts = seconds_parts

    def __hash__(self):
        return hash((self.endianness, self.seconds_parts))

    def to_bytes(self):
        return self.VALUES_TO_BYTES[(self.endianness, self.seconds_parts)]

    @classmethod
    def from_bytes(cls, b):
        return PcapMagic(*cls.BYTES_TO_VALUES[b])


class PcapEnvironment(CaptureEnvironment):
    def __init__(self, endianness='little_endian', seconds_parts='microseconds', major_version=2, minor_version=4,
                 time_zone_offset_hours=0, max_capture_length_octets=0x40000, link_layer_type=1):
        self.endianness = endianness
        self.seconds_parts = seconds_parts
        self.major_version = major_version
        self.minor_version = minor_version
        self.time_zone_offset_hours = time_zone_offset_hours
        self.max_capture_length_octets = max_capture_length_octets
        self.link_layer_type = link_layer_type


class PcapNetworkCapture(NetworkCapture):
    NETWORK_CAPTURE_HEADER_STRUCTURE = {'big_endian': Struct('>HHiIII'), 'little_endian': Struct('<HHiIII')}
    CAPTURED_PACKET_HEADER_STRUCTURE = {'big_endian': Struct('>IIII'), 'little_endian': Struct('<IIII')}

    def dump_to_stream(self, stream):
        network_capture_header_structure = self.NETWORK_CAPTURE_HEADER_STRUCTURE[self.environment.endianness]
        stream.write(PcapMagic(self.environment.endianness, self.environment.seconds_parts).to_bytes())
        stream.write(network_capture_header_structure.pack(
            self.environment.major_version, self.environment.minor_version,
            self.environment.time_zone_offset_hours, 0, self.environment.max_capture_length_octets,
            self.environment.link_layer_type))

        captured_packet_header_structure = self.CAPTURED_PACKET_HEADER_STRUCTURE[self.environment.endianness]
        for captured_packet in self.captured_packets:
            stream.write(captured_packet_header_structure.pack(
                captured_packet.capture_time.seconds, captured_packet.capture_time.second_parts,
                len(captured_packet), captured_packet.original_length))
            stream.write(captured_packet.data)

    @classmethod
    def load_from_stream(cls, stream):
        magic = PcapMagic.from_bytes(stream.read(4))
        header_values = cls.NETWORK_CAPTURE_HEADER_STRUCTURE[magic.endianness].unpack(stream.read(20))
        (major_version, minor_version, time_zone_offset_hours, _, max_capture_length_octets,
         link_layer_type) = header_values
        pcap_environment = PcapEnvironment(magic.endianness, magic.seconds_parts, major_version, minor_version,
                                           time_zone_offset_hours, max_capture_length_octets, link_layer_type)

        captured_packets = []
        captured_packet_header_structure = cls.CAPTURED_PACKET_HEADER_STRUCTURE[magic.endianness]
        while True:
            packet_header_bytes = stream.read(16)
            if not packet_header_bytes:
                break
            packet_header_values = captured_packet_header_structure.unpack(packet_header_bytes)
            seconds, seconds_parts, data_length, original_length = packet_header_values
            captured_packets.append(
                CapturedPacket(stream.read(data_length), Timestamp(seconds, seconds_parts), original_length))
        return PcapNetworkCapture(captured_packets, pcap_environment)
