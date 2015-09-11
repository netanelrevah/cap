from random import randint
from _pytest.python import raises
import mock
import struct

from cap.formats import PacketCaptureHeaderFormat

__author__ = 'netanelrevah'


def test_init_with_defaults():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    assert packet_capture_header_format.major_version == 2
    assert packet_capture_header_format.minor_version == 4
    assert packet_capture_header_format.time_zone_hours == 0
    assert packet_capture_header_format.max_capture_length_octets == 0x40000
    assert packet_capture_header_format.link_layer_type == 1


def test_init_with_randoms():
    major_version = randint(0, 100)
    minor_version = randint(0, 100)
    time_zone_hours = randint(0, 100)
    max_capture_length_octets = randint(0, 100)
    link_layer_type = randint(0, 100)
    packet_capture_header_format = PacketCaptureHeaderFormat(major_version, minor_version, time_zone_hours,
                                                             max_capture_length_octets, link_layer_type)
    assert packet_capture_header_format.major_version == major_version
    assert packet_capture_header_format.minor_version == minor_version
    assert packet_capture_header_format.time_zone_hours == time_zone_hours
    assert packet_capture_header_format.max_capture_length_octets == max_capture_length_octets
    assert packet_capture_header_format.link_layer_type == link_layer_type


def test_eq():
    major_version = randint(100, 200)
    minor_version = randint(100, 200)
    time_zone_hours = randint(100, 200)
    max_capture_length_octets = randint(100, 200)
    link_layer_type = randint(100, 200)
    packet_capture_header_format = PacketCaptureHeaderFormat(major_version, minor_version, time_zone_hours,
                                                             max_capture_length_octets, link_layer_type)
    packet_capture_header_format2 = PacketCaptureHeaderFormat()
    assert packet_capture_header_format != packet_capture_header_format2
    packet_capture_header_format2.major_version = major_version
    assert packet_capture_header_format != packet_capture_header_format2
    packet_capture_header_format2.minor_version = minor_version
    assert packet_capture_header_format != packet_capture_header_format2
    packet_capture_header_format2.time_zone_hours = time_zone_hours
    assert packet_capture_header_format != packet_capture_header_format2
    packet_capture_header_format2.max_capture_length_octets = max_capture_length_octets
    assert packet_capture_header_format != packet_capture_header_format2
    packet_capture_header_format2.link_layer_type = link_layer_type
    assert packet_capture_header_format == packet_capture_header_format2


def test_loads():
    major_version = randint(0x0, 0xFFFF)
    minor_version = randint(0x0, 0xFFFF)
    time_zone_hours = randint(-0x7FFFFFFF, 0x7FFFFFFF)
    max_capture_length_octets = randint(0x0, 0xFFFFFFFF)
    link_layer_type = randint(0x0, 0xFFFFFFFF)
    packet_capture_header_format = PacketCaptureHeaderFormat(major_version, minor_version, time_zone_hours,
                                                             max_capture_length_octets, link_layer_type)

    stream = mock.Mock()
    stream.read.return_value = packet_capture_header_format.pack()
    loaded_packet_capture_header_format = PacketCaptureHeaderFormat.loads(stream)
    assert loaded_packet_capture_header_format.major_version == major_version
    assert loaded_packet_capture_header_format.minor_version == minor_version
    assert loaded_packet_capture_header_format.time_zone_hours == time_zone_hours
    assert loaded_packet_capture_header_format.max_capture_length_octets == max_capture_length_octets
    assert loaded_packet_capture_header_format.link_layer_type == link_layer_type


def test_loads_with_none_value():
    stream = mock.Mock()
    stream.read.return_value = None
    with raises(struct.error):
        PacketCaptureHeaderFormat.loads(stream)


def test_loads_with_empty_value():
    stream = mock.Mock()
    stream.read.return_value = b''
    with raises(struct.error):
        PacketCaptureHeaderFormat.loads(stream)


def test_loads_with_insufficient_length():
    stream = mock.Mock()
    stream.read.return_value = b'AB'
    with raises(struct.error):
        PacketCaptureHeaderFormat.loads(stream)
