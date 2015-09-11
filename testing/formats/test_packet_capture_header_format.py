from random import randint

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
#
#
# def test_capture_time_property_for_epoch():
#     captured_packet_header_format = CapturedPacketHeaderFormat()
#     assert captured_packet_header_format.capture_time == datetime(1970, 1, 1, tzinfo=pytz.UTC)
#
#
# def test_capture_time_property_for_now():
#     now = current_datetime()
#     captured_packet_header_format = CapturedPacketHeaderFormat(seconds_from_datetime(now), now.microsecond)
#     assert captured_packet_header_format.capture_time == now
#
#
# def test_init_from_captured_packet():
#     now = datetime.now(tz=pytz.UTC)
#     original_length = len(MOCKED_DATA) + randint(0, 100)
#     captured_packet = CapturedPacket(MOCKED_DATA, now, original_length)
#     captured_packet_header_format = CapturedPacketHeaderFormat.init_from_captured_packet(captured_packet)
#     assert captured_packet_header_format.seconds == seconds_from_datetime(now)
#     assert captured_packet_header_format.microseconds == now.microsecond
#     assert captured_packet_header_format.data_length == len(MOCKED_DATA)
#     assert captured_packet_header_format.original_length == original_length
#
#
# def test_loads():
#     seconds = randint(0x00, 0xFFFFFFFF)
#     microseconds = randint(0x00, 0xFFFFFFFF)
#     data_length = randint(0x00, 0xFFFFFFFF)
#     original_length = randint(0x00, 0xFFFFFFFF)
#     captured_packet_header_format = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)
#
#     stream = mock.Mock()
#     stream.read.return_value = captured_packet_header_format.pack()
#     loaded_captured_packet_header_format = CapturedPacketHeaderFormat.loads(stream)
#     assert loaded_captured_packet_header_format.seconds == seconds
#     assert loaded_captured_packet_header_format.microseconds == microseconds
#     assert loaded_captured_packet_header_format.data_length == data_length
#     assert loaded_captured_packet_header_format.original_length == original_length
#
#
# def test_loads_with_none_value():
#     stream = mock.Mock()
#     stream.read.return_value = None
#     assert CapturedPacketHeaderFormat.loads(stream) is None
#
#
# def test_loads_with_empty_value():
#     stream = mock.Mock()
#     stream.read.return_value = b''
#     assert CapturedPacketHeaderFormat.loads(stream) is None
#
#
# def test_loads_with_insufficient_length():
#     stream = mock.Mock()
#     stream.read.return_value = b'AB'
#     with raises(struct.error):
#         CapturedPacketHeaderFormat.loads(stream)
#
