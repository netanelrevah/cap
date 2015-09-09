from cap.formats import PacketCaptureHeaderFormat

__author__ = 'netanelrevah'

from io import BytesIO
import struct
import datetime
import random

from _pytest.python import fixture, raises

from cap.nicer.times import datetime_from_timestamp, seconds_from_datetime, microseconds_from_datetime
import cap

MAGIC_WITH_NATIVE_ORDERING = b'\xa1\xb2\xc3\xd4'
MAGIC_WITH_SWAPPED_ORDERING = b'\xd4\xc3\xb2\xa1'

CAP_HEADER = b"\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01"
CAP_HEADER_WITH_SWAPPED_ORDER = b"\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01" \
                                b"\x00\x00\x00"

CAP_HEADER_WITH_PACKET = b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00' \
                         b'\x00U\x0f#D\x00\x0b\xe2\xf8\x00\x00\x00\t\x00\x00\x00\t123456789'

CAP_HEADER_WITH_PACKET_AND_SWAPPED_ORDER = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                                           b'\x04\x00\x00\x00\x00\x00D#\x0fU\xf8\xe2\x0b\x00\t\x00\x00\x00\t\x00\x00' \
                                           b'\x00123456789'


def create_random_byte_array(minimum, maximum):
    return b''.join([bytes(random.randint(0, 255)) for _ in range(0, random.randint(minimum, maximum))])


def test_loads_empty_file():
    with raises(Exception) as e:
        cap.loads(b"")


def test_loads_too_short_data():
    random_string = create_random_byte_array(0, 23)
    with raises(Exception) as e:
        cap.loads(random_string)


def test_loads_cap_with_wrong_magic():
    random_string = b"\xFF" + create_random_byte_array(23, 23)
    with raises(Exception) as e:
        cap.loads(random_string)


def test_loads_empty_cap():
    c = cap.loads(CAP_HEADER)
    assert c.link_layer_type == cap.LinkLayerTypes.ethernet
    assert len(c) == 0
    pass


def test_loads_empty_cap_with_big_endian():
    c = cap.loads(CAP_HEADER_WITH_SWAPPED_ORDER)
    assert c.link_layer_type == cap.LinkLayerTypes.ethernet
    assert len(c) == 0
    pass


def test_loads_cap_with_packet():
    c = cap.loads(CAP_HEADER_WITH_PACKET)
    p = c.captured_packets[0]
    assert p.data == b'123456789'
    assert len(p) == 9
    assert p.capture_time == datetime_from_timestamp(1427055428.779000)
    assert p.original_length == 9


def test_loads_cap_with_packet_and_swapped_order():
    c = cap.loads(CAP_HEADER_WITH_PACKET_AND_SWAPPED_ORDER)
    p = c.captured_packets[0]
    assert p.data == b'123456789'
    assert len(p) == 9
    assert p.capture_time == datetime_from_timestamp(1427055428.779000)
    assert p.original_length == 9


def test_dumps_empty_capture_file():
    c = cap.NetworkCapture([], 1)
    assert CAP_HEADER == cap.dumps(c)


def test_dumps_empty_capture_file_with_swapped_order():
    c = cap.NetworkCapture([], 1)
    assert CAP_HEADER_WITH_SWAPPED_ORDER == cap.dumps(c, is_native_order=False)


def test_sorting_cap_packets(random_cap):
    random_cap.sort()
    for i in range(len(random_cap) - 1):
        assert random_cap[i].capture_time < random_cap[i + 1].capture_time
    pass


def test_sorting_cap_packets_with_sorted(random_cap):
    sorted_random_cap = sorted(random_cap)
    for i in range(len(sorted_random_cap) - 1):
        assert sorted_random_cap[i].capture_time < sorted_random_cap[i + 1].capture_time
    pass


def test_add_two_random_cap():
    c1, c2 = random_cap(), random_cap()
    c3 = c1 + c2
    assert c3.captured_packets == c1.captured_packets + c2.captured_packets


@fixture()
def random_cap():
    c = cap.NetworkCapture([], 1)
    for i in range(random.randint(1, 50)):
        c.append(cap.CapturedPacket(create_random_byte_array(100, 1500), i))
    return c


def test_dumps_capture_with_some_packets(random_cap):
    io = BytesIO(cap.dumps(random_cap))
    assert io.read(24) == CAP_HEADER
    index = 0
    while True:
        h = io.read(16)
        if h == b'':
            break
        assert h == struct.pack('>IIII',
                                seconds_from_datetime(random_cap[index].capture_time),
                                microseconds_from_datetime(random_cap[index].capture_time),
                                len(random_cap[index]), random_cap[index].original_length)
        assert io.read(len(random_cap[index])) == random_cap[index].data
        index += 1
    assert index == len(random_cap)
