from StringIO import StringIO
import struct
import _pytest.python
import datetime
import capture
import random

__author__ = 'netanelrevah'

MAGIC_WITH_NATIVE_ORDERING = '\xa1\xb2\xc3\xd4'
MAGIC_WITH_SWAPPED_ORDERING = '\xd4\xc3\xb2\xa1'

CAP_HEADER = "\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01"
CAP_HEADER_WITH_SWAPPED_ORDER = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01" \
                                "\x00\x00\x00"


def create_random_byte_array(min, max):
    return ''.join([chr(random.randint(0, 255)) for i in xrange(0, random.randint(min, max))])


def test_loads_empty_file():
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads("")
    assert e.value.data == ""


def test_loads_too_short_data():
    import random

    random_string = create_random_byte_array(0, 23)
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads(random_string)
    assert e.value.data == random_string


def test_loads_cap_with_wrong_magic():
    import random

    random_string = "\xFF" + create_random_byte_array(23, 23)
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads(random_string)
    assert e.value.data == random_string


def test_loads_empty_cap():
    cap = capture.loads(CAP_HEADER)
    assert cap.swapped_order is False
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 131072
    assert len(cap) == 0
    pass


def test_loads_empty_cap_with_big_endian():
    cap = capture.loads(CAP_HEADER_WITH_SWAPPED_ORDER)
    assert cap.swapped_order is True
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 131072
    assert len(cap) == 0
    pass


def test_create_new_capture_file():
    cap = capture.NetworkCapture(swapped_order=True, version=(6, 7),
                                 link_layer_type=capture.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=123456)
    assert cap.swapped_order is True
    assert cap.version == (6, 7)
    assert cap.link_layer_type == capture.LinkLayerTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 123456
    assert len(cap) == 0


def test_dumps_empty_capture_file():
    cap = capture.NetworkCapture(swapped_order=False, version=(2, 4),
                                 link_layer_type=capture.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER == capture.dumps(cap)


def test_dumps_empty_capture_file_with_swapped_order():
    cap = capture.NetworkCapture(swapped_order=True, version=(2, 4),
                                 link_layer_type=capture.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER_WITH_SWAPPED_ORDER == capture.dumps(cap)


def test_dumps_capture_with_some_packets():
    import random
    cap = capture.NetworkCapture(swapped_order=False, version=(2, 4),
                                 link_layer_type=capture.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    for i in xrange(random.randint(1, 15)):
        cap.append(capture.CapturedPacket(create_random_byte_array(100, 1500), i))

    io = StringIO(capture.dumps(cap))
    assert io.read(24) == CAP_HEADER
    index = 0
    while True:
        h = io.read(16)
        if h == '':
            break
        assert h == struct.pack('>IIII', cap[index].seconds, cap[index].micro_seconds, len(cap[index]),
                                cap[index].original_length)
        assert io.read(len(cap[index])) == cap[index].data
        index += 1
    assert index == len(cap)

