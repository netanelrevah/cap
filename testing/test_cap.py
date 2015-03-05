from StringIO import StringIO
import struct
import _pytest.python
import datetime
import cap
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
    with _pytest.python.raises(cap.InvalidCapException) as e:
        cap.loads("")
    assert e.value.data == ""


def test_loads_too_short_data():
    import random

    random_string = create_random_byte_array(0, 23)
    with _pytest.python.raises(cap.InvalidCapException) as e:
        cap.loads(random_string)
    assert e.value.data == random_string


def test_loads_cap_with_wrong_magic():
    import random

    random_string = "\xFF" + create_random_byte_array(23, 23)
    with _pytest.python.raises(cap.InvalidCapException) as e:
        cap.loads(random_string)
    assert e.value.data == random_string


def test_loads_empty_cap():
    c = cap.loads(CAP_HEADER)
    assert c.swapped_order is False
    assert c.version == (2, 4)
    assert c.link_layer_type == cap.LinkLayerTypes.ethernet
    assert c.time_zone == datetime.timedelta(hours=0)
    assert c.max_capture_length == 131072
    assert len(c) == 0
    pass


def test_loads_empty_cap_with_big_endian():
    c = cap.loads(CAP_HEADER_WITH_SWAPPED_ORDER)
    assert c.swapped_order is True
    assert c.version == (2, 4)
    assert c.link_layer_type == cap.LinkLayerTypes.ethernet
    assert c.time_zone == datetime.timedelta(hours=0)
    assert c.max_capture_length == 131072
    assert len(c) == 0
    pass


def test_create_new_capture_file():
    c = cap.NetworkCapture(swapped_order=True, version=(6, 7),
                                 link_layer_type=cap.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=123456)
    assert c.swapped_order is True
    assert c.version == (6, 7)
    assert c.link_layer_type == cap.LinkLayerTypes.ethernet
    assert c.time_zone == datetime.timedelta(hours=0)
    assert c.max_capture_length == 123456
    assert len(c) == 0


def test_dumps_empty_capture_file():
    c = cap.NetworkCapture(swapped_order=False, version=(2, 4),
                                 link_layer_type=cap.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER == cap.dumps(c)


def test_dumps_empty_capture_file_with_swapped_order():
    c = cap.NetworkCapture(swapped_order=True, version=(2, 4),
                                 link_layer_type=cap.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER_WITH_SWAPPED_ORDER == cap.dumps(c)


def test_dumps_capture_with_some_packets():
    import random
    c = cap.NetworkCapture(swapped_order=False, version=(2, 4),
                                 link_layer_type=cap.LinkLayerTypes.ethernet,
                                 time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    for i in xrange(random.randint(1, 15)):
        c.append(cap.CapturedPacket(create_random_byte_array(100, 1500), i))

    io = StringIO(cap.dumps(c))
    assert io.read(24) == CAP_HEADER
    index = 0
    while True:
        h = io.read(16)
        if h == '':
            break
        assert h == struct.pack('>IIII', c[index].seconds, c[index].micro_seconds, len(c[index]),
                                c[index].original_length)
        assert io.read(len(c[index])) == c[index].data
        index += 1
    assert index == len(c)

