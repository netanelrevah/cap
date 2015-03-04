import _pytest.python
import datetime
import capture

__author__ = 'netanelrevah'

MAGIC_WITH_NATIVE_ORDERING = '\xa1\xb2\xc3\xd4'
MAGIC_WITH_SWAPPED_ORDERING = '\xd4\xc3\xb2\xa1'

CAP_HEADER = "\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01"
CAP_HEADER_WITH_SWAPPED_ORDER = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01" \
                                "\x00\x00\x00"


def test_loads_empty_file():
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads("")
    assert e.value.data == ""


def test_loads_too_short_data():
    import random
    random_string = ''.join([chr(random.randint(0, 255)) for i in xrange(0, random.randint(0, 23))])
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads(random_string)
    assert e.value.data == random_string


def test_loads_cap_with_wrong_magic():
    import random
    random_string = "\xFF" + ''.join([chr(random.randint(0, 255)) for i in xrange(23)])
    with _pytest.python.raises(capture.InvalidCapException) as e:
        capture.loads(random_string)
    assert e.value.data == random_string


def test_loads_empty_cap():
    cap = capture.loads(CAP_HEADER)
    assert cap.swapped_order is False
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerHeaderTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 131072
    assert len(cap) == 0
    pass


def test_loads_empty_cap_with_big_endian():
    cap = capture.loads(CAP_HEADER_WITH_SWAPPED_ORDER)
    assert cap.swapped_order is True
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerHeaderTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 131072
    assert len(cap) == 0
    pass


def test_create_new_capture_file():
    cap = capture.CaptureFile(swapped_order=True, version=(6, 7),
                              link_layer_type=capture.LinkLayerHeaderTypes.ethernet,
                              time_zone=datetime.timedelta(hours=0), max_capture_length=123456)
    assert cap.swapped_order is True
    assert cap.version == (6, 7)
    assert cap.link_layer_type == capture.LinkLayerHeaderTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 123456
    assert len(cap) == 0


def test_dumps_empty_capture_file():
    cap = capture.CaptureFile(swapped_order=False, version=(2, 4),
                              link_layer_type=capture.LinkLayerHeaderTypes.ethernet,
                              time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER == capture.dumps(cap)


def test_dumps_empty_capture_file_with_swapped_order():
    cap = capture.CaptureFile(swapped_order=True, version=(2, 4),
                              link_layer_type=capture.LinkLayerHeaderTypes.ethernet,
                              time_zone=datetime.timedelta(hours=0), max_capture_length=131072)
    assert CAP_HEADER_WITH_SWAPPED_ORDER == capture.dumps(cap)