import datetime
import capture

__author__ = 'netanelrevah'

MAGIC_WITH_NATIVE_ORDERING = '\xa1\xb2\xc3\xd4'
MAGIC_WITH_SWAPPED_ORDERING = '\xd4\xc3\xb2\xa1'

CAP_HEADER = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"


def test_load_empty_cap():
    cap = capture.loads(CAP_HEADER)
    assert cap.swapped_order is True
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerHeaderTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 131072
    assert len(cap) == 0
    pass


def test_create_new_capture_file():
    cap = capture.CaptureFile(swapped_order=False, version=(2, 4),
                              link_layer_type=capture.LinkLayerHeaderTypes.ethernet,
                              time_zone=datetime.timedelta(hours=0), max_capture_length=123456)
    assert cap.swapped_order is True
    assert cap.version == (2, 4)
    assert cap.link_layer_type == capture.LinkLayerHeaderTypes.ethernet
    assert cap.time_zone == datetime.timedelta(hours=0)
    assert cap.max_capture_length == 123456
    assert len(cap) == 0