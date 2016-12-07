from io import BytesIO

from .core import PcapNetworkCapture
from ._nicer.streams import to_stream

__author__ = 'netanelrevah'


def load(path):
    return load_from_file(path)


def load_from_file(path):
    return PcapNetworkCapture.load_from_stream(open(path, 'rb'))


def load_from_stream(stream):
    return PcapNetworkCapture.load_from_stream(stream)


def loads(stream):
    return PcapNetworkCapture.load_from_stream(to_stream(stream))


def dump_into_file(network_capture, path):
    network_capture.dump_to_stream(open(path, 'wb'))


def dump_into_bytes(network_capture):
    stream = BytesIO()
    network_capture.dump_to_stream(stream)
    stream.seek(0)
    return stream.read()


def dump(network_capture, path):
    return dump_into_file(network_capture, path)


def dumps(network_capture):
    dump_into_bytes(network_capture)


def merge(target_path, *source_paths):
    result = PcapNetworkCapture()
    for source_path in source_paths:
        result.append(load(source_path))
    return dump_into_file(result, target_path)
