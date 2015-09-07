from cap.logics import NetworkCapture
from cap.fmt import PacketCaptureFormat
from cap.nicer.streams import to_stream

__author__ = 'netanelrevah'


def load(path):
    return loads(open(path, 'rb'))


def loads(stream):
    return PacketCaptureFormat.loads(to_stream(stream)).to_network_capture()


def dump(network_capture, path):
    open(path, 'wb').write(dumps(network_capture))


def dumps(network_capture, is_native_order=True):
    return PacketCaptureFormat.from_network_capture(network_capture).dumps(is_native_order)


def merge(target_path, *source_paths):
    result = NetworkCapture()
    for source_path in source_paths:
        result.append(load(source_path))
    return dump(result, target_path)
