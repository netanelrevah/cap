from io import BytesIO

__author__ = 'netanelrevah'


def to_stream(value):
    if isinstance(value, bytes):
        return BytesIO(value)
    return value
