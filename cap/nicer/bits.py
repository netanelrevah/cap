from cap.nicer.slices import slice_by_size

__author__ = 'code-museum'


def format_byte(byte):
    return byte[:1].encode('hex')


def format_dword(dword):
    return ' '.join(slice_by_size(dword.encode('hex'), 2))


def format_bytes(data):
    data = bytes(data)
    max_digits_for_index = len(str(len(data)))
    indexes_format = "{:" + str(max_digits_for_index) + "}: "

    dwords = []
    for i in range(0, len(data), 8):
        dword = data[i: i + 8]
        dwords.append(indexes_format.format(i) + format_dword(dword))

    lines = []
    for i in range(0, len(dwords), 2):
        line = dwords[i]
        line += ' ' + dwords[i + 1] if i + 1 < len(dwords) else ''
        lines.append(line)

    return '\n'.join(lines)
