__author__ = 'code-museum'


def format_byte(byte):
    return "{:02x}".format(ord(bytes(byte[:1])))


def format_dword(dword):
    return ' '.join(format_byte(byte) for byte in bytes(dword)[0:8])


def format_bytes(data):
    data = bytes(data)
    max_digits_for_index = len(str(len(data)))
    indexes_format = "{:" + str(max_digits_for_index) + "}: "

    lines = []
    for i in range(len(data) / 16 + 1):
        first_dword = data[i * 16: i * 16 + 8]
        last_dword = data[i * 16 + 8: i * 16 + 16]

        line = ''
        line += indexes_format.format(i * 16) + format_dword(first_dword)
        line += '  ' + indexes_format.format(i * 16 + 8) + format_dword(last_dword) if last_dword else ''
        lines.append(line)

    return '\n'.join(lines)
