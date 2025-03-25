def compute_checksum(data):
    return sum(data) & 0xFFFF
