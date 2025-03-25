BLOCK_BASE = 0xC0000
ENTRY_SIZE = 8
TABLE_OFFSET = 0x2C040
BLOCK_SIZE = 64 * 1024
NUM_BLOCKS = 16

import struct

def load_bin_file(path):
    with open(path, "rb") as f:
        data = f.read()
    size = len(data)
    if size == 1048576:
        ecu_type = "T8"
    elif size == 524288:
        ecu_type = "T7"
    else:
        ecu_type = "Unknown"
    return data, ecu_type

def parse_block_table(data):
    blocks = []
    for i in range(NUM_BLOCKS):
        entry = data[TABLE_OFFSET + i * ENTRY_SIZE:TABLE_OFFSET + (i + 1) * ENTRY_SIZE]
        if len(entry) < 8:
            continue
        ptr, meta = struct.unpack("<II", entry)
        block_id = (meta >> 8) & 0xFF
        file_offset = BLOCK_BASE + (block_id - 0x0C) * BLOCK_SIZE
        block_data = data[file_offset:file_offset + BLOCK_SIZE]
        blocks.append((block_id, file_offset, block_data))
    return blocks

def extract_block(data, block_id):
    file_offset = BLOCK_BASE + (block_id - 0x0C) * BLOCK_SIZE
    return data[file_offset:file_offset + BLOCK_SIZE]

def inject_block(data, block_id, new_block):
    file_offset = BLOCK_BASE + (block_id - 0x0C) * BLOCK_SIZE
    patched = bytearray(data)
    patched[file_offset:file_offset + BLOCK_SIZE] = new_block
    return bytes(patched)
