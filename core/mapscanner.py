import struct

def scan_maps(data, comp_data=None):
    results = []
    for offset in range(0, len(data) - 256, 2):
        try:
            values = struct.unpack("<64H", data[offset:offset+128])
            if len(set(values)) > 10:
                changed = comp_data and values != struct.unpack("<64H", comp_data[offset:offset+128])
                results.append((offset, "int16 8x8", changed))
        except:
            pass
        try:
            values = struct.unpack("<64f", data[offset:offset+256])
            if len(set([round(x, 2) for x in values])) > 10:
                changed = comp_data and values != struct.unpack("<64f", comp_data[offset:offset+256])
                results.append((offset, "float32 8x8", changed))
        except:
            pass
    return results

def find_maps_in_block(block_data, comp_data=None, offset_base=0):
    results = []

    for i in range(0, len(block_data) - 256, 4):
        try:
            chunk = block_data[i:i + 128]
            int_data = struct.unpack("<64H", chunk)
            changed = False
            if comp_data:
                comp_chunk = comp_data[offset_base + i:offset_base + i + 128]
                comp_data_block = struct.unpack("<64H", comp_chunk)
                changed = int_data != comp_data_block
            if len(set(int_data)) > 10:
                results.append((offset_base + i, "int16 8x8", changed))
        except:
            pass

        try:
            chunk = block_data[i:i + 256]
            float_data = struct.unpack("<64f", chunk)
            changed = False
            if comp_data:
                comp_chunk = comp_data[offset_base + i:offset_base + i + 256]
                comp_data_block = struct.unpack("<64f", comp_chunk)
                changed = float_data != comp_data_block
            if len(set([round(f, 2) for f in float_data])) > 10:
                results.append((offset_base + i, "float32 8x8", changed))
        except:
            pass

    return results
