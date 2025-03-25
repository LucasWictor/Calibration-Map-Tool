def hex_diff(data1, data2):
    size = min(len(data1), len(data2))
    return [f"0x{i:06X}  |  0x{data1[i]:02X} → 0x{data2[i]:02X}" for i in range(size) if data1[i] != data2[i]]

def export_diff_lines(lines, path):
    with open(path, "w") as f:
        f.write("\n".join(lines))

def export_changed_maps(data1, data2):
    changes = []
    for offset in range(0, min(len(data1), len(data2)) - 256, 2):
        try:
            a = data1[offset:offset+128]
            b = data2[offset:offset+128]
            if a != b:
                changes.append(f"0x{offset:06X} [int16 8x8]")
        except:
            pass
        try:
            a = data1[offset:offset+256]
            b = data2[offset:offset+256]
            if a != b:
                changes.append(f"0x{offset:06X} [float32 8x8]")
        except:
            pass
    return changes
