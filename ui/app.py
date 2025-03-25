import tkinter as tk
import numpy as np
import sys
import os
import struct
from tkinter import filedialog, messagebox, ttk

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.binloader import load_bin_file, parse_block_table, extract_block, inject_block
from core.mapscanner import scan_maps, find_maps_in_block
from core.comparator import hex_diff, export_diff_lines, export_changed_maps
from utils.visualizer import plot_map_3d
from utils.checksum import compute_checksum

BLOCK_BASE = 0xC0000
BLOCK_SIZE = 64 * 1024

class T8BinTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Trionic Calibration Tool")
        self.geometry("1000x700")
        self.configure(bg="#1e1e1e")
        self.filename = None
        self.data = None
        self.comp_data = None
        self.ecu_type = "Unknown"
        self.block_infos = []

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Treeview", background="#2e2e2e", foreground="#ffffff", fieldbackground="#2e2e2e")
        style.map("Treeview", background=[("selected", "#0078D7")])

        self.tab_control = ttk.Notebook(self)
        self.main_tab = ttk.Frame(self.tab_control)
        self.map_tab = ttk.Frame(self.tab_control)
        self.diff_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.main_tab, text="Main")
        self.tab_control.add(self.map_tab, text="Map Discovery")
        self.tab_control.add(self.diff_tab, text="Block Diff")
        self.tab_control.pack(expand=True, fill=tk.BOTH)

        self.build_main_tab()
        self.build_map_tab()
        self.build_diff_tab()

    def build_main_tab(self):
        ttk.Button(self.main_tab, text="Load BIN", command=self.load_bin).pack(pady=10)
        self.tree = ttk.Treeview(self.main_tab, columns=("ID", "Offset", "Valid", "Checksum"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        button_frame = ttk.Frame(self.main_tab)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Extract Block", command=self.extract_block_ui).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Inject Block", command=self.inject_block_ui).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Visualize Block", command=self.visualize_block).pack(side=tk.LEFT, padx=10)
        self.status = ttk.Label(self.main_tab, text="")
        self.status.pack(pady=5)

    def build_map_tab(self):
        self.map_list = tk.Listbox(self.map_tab)
        self.map_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.map_list.bind("<Double-Button-1>", self.view_selected_map)
        ttk.Button(self.map_tab, text="Export Changed Maps", command=self.export_changed_maps).pack(side=tk.BOTTOM, pady=5)
        ttk.Button(self.map_tab, text="Load Comparison BIN", command=self.load_comparison_bin).pack(side=tk.RIGHT, padx=10)
        ttk.Button(self.map_tab, text="Scan All Maps", command=self.scan_all_maps).pack(side=tk.RIGHT, padx=10)

    def build_diff_tab(self):
        ttk.Label(self.diff_tab, text="HEX Diff Viewer").pack(pady=10)
        ttk.Button(self.diff_tab, text="Show HEX Diff", command=self.hex_diff_viewer).pack(pady=10)

    def load_bin(self):
        path = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
        if not path:
            return
        self.data, self.ecu_type = load_bin_file(path)
        self.block_infos = parse_block_table(self.data)
        self.tree.delete(*self.tree.get_children())
        for block_id, offset, block_data in self.block_infos:
            checksum = compute_checksum(block_data)
            valid = any(b != 0xFF for b in block_data[:16])
            self.tree.insert("", "end", values=(f"0x{block_id:02X}", f"0x{offset:06X}", str(valid), f"0x{checksum:04X}"))
        self.status.config(text=f"Loaded: {path} | Detected ECU: {self.ecu_type}")

    def extract_block_ui(self):
        selected = self.tree.selection()
        if not selected: return
        block_id = int(self.tree.item(selected[0])['values'][0], 16)
        data = extract_block(self.data, block_id)
        save_path = filedialog.asksaveasfilename(defaultextension=".bin")
        if save_path: open(save_path, "wb").write(data)

    def inject_block_ui(self):
        selected = self.tree.selection()
        if not selected: return
        block_id = int(self.tree.item(selected[0])['values'][0], 16)
        patch_path = filedialog.askopenfilename()
        if patch_path:
            new_block = open(patch_path, "rb").read()
            self.data = inject_block(self.data, block_id, new_block)
            messagebox.showinfo("Injected", f"Block 0x{block_id:02X} updated.")

    def visualize_block(self):
        selected = self.tree.selection()
        if not selected:
            return
        block_id = int(self.tree.item(selected[0])['values'][0], 16)
        data = extract_block(self.data, block_id)
        try:
            values = [
                struct.unpack("<H", data[i:i+2])[0]
                for i in range(0, len(data), 2)
                if data[i:i+2] != b'\xFF\xFF'
            ]
            size = int(len(values) ** 0.5)
            if size >= 4:
                array = np.array(values[:size * size]).reshape((size, size))
                plot_map_3d(array, title=f"Block 0x{block_id:02X}")
        except Exception as e:
            messagebox.showerror("Plot Error", str(e))

    def scan_all_maps(self):
        self.map_list.delete(0, tk.END)
        if not self.block_infos:
            messagebox.showwarning("No blocks", "Load a BIN file first.")
            return
        for block_id, offset, block_data in self.block_infos:
            if all(b == 0xFF for b in block_data[:64]):
                continue
            results = find_maps_in_block(block_data, self.comp_data, offset)
            for map_offset, fmt, changed in results:
                tag = "🔴" if changed else "🟢"
                self.map_list.insert(tk.END, f"{tag} Block 0x{block_id:02X} @ 0x{map_offset:06X} [{fmt}]")

    def view_selected_map(self, event):
        idx = self.map_list.curselection()
        if not idx: return
        entry = self.map_list.get(idx[0])
        offset = int(entry.split("@")[1].split()[0], 16)
        fmt = entry.split("[")[1].replace("]", "")
        size = 128 if "int16" in fmt else 256
        unpack = "<64H" if "int16" in fmt else "<64f"
        try:
            raw = self.data[offset:offset+size]
            values = struct.unpack(unpack, raw)
            array = np.array(values).reshape((8, 8))
            plot_map_3d(array, title="Original", cmap="viridis")
            if self.comp_data:
                raw2 = self.comp_data[offset:offset+size]
                values2 = struct.unpack(unpack, raw2)
                array2 = np.array(values2).reshape((8, 8))
                plot_map_3d(array2, title="Modified", cmap="plasma")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_comparison_bin(self):
        path = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
        if path:
            with open(path, "rb") as f:
                self.comp_data = f.read()
            messagebox.showinfo("Loaded", "Comparison bin loaded.")

    def hex_diff_viewer(self):
        if not self.data or not self.comp_data:
            messagebox.showwarning("Missing", "Load both BIN files first.")
            return

        top = tk.Toplevel(self)
        top.title("HEX Diff")
        text = tk.Text(top, bg="#111", fg="#0f0", font=("Consolas", 10))
        text.pack(expand=True, fill=tk.BOTH)

        block_size = 16
        max_lines = 10000  # limit för prestanda, justera vid behov
        lines = []
        size = min(len(self.data), len(self.comp_data))

        for i in range(0, size, block_size):
            chunk_a = self.data[i:i+block_size]
            chunk_b = self.comp_data[i:i+block_size]
            if chunk_a != chunk_b:
                line = f"0x{i:06X}: " + " ".join(f"{b:02X}" for b in chunk_a) + "  →  " + " ".join(f"{b:02X}" for b in chunk_b)
                lines.append(line)
            if len(lines) >= max_lines:
                lines.append("... (truncated for performance)")
                break

        if not lines:
            messagebox.showinfo("Identical", "No differences found.")
            top.destroy()
            return

        text.insert("1.0", "\n".join(lines))
        ttk.Button(top, text="Export", command=lambda: self.export_diff(lines)).pack()


    def export_diff(self, lines):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            export_diff_lines(lines, path)

    def export_changed_maps(self):
        if not self.comp_data:
            messagebox.showwarning("Missing", "Load comparison bin first.")
            return
        changes = export_changed_maps(self.data, self.comp_data)
        if not changes:
            messagebox.showinfo("No changes", "No modified maps found.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            export_diff_lines(changes, path)

if __name__ == '__main__':
    app = T8BinTool()
    app.mainloop()
