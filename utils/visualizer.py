import numpy as np
import matplotlib.pyplot as plt
from tkinter import messagebox
from tkinter import messagebox

def plot_map_3d(data_array, title="3D Plot", cmap='viridis'):
    try:
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')
        X, Y = np.meshgrid(np.arange(data_array.shape[0]), np.arange(data_array.shape[1]))
        ax.plot_surface(X, Y, data_array, cmap=cmap)
        ax.set_title(title)
        plt.tight_layout()
        plt.show()
    except Exception as e:
        messagebox.showerror("Plot Error", str(e))
