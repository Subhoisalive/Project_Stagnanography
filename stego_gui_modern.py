import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
import os
import struct
import hashlib

# ---- Steganography core ----
MAGIC = b"STEG1"
HEADER_FMT = ">5sI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def build_payload(secret: bytes) -> bytes:
    h = sha256(secret)
    header = struct.pack(HEADER_FMT, MAGIC, len(secret))
    return header + h + secret

def parse_payload(blob: bytes) -> bytes:
    if len(blob) < HEADER_SIZE + 32:
        raise ValueError("Payload too small")
    magic, length = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError("No payload found")
    digest = blob[HEADER_SIZE:HEADER_SIZE + 32]
    content = blob[HEADER_SIZE + 32:HEADER_SIZE + 32 + length]
    if sha256(content) != digest:
        raise ValueError("Corrupted data or wrong extraction")
    return content

def bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return ((arr[:, None] >> np.arange(7, -1, -1)) & 1).astype(np.uint8).flatten()

def bits_to_bytes(bits: np.ndarray) -> bytes:
    if len(bits) % 8 != 0:
        bits = np.pad(bits, (0, 8 - len(bits) % 8))
    bits = bits.reshape((-1, 8))
    vals = (bits * (1 << np.arange(7, -1, -1))).sum(axis=1).astype(np.uint8)
    return vals.tobytes()

def image_embed(cover_path, secret_path, output_path):
    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img).flatten()

    with open(secret_path, "rb") as f:
        secret = f.read()

    payload = build_payload(secret)
    bits = bytes_to_bits(payload)

    if len(bits) > arr.size:
        raise ValueError("Secret too large for this image!")

    arr[:len(bits)] = (arr[:len(bits)] & 0xFE) | bits
    stego = arr.reshape(np.array(img).shape)
    out = Image.fromarray(stego, mode="RGB")
    out.save(output_path, "PNG")
    return len(secret)

def image_extract(stego_path, output_dir):
    img = Image.open(stego_path).convert("RGB")
    arr = np.array(img).flatten()
    bits = arr[:len(arr)] & 1
    blob = bits_to_bytes(bits)
    secret = parse_payload(blob)

    out_path = os.path.join(output_dir, "extracted_file")
    with open(out_path, "wb") as f:
        f.write(secret)
    return out_path, len(secret)


# ---- Modern GUI with Animated Background ----
class StegoGUI:
    def __init__(self, root):
        self.root = root
        root.title("🖼️ Modern Image Steganography")
        root.geometry("500x350")
        root.resizable(False, False)

        # Animated background canvas
        self.canvas = tk.Canvas(root, width=500, height=350, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)

        self.offset = 0
        self.animate_background()

        # Title
        self.title_label = tk.Label(
            root, text="Image Steganography Tool",
            font=("Algerian", 18, "bold"), fg="white", bg="#1e1e2f"
        )
        self.canvas.create_window(250, 50, window=self.title_label)

        # Buttons
        self.btn_hide = self.create_button("🔒 Hide File in Image", self.hide_file)
        self.canvas.create_window(250, 130, window=self.btn_hide)

        self.btn_reveal = self.create_button("🔓 Reveal File from Image", self.reveal_file)
        self.canvas.create_window(250, 200, window=self.btn_reveal)

        # Footer
        self.footer = tk.Label(
            root, text="Made with ❤️ in Python By Suvhankar Dutta",
            font=("Bookman Old Style", 10), fg="#ddd", bg="#1e1e2f"
        )
        self.canvas.create_window(250, 310, window=self.footer)

    def animate_background(self):
        """Moving gradient blue background"""
        self.canvas.delete("bg")
        for i in range(0, 350, 5):
            # Vary blue intensity with offset
            blue_val = (i + self.offset) % 255
            color = f"#0000{blue_val:02x}"
            self.canvas.create_rectangle(0, i, 500, i + 5, fill=color, width=0, tags="bg")

        self.offset = (self.offset + 5) % 255
        self.root.after(100, self.animate_background)

    def create_button(self, text, command):
        btn = tk.Button(
            self.root, text=text, command=command,
            font=("Times New Roman", 12, "bold"),
            fg="white", bg="#5a5af0",
            activebackground="#7a7af5", activeforeground="white",
            relief="flat", bd=0, padx=20, pady=10, cursor="hand2"
        )
        return btn

    def hide_file(self):
        cover = filedialog.askopenfilename(title="Select Cover Image", filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if not cover: return
        secret = filedialog.askopenfilename(title="Select File to Hide")
        if not secret: return
        save = filedialog.asksaveasfilename(title="Save Stego Image As", defaultextension=".png",
                                            filetypes=[("PNG Image", "*.png")])
        if not save: return
        try:
            size = image_embed(cover, secret, save)
            messagebox.showinfo("✅ Success", f"File hidden successfully! ({size} bytes)\nSaved as: {save}")
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def reveal_file(self):
        stego = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("Images", "*.png")])
        if not stego: return
        outdir = filedialog.askdirectory(title="Select Folder to Save Extracted File")
        if not outdir: return
        try:
            out_path, size = image_extract(stego, outdir)
            messagebox.showinfo("✅ Success", f"Extracted {size} bytes\nSaved as: {out_path}")
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = StegoGUI(root)
    root.mainloop()
