import tkinter as tk
from tkinter import ttk, messagebox
from aes_encrypt import aes_encrypt
from aes_decrypt import aes_decrypt

class AESCipherApp:
    def __init__(self, root):
        root.title("AES Cipher")
        root.geometry("400x450")
        root.resizable(False, False)

        self.input_label = ttk.Label(root, text="Input", font=("Arial", 15))
        self.input_label.pack(pady=(20, 5))
        self.input_text = tk.Text(root, height=4, width=40)
        self.input_text.pack(pady=5)

        self.key_label = ttk.Label(root, text="Key", font=("Arial", 15))
        self.key_label.pack(pady=(20, 5))
        self.key_text = tk.Text(root, height=2, width=40)
        self.key_text.pack(pady=5)
        
        self.output_label = ttk.Label(root, text="Output", font=("Arial", 15))
        self.output_label.pack(pady=(20, 5))
        self.output_text = tk.Text(root, height=4, width=40)
        self.output_text.pack(pady=5)

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=20)

        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt", bg="#4CAF50", fg="white", relief="flat", borderwidth=5, font=("Arial", 15), command=self.btn_encrypt)
        self.encrypt_button.grid(row=0, column=0, padx=20)

        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt", bg="#2196F3", fg="white", relief="flat", borderwidth=5, font=("Arial", 15), command=self.btn_decrypt)
        self.decrypt_button.grid(row=0, column=1, padx=10)

    def btn_encrypt(self):
        plaintext = self.input_text.get("1.0", tk.END).strip()
        key_text = self.key_text.get("1.0", tk.END).strip()
        if not plaintext or not key_text:
            messagebox.showerror("Lỗi", "Bạn phải nhập cả ô Input và ô Key!")
            return
        # Kiểm tra độ dài khóa, phải đủ 16 bytes cho AES-128
        if len(plaintext) != 16:
            messagebox.showerror("Lỗi", "Plain text phải có độ dài chính xác 16 ký tự (128-bit).")
            return
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, aes_encrypt(plaintext, key_text))

    def btn_decrypt(self):
        ciphertext = self.input_text.get("1.0", tk.END).strip()
        key_text = self.key_text.get("1.0", tk.END).strip()
        if not ciphertext or not key_text:
            messagebox.showerror("Lỗi", "Bạn phải nhập cả ô Input và ô Key!")
            return
        if len(ciphertext) != 32:
            messagebox.showerror("Lỗi", "Ciphertext phải có độ dài chính xác 32 ký tự (128-bit).")
            return
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, aes_decrypt(ciphertext, key_text))

if __name__ == "__main__":
    root = tk.Tk()
    app = AESCipherApp(root)
    root.mainloop()