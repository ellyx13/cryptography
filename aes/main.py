import tkinter as tk
from tkinter import ttk, messagebox
from aes import encrypt, decrypt

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
        input_text = self.input_text.get("1.0", tk.END).strip()
        key_text = self.key_text.get("1.0", tk.END).strip()
        if not input_text or not key_text:
            messagebox.showerror("Lỗi", "Bạn phải nhập cả ô Input và ô Key!")
            return
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypt(input_text, key_text))

    def btn_decrypt(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        key_text = self.key_text.get("1.0", tk.END).strip()
        if not input_text or not key_text:
            messagebox.showerror("Lỗi", "Bạn phải nhập cả ô Input và ô Key!")
            return
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypt(input_text, key_text))

if __name__ == "__main__":
    root = tk.Tk()
    app = AESCipherApp(root)
    root.mainloop()