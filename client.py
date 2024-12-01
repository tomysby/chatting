import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, Listbox, Toplevel, END
from utils import aes_encrypt, aes_decrypt, generate_rsa_keypair

private_key, public_key = generate_rsa_keypair()

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("🌐 Chat Client")
        self.master.geometry("500x600")
        self.master.configure(bg="#f5f5f5")

        # Frame untuk memasukkan nama dan password
        self.name_frame = tk.Frame(master, bg="#f5f5f5")
        self.name_frame.pack(pady=20)

        tk.Label(
            self.name_frame, text="Nama Anda:", font=("Arial", 12), bg="#f5f5f5"
        ).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.name_entry = tk.Entry(self.name_frame, font=("Arial", 12), width=25)
        self.name_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(
            self.name_frame, text="Password:", font=("Arial", 12), bg="#f5f5f5"
        ).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.password_entry = tk.Entry(
            self.name_frame, font=("Arial", 12), show="*", width=25
        )
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        self.connect_button = tk.Button(
            self.name_frame,
            text="🔑 Masuk",
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            command=self.connect,
        )
        self.connect_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Frame untuk area chat
        self.chat_frame = tk.Frame(master, bg="#f5f5f5")
        self.chat_area = scrolledtext.ScrolledText(
            self.chat_frame,
            wrap=tk.WORD,
            font=("Arial", 12),
            state="disabled",
            bg="#ffffff",
            fg="#333333",
            height=20,
        )
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Frame untuk input pesan dan tombol kirim
        self.input_frame = tk.Frame(self.chat_frame, bg="#f5f5f5")
        self.input_frame.pack(padx=10, pady=5, fill=tk.X)

        self.selected_user_button = tk.Button(
            self.input_frame,
            text="👤 Pilih Penerima",
            font=("Arial", 12),
            bg="#FFC107",
            fg="#333333",
            command=self.open_user_selection,
        )
        self.selected_user_button.pack(side=tk.LEFT, padx=5)

        self.entry_area = tk.Entry(
            self.input_frame, font=("Arial", 12), width=40, bg="#ffffff"
        )
        self.entry_area.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        self.entry_area.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            self.input_frame,
            text="📤 Kirim",
            font=("Arial", 12),
            bg="#007BFF",
            fg="white",
            command=self.send_message,
        )
        self.send_button.pack(side=tk.RIGHT, padx=5)

        self.client_socket = None
        self.client_name = None
        self.password = "shared_secret_key"

        # Daftar pengguna
        self.user_list = []
        self.selected_user = None

    def connect(self):
        self.client_name = self.name_entry.get()
        if not self.client_name or not self.password:
            messagebox.showwarning("Peringatan", "Nama atau Password tidak boleh kosong!")
            return

        # Simulasi login berhasil
        messagebox.showinfo("Info", f"Berhasil masuk sebagai {self.client_name}")
        self.name_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        # Mencoba untuk terhubung ke server
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect(('localhost', 5555))
            self.client_socket.send(self.client_name.encode('utf-8'))

            # Menyembunyikan frame nama dan menampilkan frame chat
            self.name_frame.pack_forget()
            self.chat_frame.pack(fill=tk.BOTH, expand=True)

            # Mengubah judul jendela untuk mencakup nama pengguna
            self.master.title(f"Chat Client ({self.client_name})")

            # Memulai thread untuk menerima pesan
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Gagal terhubung ke server: {e}")

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message.startswith("USER_LIST:"):
                    # Memperbarui daftar pengguna
                    user_list = message.split("USER_LIST:")[1]
                    self.user_list = user_list.split(', ')
                else:
                    sender, encrypted_message = message.split(':', 1)
                    decrypted_message = aes_decrypt(encrypted_message, self.password)
                    self.display_message(f"{sender}: {decrypted_message}")
            except:
                self.display_message("Connection closed")
                self.client_socket.close()
                break

    def open_user_selection(self):
        # Membuat pop-up untuk memilih pengguna
        user_selection_window = Toplevel(self.master)
        user_selection_window.title("👤 Pilih Penerima")
        user_selection_window.geometry("300x400")
        user_selection_window.configure(bg="#f5f5f5")

        tk.Label(
            user_selection_window,
            text="Daftar Pengguna:",
            font=("Arial", 12),
            bg="#f5f5f5",
        ).pack(pady=10)

        user_listbox = Listbox(
            user_selection_window, font=("Arial", 12), height=15, selectmode=tk.SINGLE
        )
        user_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Tambahkan pengguna ke Listbox, kecuali nama pengguna yang sedang login
        for user in self.user_list:
            if user != self.client_name: 
                user_listbox.insert(END, user)

        select_button = tk.Button(user_selection_window, text="Pilih", command=lambda: self.select_user(user_listbox, user_selection_window))
        select_button.pack(pady=5)

    def select_user(self, listbox, window):
        selected_index = listbox.curselection()
        if selected_index:
            self.selected_user = listbox.get(selected_index)
            self.selected_user_button.config(text=self.selected_user)  # Ubah teks tombol menjadi nama pengguna yang dipilih
            window.destroy()  # Tutup pop-up setelah memilih
        else:
            messagebox.showwarning("Peringatan", "Silakan pilih pengguna!")

    def send_message(self, event=None):
        if not self.selected_user:
            messagebox.showwarning("Peringatan", "Silakan pilih penerima!")
            return

        if self.selected_user == self.client_name:
            messagebox.showwarning("Peringatan", "Anda tidak dapat mengirim pesan kepada diri sendiri!")
            return

        message = self.entry_area.get()
        if message: 
            encrypted_message = aes_encrypt(message, self.password)
            self.client_socket.send(f"{self.selected_user}:{encrypted_message}".encode('utf-8'))
            self.entry_area.delete(0, tk.END)  # Bersihkan kolom input setelah mengirim
            self.chat_area.config(state="normal")
            self.chat_area.insert(tk.END, f"{self.client_name} -> {self.selected_user}: {message}\n")
            self.chat_area.yview(tk.END)
            self.chat_area.config(state="disabled")
            self.entry_area.delete(0, tk.END)


    def display_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
