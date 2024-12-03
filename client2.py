import tkinter as tk
from tkinter import ttk

class ChatUI:
    def __init__(self, root):
        # Configure root window
        root.title("Chat Application")
        root.geometry("1000x600")
        root.configure(bg="#1F1F2E")  # Dark background

        # Left sidebar frame
        self.sidebar = tk.Frame(root, bg="#EFF3F8", width=300)
        self.sidebar.pack(side="left", fill="y")

        # Search bar
        self.search_frame = tk.Frame(self.sidebar, bg="#EFF3F8")
        self.search_frame.pack(pady=10)
        self.search_entry = ttk.Entry(self.search_frame, font=("Arial", 12))
        self.search_entry.pack(padx=10, pady=5, fill="x")

        # User list
        self.user_list = tk.Frame(self.sidebar, bg="#EFF3F8")
        self.user_list.pack(fill="both", expand=True)

        # Sample user chats
        self.add_user_chat("Chole Adams", "Hey, did you just ...", "just now", True)
        self.add_user_chat("Amin Rokhead", "Can you send it to me", "yesterday 11:00 pm")
        self.add_user_chat("Zareena", "You are a ****", "yesterday 10:59 pm")

        # Main chat area
        self.chat_area = tk.Frame(root, bg="#F8F9FD")
        self.chat_area.pack(side="left", fill="both", expand=True)

        # Chat header
        self.chat_header = tk.Frame(self.chat_area, bg="#F8F9FD", height=50)
        self.chat_header.pack(fill="x", padx=10, pady=5)
        self.chat_name = tk.Label(self.chat_header, text="Chole Adams", font=("Arial", 14, "bold"), bg="#F8F9FD")
        self.chat_name.pack(side="left")

        # Chat messages area
        self.messages_frame = tk.Frame(self.chat_area, bg="#F8F9FD")
        self.messages_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.messages_canvas = tk.Canvas(self.messages_frame, bg="#F8F9FD")
        self.messages_canvas.pack(side="left", fill="both", expand=True)

        # Scrollbar for messages
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical", command=self.messages_canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)

        # Message entry and send button
        self.input_frame = tk.Frame(self.chat_area, bg="#F8F9FD", height=50)
        self.input_frame.pack(fill="x", padx=10, pady=5)
        self.message_entry = ttk.Entry(self.input_frame, font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="right")

    def add_user_chat(self, name, message, time, active=False):
        """Adds a user to the left sidebar."""
        user_frame = tk.Frame(self.user_list, bg="#EFF3F8", height=60)
        user_frame.pack(fill="x", pady=5)

        user_avatar = tk.Label(user_frame, text="🙂", font=("Arial", 20), bg="#EFF3F8")
        user_avatar.pack(side="left", padx=10)

        user_details = tk.Frame(user_frame, bg="#EFF3F8")
        user_details.pack(side="left", fill="x", expand=True)

        user_name = tk.Label(user_details, text=name, font=("Arial", 12, "bold"), bg="#EFF3F8")
        user_name.pack(anchor="w")

        user_message = tk.Label(user_details, text=message, font=("Arial", 10), fg="gray", bg="#EFF3F8")
        user_message.pack(anchor="w")

        time_label = tk.Label(user_frame, text=time, font=("Arial", 8), fg="gray", bg="#EFF3F8")
        time_label.pack(side="right", padx=10)

        if active:
            user_frame.config(bg="#D9E7FF")  # Highlight the active user

    def send_message(self):
        """Handles sending a message."""
        message = self.message_entry.get()
        if message:
            tk.Label(self.messages_canvas, text=message, bg="#007BFF", fg="white", font=("Arial", 12), anchor="e", padx=10, pady=5).pack(anchor="e", pady=5)
            self.message_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatUI(root)
    root.mainloop()
