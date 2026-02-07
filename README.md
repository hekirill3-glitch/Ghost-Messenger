# Ghost-Messenger
Мессенджер конфиденциальный данные хранятся нигде
# ghost_messenger.py
import socket
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Генерация ключа шифрования
key = Fernet.generate_key()
cipher = Fernet(key)

# Настройки сети
HOST = '127.0.0.1'  # Локальный хост
PORT = 5000         # Порт для соединения

# GUI
root = tk.Tk()
root.title("Ghost Messenger")

chat_area = scrolledtext.ScrolledText(root, width=50, height=20)
chat_area.pack()

entry_msg = tk.Entry(root, width=50)
entry_msg.pack()

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            decrypted_msg = cipher.decrypt(data).decode()
            chat_area.insert(tk.END, f"Friend: {decrypted_msg}\n")
        except:
            break

def send_message(sock):
    msg = entry_msg.get()
    if msg:
        encrypted_msg = cipher.encrypt(msg.encode())
        sock.sendall(encrypted_msg)
        chat_area.insert(tk.END, f"You: {msg}\n")
        entry_msg.delete(0, tk.END)

def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except:
        messagebox.showerror("Error", "Cannot connect to server")
        return

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    send_button = tk.Button(root, text="Send", command=lambda: send_message(sock))
    send_button.pack()

    root.mainloop()

def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    chat_area.insert(tk.END, "Waiting for connection...\n")
    conn, addr = server_sock.accept()
    chat_area.insert(tk.END, f"Connected by {addr}\n")

    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()

    send_button = tk.Button(root, text="Send", command=lambda: send_message(conn))
    send_button.pack()

    root.mainloop()

# Запуск
choice = input("Start as server (s) or client (c)? ")
if choice.lower() == 's':
    start_server()
else:
    start_client()
