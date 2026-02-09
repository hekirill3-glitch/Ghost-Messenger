
import socket
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox

HOST = '127.0.0.1'
PORT = 5000

# Generate key once and replace manually if needed
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

root = tk.Tk()
root.title("Ghost Messenger")

chat_area = scrolledtext.ScrolledText(root, width=50, height=20)
chat_area.pack()

entry_msg = tk.Entry(root, width=50)
entry_msg.pack()

connection = None

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

def send_message():
    global connection
    msg = entry_msg.get()
    if msg and connection:
        encrypted_msg = cipher.encrypt(msg.encode())
        connection.sendall(encrypted_msg)
        chat_area.insert(tk.END, f"You: {msg}\n")
        entry_msg.delete(0, tk.END)

def start_client():
    global connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except:
        messagebox.showerror("Ошибка", "Не удалось подключиться")
        return

    connection = sock
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    chat_area.insert(tk.END, "Подключено к серверу\n")

def start_server():
    global connection
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)

    chat_area.insert(tk.END, "Ожидание подключения...\n")
    conn, addr = server_sock.accept()
    chat_area.insert(tk.END, f"Подключен: {addr}\n")

    connection = conn
    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()

btn_frame = tk.Frame(root)
btn_frame.pack()

tk.Button(btn_frame, text="Запустить сервер", command=start_server).pack(side=tk.LEFT)
tk.Button(btn_frame, text="Подключиться как клиент", command=start_client).pack(side=tk.LEFT)
tk.Button(root, text="Send", command=send_message).pack()

root.mainloop()
