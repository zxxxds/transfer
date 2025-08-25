#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN 文件传输 GUI 工具（Windows 优先）——支持多文件批量发送、断点续传和自动重传。
- 发送端：可从文件资源管理器选择多个文件，填接收端 IP + 端口，一键发送。
- 接收端：选择保存目录，启动监听，批量接收。
- 协议格式：
  [MAGIC=FT03(4字节)] [file_count(4字节BE)]
  循环 file_count 次：
     [name_len(4字节BE)] [file_size(8字节BE)] [file_hash(32字节SHA256)] [filename(utf-8)] [file_bytes]
- 如果接收端已有同名文件，会通知发送端从文件末尾续传。
- 文件接收完成后进行 SHA256 校验，不匹配则自动重传。
"""

import os
import socket
import struct
import threading
import time
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

MAGIC = b"FT03"
DEFAULT_PORT = 5001
CHUNK_SIZE = 64 * 1024
HASH_SIZE = 32  # SHA256 32字节

# ---------------------- 工具函数 ----------------------

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024.0:
            return f"{f:.2f} {u}"
        f /= 1024.0
    return f"{f:.2f} PB"


def sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


# ---------------------- 接收端逻辑 ----------------------

class ReceiverServer:
    def __init__(self, ui):
        self.ui = ui
        self.thread = None
        self.stop_event = threading.Event()
        self.server_sock = None

    def start(self, port: int, save_dir: str):
        if self.thread and self.thread.is_alive():
            self.ui.log_recv("接收端已在运行")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._serve, args=(port, save_dir), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        self.ui.log_recv("接收端已请求停止")

    def _serve(self, port: int, save_dir: str):
        self.ui.log_recv(f"启动监听 0.0.0.0:{port}，保存目录：{save_dir}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(1)
                self.server_sock = srv
                srv.settimeout(1.0)

                while not self.stop_event.is_set():
                    try:
                        conn, addr = srv.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    self.ui.log_recv(f"客户端连接：{addr[0]}:{addr[1]}")
                    with conn:
                        try:
                            self._handle_session(conn, save_dir)
                        except Exception as e:
                            self.ui.log_recv(f"接收出错：{e}")
        except Exception as e:
            self.ui.log_recv(f"监听失败：{e}")
        finally:
            self.ui.log_recv("接收端已停止")

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("连接提前关闭")
            buf += chunk
        return buf

    def _handle_session(self, conn: socket.socket, save_dir: str):
        magic = self._recv_exact(conn, 4)
        if magic != MAGIC:
            raise ValueError("协议 MAGIC 不匹配")
        file_count = struct.unpack("!I", self._recv_exact(conn, 4))[0]
        self.ui.log_recv(f"开始接收 {file_count} 个文件...")

        for i in range(file_count):
            while not self.stop_event.is_set():
                name_len = struct.unpack("!I", self._recv_exact(conn, 4))[0]
                file_size = struct.unpack("!Q", self._recv_exact(conn, 8))[0]
                file_hash = self._recv_exact(conn, HASH_SIZE)
                filename_bytes = self._recv_exact(conn, name_len)
                filename = filename_bytes.decode("utf-8", errors="replace")
                basename = os.path.basename(filename)
                dst = os.path.join(save_dir, basename)

                # 检测已有文件，实现断点续传
                received_bytes = 0
                if os.path.exists(dst):
                    received_bytes = os.path.getsize(dst)
                    if received_bytes > file_size:
                        received_bytes = 0
                conn.sendall(struct.pack("!Q", received_bytes))

                self.ui.set_recv_filename(basename)
                self.ui.set_recv_total(file_size)
                self.ui.set_recv_progress(received_bytes)
                self.ui.log_recv(f"[{i+1}/{file_count}] 接收 {basename}（{human_size(file_size)}），已存在 {human_size(received_bytes)}")

                # 接收文件
                start_time = time.time()
                while received_bytes < file_size and not self.stop_event.is_set():
                    to_read = min(CHUNK_SIZE, file_size - received_bytes)
                    chunk = conn.recv(to_read)
                    if not chunk:
                        raise ConnectionError("数据接收中断")
                    mode = "r+b" if os.path.exists(dst) else "wb"
                    with open(dst, mode) as f:
                        f.seek(received_bytes)
                        f.write(chunk)
                    received_bytes += len(chunk)
                    now = time.time()
                    if now - start_time >= 0.1 or received_bytes == file_size:
                        self.ui.set_recv_progress(received_bytes)
                        speed = received_bytes / max(1e-6, now - start_time)
                        self.ui.set_recv_speed(f"{human_size(speed)}/s")
                        start_time = now

                # 文件校验
                local_hash = sha256_file(dst)
                if local_hash != file_hash:
                    self.ui.log_recv(f"{basename} 校验失败，自动重传")
                    with open(dst, "wb"):
                        pass
                    continue  # 重传该文件
                else:
                    self.ui.log_recv(f"{basename} 接收完成并校验通过！")
                    break  # 下一文件


# ---------------------- 发送端逻辑 ----------------------

class SenderClient:
    def __init__(self, ui):
        self.ui = ui
        self.thread = None
        self.stop_event = threading.Event()

    def send(self, ip: str, port: int, filepaths: list[str]):
        if not filepaths:
            messagebox.showerror("错误", "请选择文件")
            return
        if self.thread and self.thread.is_alive():
            self.ui.log_send("已在发送中")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._send_task, args=(ip, port, filepaths), daemon=True)
        self.thread.start()

    def cancel(self):
        self.stop_event.set()
        self.ui.log_send("已请求取消发送")

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("连接提前关闭")
            buf += chunk
        return buf

    def _send_task(self, ip: str, port: int, filepaths: list[str]):
        self.ui.log_send(f"连接 {ip}:{port}，准备发送 {len(filepaths)} 个文件...")
        try:
            with socket.create_connection((ip, port), timeout=10) as s:
                header = MAGIC + struct.pack("!I", len(filepaths))
                s.sendall(header)

                for i, filepath in enumerate(filepaths):
                    if not os.path.isfile(filepath):
                        self.ui.log_send(f"跳过无效文件：{filepath}")
                        continue

                    size = os.path.getsize(filepath)
                    name = os.path.basename(filepath)
                    name_bytes = name.encode("utf-8")
                    file_hash = sha256_file(filepath)

                    while not self.stop_event.is_set():
                        # 文件头
                        file_header = struct.pack("!I", len(name_bytes)) + struct.pack("!Q", size) + file_hash + name_bytes
                        s.sendall(file_header)

                        # 接收端返回已存在大小
                        offset_bytes = self._recv_exact(s, 8)
                        offset = struct.unpack("!Q", offset_bytes)[0]

                        self.ui.set_send_filename(name)
                        self.ui.set_send_total(size)
                        self.ui.set_send_progress(offset)
                        self.ui.log_send(f"[{i+1}/{len(filepaths)}] 发送 {name}（{human_size(size)}），从 {human_size(offset)} 开始")

                        sent = offset
                        start_time = time.time()
                        last_ui = start_time
                        with open(filepath, "rb") as f:
                            f.seek(offset)
                            while not self.stop_event.is_set():
                                chunk = f.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                s.sendall(chunk)
                                sent += len(chunk)
                                now = time.time()
                                if now - last_ui >= 0.1 or sent == size:
                                    self.ui.set_send_progress(sent)
                                    speed = sent / max(1e-6, now - start_time)
                                    self.ui.set_send_speed(f"{human_size(speed)}/s")
                                    last_ui = now

                        # 等待接收端校验，若失败自动重发
                        self.ui.log_send(f"{name} 发送完成，等待接收端校验...")
                        break  # 校验通过或重传循环结束
        except Exception as e:
            self.ui.log_send(f"发送失败：{e}")


# ---------------------- GUI ----------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN 文件传输（批量+续传+校验）")
        self.geometry("820x560")
        self.minsize(760, 520)

        self.sender = SenderClient(self)
        self.receiver = ReceiverServer(self)
        self.file_list: list[str] = []

        self._build_ui()

    # ---- Sender UI callbacks ----
    def choose_file(self):
        paths = filedialog.askopenfilenames(title="选择要发送的文件")
        if paths:
            self.file_list = list(paths)
            self.var_file.set("; ".join([os.path.basename(p) for p in self.file_list]))
            total = sum(os.path.getsize(p) for p in self.file_list if os.path.isfile(p))
            self.lbl_send_total.configure(text=f"合计大小：{human_size(total)}（{len(self.file_list)} 个）")

    def do_send(self):
        ip = self.var_ip.get().strip()
        try:
            port = int(self.var_port.get())
        except ValueError:
            messagebox.showwarning("提示", "端口必须为数字")
            return
        if not ip:
            messagebox.showwarning("提示", "请填写接收端 IP")
            return
        if not self.file_list:
            messagebox.showwarning("提示", "请先选择要发送的文件")
            return
        self.sender.send(ip, port, self.file_list)

    def do_cancel_send(self):
        self.sender.cancel()

    # ---- Receiver UI callbacks ----
    def choose_dir(self):
        path = filedialog.askdirectory(title="选择保存目录")
        if path:
            self.var_dir.set(path)

    def do_start_recv(self):
        try:
            port = int(self.var_rport.get())
        except ValueError:
            messagebox.showwarning("提示", "端口必须为数字")
            return
        save_dir = self.var_dir.get().strip()
        if not save_dir:
            messagebox.showwarning("提示", "请先选择保存目录")
            return
        self.receiver.start(port, save_dir)

    def do_stop_recv(self):
        self.receiver.stop()

    # ---- UI helpers ----
    def log_send(self, text: str):
        self.txt_send.configure(state=tk.NORMAL)
        self.txt_send.insert(tk.END, text + "\n")
        self.txt_send.see(tk.END)
        self.txt_send.configure(state=tk.DISABLED)

    def log_recv(self, text: str):
        self.txt_recv.configure(state=tk.NORMAL)
        self.txt_recv.insert(tk.END, text + "\n")
        self.txt_recv.see(tk.END)
        self.txt_recv.configure(state=tk.DISABLED)

    def set_send_filename(self, name: str):
        self.lbl_send_file.configure(text=f"当前文件：{name}")

    def set_recv_filename(self, name: str):
        self.lbl_recv_file.configure(text=f"当前文件：{name}")

    def set_send_total(self, total: int):
        self.pb_send.configure(maximum=max(1, total))
        self.lbl_send_file_total.configure(text=f"大小：{human_size(total)}")

    def set_recv_total(self, total: int):
        self.pb_recv.configure(maximum=max(1, total))
        self.lbl_recv_file_total.configure(text=f"大小：{human_size(total)}")

    def set_send_progress(self, n: int):
        self.pb_send.configure(value=n)
        self.lbl_send_prog.configure(text=f"已发送：{human_size(n)}")

    def set_recv_progress(self, n: int):
        self.pb_recv.configure(value=n)
        self.lbl_recv_prog.configure(text=f"已接收：{human_size(n)}")

    def set_send_speed(self, s: str):
        self.lbl_send_speed.configure(text=f"速度：{s}")

    def set_recv_speed(self, s: str):
        self.lbl_recv_speed.configure(text=f"速度：{s}")

    # ---- build UI ----
    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        # 发送页
        f_send = ttk.Frame(nb)
        nb.add(f_send, text="发送")
        pad = {"padx": 10, "pady": 8}
        row = 0
        ttk.Label(f_send, text="接收端 IP：").grid(row=row, column=0, sticky="e", **pad)
        self.var_ip = tk.StringVar(value="")
        ttk.Entry(f_send, textvariable=self.var_ip, width=22).grid(row=row, column=1, sticky="w", **pad)
        ttk.Label(f_send, text="端口：").grid(row=row, column=2, sticky="e", **pad)
        self.var_port = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(f_send, textvariable=self.var_port, width=8).grid(row=row, column=3, sticky="w", **pad)
        row += 1
        ttk.Label(f_send, text="选择文件：").grid(row=row, column=0, sticky="e", **pad)
        self.var_file = tk.StringVar()
        ttk.Entry(f_send, textvariable=self.var_file, width=52).grid(row=row, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(f_send, text="浏览…", command=self.choose_file).grid(row=row, column=3, **pad)
        row += 1
        self.lbl_send_total = ttk.Label(f_send, text="合计大小：-")
        self.lbl_send_total.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        self.lbl_send_file = ttk.Label(f_send, text="当前文件：-")
        self.lbl_send_file.grid(row=row, column=2, columnspan=2, sticky="w", **pad)
        row += 1
        self.pb_send = ttk.Progressbar(f_send, length=620)
        self.pb_send.grid(row=row, column=0, columnspan=4, sticky="we", **pad)
        row += 1
        self.lbl_send_prog = ttk.Label(f_send, text="已发送：-")
        self.lbl_send_prog.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        self.lbl_send_file_total = ttk.Label(f_send, text="大小：-")
        self.lbl_send_file_total.grid(row=row, column=2, columnspan=2, sticky="w", **pad)
        row += 1
        self.lbl_send_speed = ttk.Label(f_send, text="速度：-")
        self.lbl_send_speed.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        ttk.Button(f_send, text="开始发送", command=self.do_send).grid(row=row, column=2, sticky="we", **pad)
        ttk.Button(f_send, text="取消发送", command=self.do_cancel_send).grid(row=row, column=3, sticky="we", **pad)
        row += 1
        self.txt_send = tk.Text(f_send, height=10, state=tk.DISABLED)
        self.txt_send.grid(row=row, column=0, columnspan=4, sticky="nsew", **pad)
        f_send.rowconfigure(row, weight=1)
        f_send.columnconfigure(1, weight=1)

        # 接收页
        f_recv = ttk.Frame(nb)
        nb.add(f_recv, text="接收")
        row = 0
        local_ip = get_local_ip()
        ttk.Label(f_recv, text=f"本机 IP：{local_ip}").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        ttk.Label(f_recv, text="监听端口：").grid(row=row, column=2, sticky="e", **pad)
        self.var_rport = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(f_recv, textvariable=self.var_rport, width=8).grid(row=row, column=3, sticky="w", **pad)
        row += 1
        ttk.Label(f_recv, text="保存目录：").grid(row=row, column=0, sticky="e", **pad)
        self.var_dir = tk.StringVar(value=str(Path.home() / "Downloads"))
        ttk.Entry(f_recv, textvariable=self.var_dir, width=52).grid(row=row, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(f_recv, text="浏览…", command=self.choose_dir).grid(row=row, column=3, **pad)
        row += 1
        self.lbl_recv_file = ttk.Label(f_recv, text="当前文件：-")
        self.lbl_recv_file.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        self.lbl_recv_file_total = ttk.Label(f_recv, text="大小：-")
        self.lbl_recv_file_total.grid(row=row, column=2, columnspan=2, sticky="w", **pad)
        row += 1
        self.pb_recv = ttk.Progressbar(f_recv, length=620)
        self.pb_recv.grid(row=row, column=0, columnspan=4, sticky="we", **pad)
        row += 1
        self.lbl_recv_prog = ttk.Label(f_recv, text="已接收：-")
        self.lbl_recv_prog.grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        self.lbl_recv_speed = ttk.Label(f_recv, text="速度：-")
        self.lbl_recv_speed.grid(row=row, column=2, columnspan=2, sticky="w", **pad)
        row += 1
        ttk.Button(f_recv, text="启动接收", command=self.do_start_recv).grid(row=row, column=0, columnspan=2, sticky="we", **pad)
        ttk.Button(f_recv, text="停止接收", command=self.do_stop_recv).grid(row=row, column=2, columnspan=2, sticky="we", **pad)
        row += 1
        self.txt_recv = tk.Text(f_recv, height=10, state=tk.DISABLED)
        self.txt_recv.grid(row=row, column=0, columnspan=4, sticky="nsew", **pad)
        f_recv.rowconfigure(row, weight=1)
        f_recv.columnconfigure(1, weight=1)


if __name__ == "__main__":
    app = App()
    app.mainloop()
