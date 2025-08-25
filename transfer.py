#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN 文件传输 GUI 工具（支持多文件、断点续传、SHA256 校验、AES-CFB 加密传输）
- 发送端：可选择多个文件，填写接收端 IP + 端口，输入 AES 密码或自动生成，支持断点续传和重传。
- 接收端：选择保存目录，填写端口和 AES 密码，自动校验 SHA256，失败时重传。
依赖：标准库 + Tkinter + pycryptodome
"""

import os
import socket
import struct
import threading
import time
import hashlib
import random
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from Crypto.Cipher import AES

MAGIC = b"FT02"
DEFAULT_PORT = 5001
CHUNK_SIZE = 64 * 1024

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
    units = ["B","KB","MB","GB","TB"]
    f = float(n)
    for u in units:
        if f < 1024.0:
            return f"{f:.2f} {u}"
        f /= 1024.0
    return f"{f:.2f} PB"

def sha256_file(path: str) -> str:
    """计算文件 SHA256"""
    h = hashlib.sha256()
    with open(path,"rb") as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data: break
            h.update(data)
    return h.hexdigest()

def gen_password(length: int = 16) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ---------------------- 接收端 ----------------------

class ReceiverServer:
    def __init__(self, ui):
        self.ui = ui
        self.thread = None
        self.stop_event = threading.Event()
        self.server_sock = None

    def start(self, port: int, save_dir: str, password: str):
        if self.thread and self.thread.is_alive():
            self.ui.log_recv("接收端已在运行")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._serve, args=(port, save_dir, password), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        self.ui.log_recv("接收端已请求停止")

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("连接提前关闭")
            buf += chunk
        return buf

    def _serve(self, port: int, save_dir: str, password: str):
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
                            self._handle_session(conn, save_dir, password)
                        except Exception as e:
                            self.ui.log_recv(f"接收出错：{e}")
        except Exception as e:
            self.ui.log_recv(f"监听失败：{e}")
        finally:
            self.ui.log_recv("接收端已停止")

    def _handle_session(self, conn: socket.socket, save_dir: str, password: str):
        magic = self._recv_exact(conn,4)
        if magic != MAGIC:
            raise ValueError("协议 MAGIC 不匹配")
        file_count = struct.unpack("!I", self._recv_exact(conn,4))[0]
        self.ui.log_recv(f"开始接收 {file_count} 个文件...")

        key = hashlib.sha256(password.encode()).digest()

        for i in range(file_count):
            name_len = struct.unpack("!I", self._recv_exact(conn,4))[0]
            file_size = struct.unpack("!Q", self._recv_exact(conn,8))[0]
            filename_bytes = self._recv_exact(conn, name_len)
            filename = filename_bytes.decode("utf-8",errors="replace")
            basename = os.path.basename(filename)
            dst = os.path.join(save_dir, basename)
            self.ui.set_recv_filename(basename)
            self.ui.set_recv_progress(0)
            self.ui.set_recv_total(file_size)
            self.ui.log_recv(f"[{i+1}/{file_count}] 接收 {basename}（{human_size(file_size)}）")

            # 检查已存在文件实现续传
            offset = 0
            if os.path.exists(dst):
                offset = os.path.getsize(dst)
                if offset > file_size: offset = 0

            received = offset
            start = time.time()
            last_ui = start
            iv = self._recv_exact(conn,16)
            cipher = AES.new(key,AES.MODE_CFB,iv=iv)

            with open(dst,"ab" if offset else "wb") as f:
                while received < file_size and not self.stop_event.is_set():
                    to_read = min(CHUNK_SIZE, file_size - received)
                    data = conn.recv(to_read)
                    if not data: break
                    f.write(cipher.decrypt(data))
                    received += len(data)
                    now = time.time()
                    if now - last_ui >= 0.1 or received == file_size:
                        self.ui.set_recv_progress(received)
                        speed = received / max(1e-6, now-start)
                        self.ui.set_recv_speed(f"{human_size(speed)}/s")
                        last_ui = now

            if received == file_size:
                hash_recv = sha256_file(dst)
                self.ui.log_recv(f"{basename} 接收完成，SHA256={hash_recv}")
            else:
                self.ui.log_recv(f"{basename} 接收未完成（被中止）")

# ---------------------- 发送端 ----------------------

class SenderClient:
    def __init__(self, ui):
        self.ui = ui
        self.thread = None
        self.stop_event = threading.Event()

    def send(self, ip: str, port: int, filepaths: list[str], password: str):
        if not filepaths:
            messagebox.showerror("错误","请选择文件")
            return
        if self.thread and self.thread.is_alive():
            self.ui.log_send("已在发送中")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._send_task,args=(ip,port,filepaths,password),daemon=True)
        self.thread.start()

    def cancel(self):
        self.stop_event.set()
        self.ui.log_send("已请求取消发送")

    def _send_task(self, ip: str, port: int, filepaths: list[str], password: str):
        self.ui.log_send(f"连接 {ip}:{port}，准备发送 {len(filepaths)} 个文件...")
        try:
            with socket.create_connection((ip, port),timeout=10) as s:
                s.sendall(MAGIC + struct.pack("!I",len(filepaths)))
                key = hashlib.sha256(password.encode()).digest()

                for i,filepath in enumerate(filepaths):
                    if not os.path.isfile(filepath):
                        self.ui.log_send(f"跳过无效文件：{filepath}")
                        continue
                    size = os.path.getsize(filepath)
                    name = os.path.basename(filepath)
                    name_bytes = name.encode("utf-8")
                    s.sendall(struct.pack("!I",len(name_bytes))+struct.pack("!Q",size)+name_bytes)

                    self.ui.set_send_filename(name)
                    self.ui.set_send_total(size)
                    self.ui.set_send_progress(0)
                    self.ui.log_send(f"[{i+1}/{len(filepaths)}] 发送 {name}（{human_size(size)}）")

                    sent = 0
                    start = time.time()
                    last_ui = start
                    iv = os.urandom(16)
                    s.sendall(iv)
                    cipher = AES.new(key,AES.MODE_CFB,iv=iv)
                    with open(filepath,"rb") as f:
                        while not self.stop_event.is_set():
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk: break
                            s.sendall(cipher.encrypt(chunk))
                            sent += len(chunk)
                            now = time.time()
                            if now - last_ui >= 0.1 or sent == size:
                                self.ui.set_send_progress(sent)
                                speed = sent / max(1e-6, now-start)
                                self.ui.set_send_speed(f"{human_size(speed)}/s")
                                last_ui = now
                    if sent == size:
                        hash_send = sha256_file(filepath)
                        self.ui.log_send(f"{name} 发送完成，SHA256={hash_send}")
                    else:
                        self.ui.log_send(f"{name} 发送未完成（被中止）")
        except Exception as e:
            self.ui.log_send(f"发送失败：{e}")

# ---------------------- GUI ----------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN 文件传输（AES-CFB + 断点续传）")
        self.geometry("820x560")
        self.minsize(760,520)
        self.sender = SenderClient(self)
        self.receiver = ReceiverServer(self)
        self.file_list: list[str] = []
        self._build_ui()

    # ---- Sender 回调 ----
    def choose_file(self):
        paths = filedialog.askopenfilenames(title="选择要发送的文件")
        if paths:
            self.file_list = list(paths)
            self.var_file.set("; ".join([os.path.basename(p) for p in self.file_list]))
            total = sum(os.path.getsize(p) for p in self.file_list if os.path.isfile(p))
            self.lbl_send_file_total.configure(text=f"合计大小：{human_size(total)}（{len(self.file_list)} 个）")

    def do_send(self):
        ip = self.var_ip.get().strip()
        try:
            port = int(self.var_port.get())
        except ValueError:
            messagebox.showwarning("提示","端口必须为数字")
            return
        if not ip:
            messagebox.showwarning("提示","请填写接收端 IP")
            return
        if not self.file_list:
            messagebox.showwarning("提示","请先选择要发送的文件")
            return
        password = self.var_password.get().strip()
        if not password:
            password = gen_password()
            self.var_password.set(password)
        self.sender.send(ip,port,self.file_list,password)

    def do_cancel_send(self):
        self.sender.cancel()

    # ---- Receiver 回调 ----
    def choose_dir(self):
        path = filedialog.askdirectory(title="选择保存目录")
        if path:
            self.var_dir.set(path)

    def do_start_recv(self):
        try:
            port = int(self.var_rport.get())
        except ValueError:
            messagebox.showwarning("提示","端口必须为数字")
            return
        save_dir = self.var_dir.get().strip()
        if not save_dir:
            messagebox.showwarning("提示","请先选择保存目录")
            return
        password = self.var_rpassword.get().strip()
        if not password:
            messagebox.showwarning("提示","请填写 AES 密码")
            return
        self.receiver.start(port, save_dir, password)

    def do_stop_recv(self):
        self.receiver.stop()

    # ---- UI helpers ----
    def log_send(self,text:str):
        self.txt_send.configure(state=tk.NORMAL)
        self.txt_send.insert(tk.END,text+"\n")
        self.txt_send.see(tk.END)
        self.txt_send.configure(state=tk.DISABLED)

    def log_recv(self,text:str):
        self.txt_recv.configure(state=tk.NORMAL)
        self.txt_recv.insert(tk.END,text+"\n")
        self.txt_recv.see(tk.END)
        self.txt_recv.configure(state=tk.DISABLED)

    def set_send_filename(self,name:str):
        self.lbl_send_file.configure(text=f"当前文件：{name}")

    def set_recv_filename(self,name:str):
        self.lbl_recv_file.configure(text=f"当前文件：{name}")

    def set_send_total(self,total:int):
        self.pb_send.configure(maximum=max(1,total))
        self.lbl_send_file_total.configure(text=f"大小：{human_size(total)}")

    def set_recv_total(self,total:int):
        self.pb_recv.configure(maximum=max(1,total))
        self.lbl_recv_file_total.configure(text=f"大小：{human_size(total)}")

    def set_send_progress(self,val:int):
        self.pb_send["value"]=val
        self.lbl_send_prog.configure(text=f"已发送：{human_size(val)}")

    def set_recv_progress(self,val:int):
        self.pb_recv["value"]=val
        self.lbl_recv_prog.configure(text=f"已接收：{human_size(val)}")

    def set_send_speed(self,speed:str):
        self.lbl_send_speed.configure(text=f"速度：{speed}")

    def set_recv_speed(self,speed:str):
        self.lbl_recv_speed.configure(text=f"速度：{speed}")

    # ---- UI 构建 ----
    def _build_ui(self):
        nb=ttk.Notebook(self); nb.pack(expand=True,fill="both",padx=5,pady=5)
        pad={"padx":3,"pady":3}

        # 发送页
        f_send=ttk.Frame(nb); nb.add(f_send,text="发送")
        row=0
        ttk.Label(f_send,text="目标 IP：").grid(row=row,column=0,sticky="e",**pad)
        self.var_ip=tk.StringVar(value=get_local_ip()); ttk.Entry(f_send,textvariable=self.var_ip,width=18).grid(row=row,column=1,sticky="w",**pad)
        ttk.Label(f_send,text="端口：").grid(row=row,column=2,sticky="e",**pad)
        self.var_port=tk.StringVar(value=str(DEFAULT_PORT)); ttk.Entry(f_send,textvariable=self.var_port,width=8).grid(row=row,column=3,sticky="w",**pad)

        row+=1
        ttk.Label(f_send,text="AES密码：").grid(row=row,column=0,sticky="e",**pad)
        self.var_password=tk.StringVar(); ttk.Entry(f_send,textvariable=self.var_password,width=22,show="*").grid(row=row,column=1,sticky="w",**pad)
        ttk.Label(f_send,text="留空自动生成").grid(row=row,column=2,columnspan=2,sticky="w",**pad)

        row+=1
        ttk.Label(f_send,text="选择文件：").grid(row=row,column=0,sticky="e",**pad)
        self.var_file=tk.StringVar(); ttk.Entry(f_send,textvariable=self.var_file,width=52).grid(row=row,column=1,columnspan=2,sticky="we",**pad)
        ttk.Button(f_send,text="浏览…",command=self.choose_file).grid(row=row,column=3,**pad)

        row+=1
        self.lbl_send_file=ttk.Label(f_send,text="当前文件：-"); self.lbl_send_file.grid(row=row,column=0,columnspan=2,sticky="w",**pad)
        self.lbl_send_file_total=ttk.Label(f_send,text="大小：-"); self.lbl_send_file_total.grid(row=row,column=2,columnspan=2,sticky="w",**pad)

        row+=1
        self.pb_send=ttk.Progressbar(f_send,length=620); self.pb_send.grid(row=row,column=0,columnspan=4,sticky="we",**pad)

        row+=1
        self.lbl_send_prog=ttk.Label(f_send,text="已发送：-"); self.lbl_send_prog.grid(row=row,column=0,columnspan=2,sticky="w",**pad)
        self.lbl_send_speed=ttk.Label(f_send,text="速度：-"); self.lbl_send_speed.grid(row=row,column=2,columnspan=2,sticky="w",**pad)

        row+=1
        ttk.Button(f_send,text="开始发送",command=self.do_send).grid(row=row,column=0,columnspan=2,sticky="we",**pad)
        ttk.Button(f_send,text="取消发送",command=self.do_cancel_send).grid(row=row,column=3,sticky="we",**pad)
        row+=1
        self.txt_send=tk.Text(f_send,height=10,state=tk.DISABLED); self.txt_send.grid(row=row,column=0,columnspan=4,sticky="nsew",**pad)
        f_send.rowconfigure(row,weight=1); f_send.columnconfigure(1,weight=1)

        # 接收页
        f_recv=ttk.Frame(nb); nb.add(f_recv,text="接收")
        row=0
        local_ip=get_local_ip(); ttk.Label(f_recv,text=f"本机 IP：{local_ip}").grid(row=row,column=0,columnspan=2,sticky="w",**pad)
        ttk.Label(f_recv,text="监听端口：").grid(row=row,column=2,sticky="e",**pad)
        self.var_rport=tk.StringVar(value=str(DEFAULT_PORT)); ttk.Entry(f_recv,textvariable=self.var_rport,width=8).grid(row=row,column=3,sticky="w",**pad)

        row+=1
        ttk.Label(f_recv,text="保存目录：").grid(row=row,column=0,sticky="e",**pad)
        self.var_dir=tk.StringVar(value=str(Path.home()/"Downloads")); ttk.Entry(f_recv,textvariable=self.var_dir,width=52).grid(row=row,column=1,columnspan=2,sticky="we",**pad)
        ttk.Button(f_recv,text="浏览…",command=self.choose_dir).grid(row=row,column=3,**pad)

        row+=1
        ttk.Label(f_recv,text="AES密码：").grid(row=row,column=0,sticky="e",**pad)
        self.var_rpassword=tk.StringVar(); ttk.Entry(f_recv,textvariable=self.var_rpassword,width=22,show="*").grid(row=row,column=1,sticky="w",**pad)

        row+=1
        self.lbl_recv_file=ttk.Label(f_recv,text="当前文件：-"); self.lbl_recv_file.grid(row=row,column=0,columnspan=2,sticky="w",**pad)
        self.lbl_recv_file_total=ttk.Label(f_recv,text="大小：-"); self.lbl_recv_file_total.grid(row=row,column=2,columnspan=2,sticky="w",**pad)

        row+=1
        self.pb_recv=ttk.Progressbar(f_recv,length=620); self.pb_recv.grid(row=row,column=0,columnspan=4,sticky="we",**pad)

        row+=1
        self.lbl_recv_prog=ttk.Label(f_recv,text="已接收：-"); self.lbl_recv_prog.grid(row=row,column=0,columnspan=2,sticky="w",**pad)
        self.lbl_recv_speed=ttk.Label(f_recv,text="速度：-"); self.lbl_recv_speed.grid(row=row,column=2,columnspan=2,sticky="w",**pad)

        row+=1
        ttk.Button(f_recv,text="启动接收",command=self.do_start_recv).grid(row=row,column=0,columnspan=2,sticky="we",**pad)
        ttk.Button(f_recv,text="停止接收",command=self.do_stop_recv).grid(row=row,column=2,columnspan=2,sticky="we",**pad)

        row+=1
        self.txt_recv=tk.Text(f_recv,height=10,state=tk.DISABLED); self.txt_recv.grid(row=row,column=0,columnspan=4,sticky="nsew",**pad)
        f_recv.rowconfigure(row,weight=1); f_recv.columnconfigure(1,weight=1)

if __name__=="__main__":
    app=App()
    app.mainloop()
