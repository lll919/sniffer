import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff
from threading import Thread
import os


class PacketSniffer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")
        self.root.configure(bg="white")

        # 添加菜单栏
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="操作", menu=self.file_menu)
        self.file_menu.add_command(label="开始", command=self.start_sniffing)
        self.file_menu.add_command(label="停止", command=self.stop_sniffing)
        self.file_menu.add_command(label="保存", command=self.save_data)

        # 添加三个文本框来分别显示抓到的数据、分析出的包头信息和网络适配器名称
        tk.Label(self.root, text="实时抓取的数据包", bg="white").pack(padx=10, pady=5)
        self.packet_text = tk.Text(self.root, height=10, bg="light grey")
        self.packet_text.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(self.root, text="分析过的信息", bg="white").pack(padx=10, pady=5)
        self.header_text = tk.Text(self.root, height=10, bg="light grey")
        self.header_text.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(self.root, text="网络适配器名称", bg="white").pack(padx=10, pady=5)
        self.adapter_text = tk.Text(self.root, height=2, bg="light grey")
        self.adapter_text.pack(padx=10, pady=5, fill=tk.X)

        # 添加一个标志，用于控制抓包线程的运行/停止
        self.sniffing = False

    def start_sniffing(self):
        # 设置标志为True并启动抓包线程
        self.sniffing = True
        Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        # 设置标志为False以停止抓包线程
        self.sniffing = False

    def save_data(self):
        # 将抓取到的数据保存到桌面的txt文件中
        with open(os.path.expanduser("~/Desktop/data.txt"), 'w') as f:
            f.write(self.packet_text.get('1.0', tk.END))

        messagebox.showinfo("保存成功", "数据已保存到桌面，文件名为data.txt")

    def sniff_packets(self):
        while self.sniffing:
            # 使用scapy的sniff函数抓取单个数据包
            packet = sniff(count=1)[0]  # 这里我们每次只抓取一个包
            # 在文本框中显示数据包的摘要信息
            self.packet_text.insert(tk.END, packet.summary() + '\n')
            # 清空头部信息文本框并显示最新数据包的头部信息
            self.header_text.delete('1.0', tk.END)
            self.header_text.insert(tk.END, packet.show(dump=True) + '\n')
            # 显示网络适配器名称
            self.adapter_text.delete('1.0', tk.END)
            self.adapter_text.insert(tk.END, "Intel(R) Wi-Fi 6E AX211 160MHz" + '\n')

    def run(self):
        # 运行GUI
        self.root.mainloop()


if __name__ == '__main__':
    sniffer = PacketSniffer()
    sniffer.run()
# 这是一个示例 Python 脚本。

# 按 Shift+F10 执行或将其替换为您的代码。
# 按 双击 Shift 在所有地方搜索类、文件、工具窗口、操作和设置。


def print_hi(name):
    # 在下面的代码行中使用断点来调试脚本。
    print(f'Hi, {name}')  # 按 Ctrl+F8 切换断点。


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    print_hi('PyCharm')

# 访问 https://www.jetbrains.com/help/pycharm/ 获取 PyCharm 帮助
