# -*- coding: UTF-8 -*-

from prometheus_client import start_http_server, Gauge
from time import sleep
import json
import sys

syscall = Gauge('syscall', 'The amount of syscalls', ['container'])
exec = Gauge('exec', 'The amount of exec', ['container'])
fileopen = Gauge('fileopen', 'The amount of fileopen', ['container'])
netvisit = Gauge('netvisit', 'The amount of netvisit', ['container'])

'''
syscall_count = {}
exec_count = {}
fileopen_count = {}
netvisit_count = {}
'''

start_time = ""


# 检查./RUNNING文件是否存在且可读，读取文件内容并处理。如果文件无法打开，程序会输出错误信息并退出
def checkRUNNING():
    global start_time
    try:
        with open("./RUNNING", "r") as RUNNING_file:
            start_time = RUNNING_file.read().strip()  # 读取内容并去除前后空白字符
    except FileNotFoundError:
        print("failed to open ./RUNNING, please check if the ContGuard is running!")
        sys.exit(1)
    except IOError:
        print("Error occurred while reading ./RUNNING.")
        sys.exit(1)


# 读取四种类型的日志数据（系统调用、进程执行、文件打开和容器访问），并计算每种数据类型中包含的项的数量
def update():
    checkRUNNING()
    syscall_file = open("./logs/syscall/syscall_%s.json" % start_time)
    exec_file = open("./logs/exec/exec_%s.json" % start_time)
    fileopen_file = open("./logs/fileopen/fileopen_%s.json" % start_time)
    netvisit_file = open("./logs/netvisit/netvisit_%s.json" % start_time)
    syscall_table = json.load(syscall_file)
    exec_table = json.load(exec_file)
    fileopen_table = json.load(fileopen_file)
    netvisit_table = json.load(netvisit_file)
    syscall_file.close()
    exec_file.close()
    fileopen_file.close()
    netvisit_file.close()
    for k, v in syscall_table.items():
        syscall.labels(container=k).set(len(v.keys()))
    for k, v in exec_table.items():
        exec.labels(container=k).set(len(v))
    for k, v in fileopen_table.items():
        fileopen.labels(container=k).set(len(v))
    for k, v in netvisit_table.items():
        netvisit.labels(container=k).set(len(v))


if __name__ == "__main__":
    start_http_server(9001)
    while 1:
        update()
        sleep(1)
