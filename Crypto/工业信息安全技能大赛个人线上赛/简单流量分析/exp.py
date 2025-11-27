from pyshark.capture.file_capture import FileCapture
from base64 import b64decode
from sys import argv
 
def solve(file_name):
    packets = FileCapture(input_file=file_name)
    res = ''
    for packet in packets:
        for pkt in packet:
            if pkt.layer_name == 'icmp' and int(pkt.type, 16):
                res += chr(int(pkt.data_len))
    return b64decode(res)
 
 
print(solve(argv[1]))  # 获取命令行传入的第一个参数，即文件路径
