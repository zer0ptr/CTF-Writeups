from pyshark.capture.file_capture import FileCapture
from base64 import b64decode
from sys import argv
 
def solve(file_name):
    packets = FileCapture(input_file=file_name)
    res = ''
    for packet in packets:
        for pkt in packet:                                           # 0x08 表示 回显请求 (Echo Request)，0x00 表示 回显应答 (Echo Reply)。
            if pkt.layer_name == 'icmp' and int(pkt.type, 16) == 8:  # icmp包 ; 将 data_len（数据包长度）转换为字符
                res += chr(int(pkt.data_len))
    return b64decode(res)
 
 
def save_to_file(data, file_name):
    # 保存解码后的数据到文件
    with open(file_name, 'wb') as f:
        f.write(data)
 
 
# 获取传入的文件名
input_file = 'fetus_pcap.pcap'  # 这里你可以手动指定文件，或使用命令行传递
output_file = '1.txt'
 
# 获取解码后的数据
decoded_data = solve(input_file)
print(decoded_data)