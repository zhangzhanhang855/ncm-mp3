import binascii
import struct
import base64
import json
import os
from Crypto.Cipher import AES

def dump(file_path):
    # 核心解密核心密钥
    core_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0:-s[-1]]
    
    f = open(file_path, 'rb')
    header = f.read(10)
    assert header == b'CTENFDAMAM'
    
    f.seek(2, 1)
    key_length = struct.unpack('<I', f.read(4))[0]
    key_data = f.read(key_length)
    key_data_array = bytearray(key_data)
    for i in range(0, len(key_data_array)): key_data_array[i] ^= 0x64
    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_program = 0
    for i in range(256):
        c = (key_data[i % key_length] + key_box[i] + c) & 0xff
        key_box[i], key_box[c] = key_box[c], key_box[i]
    
    f.seek(struct.unpack('<I', f.read(4))[0], 1)
    
    # 自动识别后缀
    output_name = os.path.splitext(file_path)[0] + ".mp3"
    
    with open(output_name, 'wb') as m:
        while True:
            chunk = f.read(0x8000)
            if not chunk:
                break
            chunk_array = bytearray(chunk)
            for i in range(1, len(chunk_array) + 1):
                j = (i + last_byte) & 0xff
                next_byte = (key_box[j] + key_box[(key_box[j] + key_box[(j + key_box[j]) & 0xff]) & 0xff]) & 0xff
                chunk_array[i - 1] ^= next_byte
            m.write(bytes(chunk_array))
    f.close()
    print(f"Success: {file_path} -> {output_name}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        dump(sys.argv[1])
