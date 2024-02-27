import os

KEY = "ABCDEFG1234"

def xor(data, key):
    key = str(key)
    l = len(key)
    output_bytes = bytearray()

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % l]
        output_bytes.append(current ^ ord(current_key))
    
    return output_bytes

str_list = [b"NTDLL", b"NtDelayExecution", b"CreateProcessA", b"KERNEL32.DLL", b"C:\\Users\\administrator\\Desktop\\implant-inject.exe", b"CreateThread"]

print('char xorkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')

for s in str_list:
    ciphertext = xor(s + b"\x00", KEY)
    rext = s.decode('utf-8').split('.')[0]
    print('char s' + rext + '[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')