encrypted_flag = [0x76, 0x60, 0x74, 0x7a, 0x48, 0x79, 0x03, 0x5b, 0x7d, 0x6c, 0x77, 0x03, 0x76, 0x4e]
flag = ''.join([chr(byte ^ 0x33) for byte in encrypted_flag])
print(flag)
