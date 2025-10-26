import os, binascii
print(binascii.hexlify(os.urandom(32)).decode())