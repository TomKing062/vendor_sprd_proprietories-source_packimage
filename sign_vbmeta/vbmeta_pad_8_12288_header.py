import hashlib
import sys

f = open("vbmeta-sign-custom.img", "rb")
b = f.read()
sha = hashlib.sha256(b).digest()
f.close()
f = open("vbmeta-sign-custom.img", "wb")
f.write(b'\x44\x48\x54\x42\x01\x00\x00\x00')
f.write(sha)
f.write(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00')
f.seek(512 - 0)
f.write(b)
f.close()
