import base64
from hashlib import sha256
from Crypto.Random import new as Random
from Crypto.Cipher import AES 

class AESCipher():
    def __init__(self, key):
        self.block_size = 16
        self.key = sha256(key.encode()).digest()[:32]
        self.pad = lambda s: s + (self.block_size - len(s) % self.block_size) * chr (self.block_size - len(s) % self.block_size)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    def _pad(self, s):
        s = bytes(s)
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = str(raw)
        raw = self.pad(raw)
        #iv = "012345678901234567890123456789"
        #iv = iv[0:16].encode('utf-8')
        iv = Random().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc.encode())
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        return self.unpad(cipher.decrypt(enc[self.block_size:])).decode('utf-8')