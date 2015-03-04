from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto import Random
import os, sys
import base64


class CCrypto:

	def __init__(self, _mode):
		if _mode == "e":
			self.gAES_MODE = AES.MODE_ECB
		elif _mode == "r":
			self.gAES_MODE = AES.MODE_CTR
		elif _mode == "c":
			self.gAES_MODE = AES.MODE_CBC
		else: 
			self.gAES_MODE = AES.MODE_CBC #default mode

		self.counter = 1
		self.nonce = ''
		self.password = ''

	def setPassword(self, password):
		self.password = password

	def pad(self, s):
		bs = AES.block_size
		padded = s + (bs - len(s) % bs) * chr(bs -len(s) % bs)
		return padded

	def unpad(self, s):
		unpadded = s[:-ord(s[len(s)-1:])]
		return unpadded

	def ctrReset(self):
		self.counter = 0

	def ctrCounter(self):
		nonce = self.nonce.encode('hex')[:16]
		n_xor_c = (int(nonce, 16) ^ self.counter)
		self.counter += 1
		return format(n_xor_c, 'x') #return hex without 0x or L

	def encrypt(self, plaintext):
		aes_mode = self.gAES_MODE
		plaintext = self.pad(plaintext)	
		iv = Random.new().read(AES.block_size) 
		key = self.generateKey(self.password, iv)

		if aes_mode == AES.MODE_CTR:
			self.nonce = iv
			cipher = AES.new(key, aes_mode, counter=self.ctrCounter)
		else:
			cipher = AES.new(key, aes_mode, iv)
			
		ciphertext = base64.b64encode(iv + cipher.encrypt(plaintext))
		return ciphertext

	def decrypt(self, ciphertext):
		aes_mode = self.gAES_MODE
		ciphertext = base64.b64decode(ciphertext)
		iv = ciphertext[:AES.block_size]
		key = self.generateKey(self.password, iv)

		if aes_mode == AES.MODE_CTR:
			self.nonce = iv
			cipher = AES.new(key, aes_mode, counter=self.ctrCounter)
		else:
			cipher = AES.new(key, aes_mode, iv)
			
		plaintext = self.unpad(cipher.decrypt(ciphertext[AES.block_size:]))
		return plaintext

	def generateKey(self, password, salt):
		# PBKDF2(password, salt, keylength, iterations)
		key = KDF.PBKDF2(password, salt, 16, 10000) #lastpass uses 10000 iterations
		return key
