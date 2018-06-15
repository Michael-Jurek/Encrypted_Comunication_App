#################################################################################################################
#                                                                                                               #
#           Project: Encrypted client-client communication, with trusted Certification Authority                #
#                                                Summer Term 2018                                               #
#					       	   FEEC BUT BRNO																	#
#																												#
#           Credits: Michael Jurek, @mikedevop                       											#
#################################################################################################################

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import os

def genNonce():									#"a number used only once"; 
	return os.urandom(AES.block_size)			#Random number to ensure that old communication cannot be reused

def genKey():									#generate key
	return os.urandom(32)

def padData(data):								#funtion generating padding data
	if len(data) % 16 == 0:
		return data 							#padding not needed
	padRequired = 16 - (len(data) % 16) 		#required padding
	data = '%s%s' % (data, '{' * padRequired)   #as padding is used symbol '{'
	return data

def unpadData(data):
	if not data:
		return data
	data = data.rstrip('{'.encode())			#unpadd data with known padding
	return data

def encrypt(data, key):
	"""
	Encrypt a cyphertext with AES 256, CBC mode; Init Vector will be prepend
	to the cypher text 
	"""
	data = padData(data)						#padding data
	iV = genNonce()								#iV is so called nonce
	aes = AES.new(key, AES.MODE_CBC, iV)		#AES inicialization
	cipherText = aes.encrypt(data)				#main encryption of data, AES_CBC mode
	return iV + cipherText

def decrypt(cipherText, key):
	"""
	Decrypt a cyphertext encrypted with AES in CBC mode. It assumes the IV vector
	to be prepended to ciphertext.
	"""
	if len(ciphertext) <= AES.block_size:		#if length of ciphertext differs with AES blocksize
		raise Exception("Invalid ciphertext")	#EXCEPTION
	iV = ciphertext[:AES.block_size]			#parsing ciphertext as iV
	ciphertext = ciphertext[AES.block_size:]	#					and main ciphertext
	aes = AES.new(key, AES.MODE_CBC, iV)		#AES inicializing
	data = aes.decrypt(ciphertext)				#AES decryption
	return unpadData(data)						#unpaded decrypted data