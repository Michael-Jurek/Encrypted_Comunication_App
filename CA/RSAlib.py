#################################################################################################################
#                                                                                                               #
#           Project: Encrypted client-client communication, with trusted Certification Authority                #
#                                                Summer Term 2018                                               #
#					       	   FEEC BUT BRNO						#
#														#
#           Credits: Michael Jurek, @mikedevop                       						#
#################################################################################################################

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
import sys

def newKeys(keysize):									#generate new keys											
	print("generating RSA keys...")
	random_generator = Random.new().read
	key = RSA.generate(keysize, random_generator)		#private and public keys
	private, public = key, key.publickey()
	return public, private

def encrypt(message, pub_key):
	"""
	RSA encryption protocol according PKCS#1 OAEP
	"""
	cipher = PKCS1_OAEP.new(pub_key)					#generates cipher 
	return cipher.encrypt(message)

def decrypt(ciphertext, priv_key):						#decrypytion
	"""
	RSA encryption protocol according PKCS#1 OAEP
	"""
	cipher = PKCS1_v1_5.new(priv_key)
	return cipher.decrypt(ciphertext)

def sign(message, priv_key):							#function for digital signature
	signer = PKCS1_v1_5.new(priv_key)					#signer init
	digest = SHA256.new()			
	digest.update(message)								#message signature
	return signer.sign(digest)							#signs a digest

def verify(message, signature, pub_key):				#y
	print("%%%%%%%%%%%%%%%%%%%%%")
	print(message)
	print(len(message))
	print("%%%%%%%%%%%%%%%%%%%%%")
	signer = PKCS1_v1_5.new(pub_key)
	digest = SHA256.new()
	digest.update(message)
	print("@@@@@@@@@@@@@@@@@@@@@")
	print(digest.hexdigest())
	print("@@@@@@@@@@@@@@@@@@@@@")

	print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
	print(signature)
	print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
	return signer.verify(digest, signature)